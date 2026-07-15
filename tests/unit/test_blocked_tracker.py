"""Unit tests for :class:`src.core.blocked_tracker.BlockedResponseTracker`.

The tracker classifies HTTP 403 responses into three buckets — ``waf_crs``,
``cf_clearance``, ``unknown_403`` — so the final scan report can separate
WAF blocks from cf_clearance rejections from generic 403s.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from src.core.blocked_tracker import BlockedResponseTracker


def _response(status: int, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status_code=status, headers=headers or {})


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_403_response_is_ignored() -> None:
    tracker = BlockedResponseTracker()
    await tracker.record(_response(200))
    await tracker.record(_response(500, {"X-Cf-Sim-Challenge": "expired"}))
    assert tracker.counts == {"waf_crs": 0, "cf_clearance": 0, "unknown_403": 0}


@pytest.mark.asyncio
async def test_cf_challenge_header_classified_as_cf_clearance() -> None:
    tracker = BlockedResponseTracker()
    await tracker.record(_response(403, {"X-Cf-Sim-Challenge": "expired"}))
    await tracker.record(_response(403, {"X-Cf-Sim-Challenge": "missing"}))
    assert tracker.counts["cf_clearance"] == 2
    assert tracker.counts["waf_crs"] == 0
    assert tracker.counts["unknown_403"] == 0


@pytest.mark.asyncio
async def test_apache_server_header_classified_as_waf_crs() -> None:
    tracker = BlockedResponseTracker()
    await tracker.record(_response(403, {"Server": "Apache/2.4.58"}))
    await tracker.record(_response(403, {"Server": "apache"}))
    assert tracker.counts["waf_crs"] == 2
    assert tracker.counts["cf_clearance"] == 0
    assert tracker.counts["unknown_403"] == 0


@pytest.mark.asyncio
async def test_403_without_known_markers_is_unknown() -> None:
    tracker = BlockedResponseTracker()
    await tracker.record(_response(403, {"Server": "nginx/1.25"}))
    await tracker.record(_response(403))
    assert tracker.counts["unknown_403"] == 2


@pytest.mark.asyncio
async def test_cf_clearance_wins_over_apache_server() -> None:
    """If both markers are present, the cf_clearance bucket takes priority.

    Reason: the simulator runs behind something that may report Apache too,
    but the X-Cf-Sim-Challenge header is the more specific signal.
    """
    tracker = BlockedResponseTracker()
    await tracker.record(_response(403, {"X-Cf-Sim-Challenge": "expired", "Server": "Apache/2.4"}))
    assert tracker.counts["cf_clearance"] == 1
    assert tracker.counts["waf_crs"] == 0


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_records_are_race_free() -> None:
    """Many concurrent ``record`` calls must produce an exact total count."""
    tracker = BlockedResponseTracker()
    responses = [_response(403, {"X-Cf-Sim-Challenge": "expired"}) for _ in range(100)] + [
        _response(403, {"Server": "Apache"}) for _ in range(150)
    ]

    await asyncio.gather(*(tracker.record(r) for r in responses))

    assert tracker.counts["cf_clearance"] == 100
    assert tracker.counts["waf_crs"] == 150
    assert tracker.counts["unknown_403"] == 0


@pytest.mark.asyncio
async def test_counts_returns_snapshot_copy() -> None:
    """``counts`` must return an independent dict — mutating it cannot
    corrupt the tracker's internal state."""
    tracker = BlockedResponseTracker()
    await tracker.record(_response(403, {"Server": "Apache"}))
    snapshot = tracker.counts
    snapshot["waf_crs"] = 9999
    assert tracker.counts["waf_crs"] == 1
