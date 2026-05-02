"""Unit tests for the Fuzzer orchestrator (per-vector timeout)."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from src.core.config import Settings
from src.fuzzing.fuzzer import Fuzzer
from src.vectors.models import AttackVector, SurfaceType, VulnType


def _make_vector(field: str = "id") -> AttackVector:
    url = "http://localhost/vuln"
    return AttackVector(
        source_url=url,
        target_url=url,
        method="GET",
        field_name=field,
        surface=SurfaceType.URL_PARAM,
        field_context=f"URL query parameter: {field}",
        extra_params={},
        priority=1,
        applicable_vulns=[VulnType.XSS],
    )


@pytest.mark.asyncio
async def test_per_vector_timeout_aborts_stuck_scanner() -> None:
    """Fuzzer must cancel a scanner that exceeds scanner_vector_timeout_seconds.

    Regression for the indefinitely-hung pipeline bug: a single endpoint that
    accepts the connection and then never responds (slow target, tarpit,
    half-broken vhost) used to block the whole fuzz phase.  The hard wall
    around scanner.scan() bounds the worst case to a known constant.
    """
    settings = Settings(
        target_url="http://localhost",
        output_dir="/tmp/dast",
        payload_types="xss",
        max_payloads_per_vector=5,
        # Tight cap so the test is fast; semantics are the same at any value.
        scanner_vector_timeout_seconds=1,
    )

    async def _hang(*_args: object, **_kwargs: object) -> list[object]:
        # Simulate a scanner that never returns (slow target).
        await asyncio.sleep(60)
        return []

    fuzzer = Fuzzer(settings)
    # Patch the scanner's scan method to hang forever.
    with patch("src.fuzzing.xss_scanner.XSSScanner.scan", new=_hang):
        # Also short-circuit the payload loader to avoid touching disk.
        with patch.object(fuzzer._loader, "load", return_value=["<script>x</script>"]):
            findings = await fuzzer.run([_make_vector()])

    # Timed-out scanner returns no findings, but the run must complete.
    assert findings == []


@pytest.mark.asyncio
async def test_per_vector_timeout_preserves_partial_findings() -> None:
    """Findings confirmed before the timeout must NOT be discarded.

    Regression for the cmdi 0-recall bug: error-based payloads matched
    ``uid=33(www-data)`` against DVWA repeatedly, but the scanner then ran
    into the serialised time-based payloads (``; sleep 5``) which consumed
    the whole 120 s budget.  ``asyncio.wait_for`` cancelled the gather and
    every confirmed finding was lost together with the cancelled task —
    the report ended up with zero cmdi findings despite nine consecutive
    pattern matches in the scan.log.
    """
    from src.analysis.models import Confidence, RawFinding
    from src.fuzzing.xss_scanner import XSSScanner
    from src.vectors.models import VulnType

    settings = Settings(
        target_url="http://localhost",
        output_dir="/tmp/dast",
        payload_types="xss",
        max_payloads_per_vector=5,
        scanner_vector_timeout_seconds=1,
    )

    vector = _make_vector()
    pre_timeout_finding = RawFinding(
        vector=vector,
        vuln_type=VulnType.XSS,
        payload="<early>",
        response_snippet="confirmed before timeout",
        confidence=Confidence.CONFIRMED,
        evidence="early hit",
        response_time_ms=12,
    )

    async def _emit_then_hang(self: XSSScanner, *_args: object, **_kwargs: object) -> list[object]:
        # Simulate the real scanner: confirm a finding, push it to the
        # partial-findings buffer (as the production code path does inside
        # the gather lock), then stall on the next payload until cancelled.
        self._partial_findings = [pre_timeout_finding]
        await asyncio.sleep(60)
        return []

    fuzzer = Fuzzer(settings)
    with patch("src.fuzzing.xss_scanner.XSSScanner.scan", new=_emit_then_hang):
        with patch.object(fuzzer._loader, "load", return_value=["<script>x</script>"]):
            findings = await fuzzer.run([vector])

    assert findings == [pre_timeout_finding]


@pytest.mark.asyncio
async def test_scanner_within_timeout_completes_normally() -> None:
    """A fast scanner must run to completion, with no spurious cancellation."""
    settings = Settings(
        target_url="http://localhost",
        output_dir="/tmp/dast",
        payload_types="xss",
        max_payloads_per_vector=5,
        scanner_vector_timeout_seconds=10,
    )

    sentinel: list[object] = ["dummy_finding"]

    async def _fast(*_args: object, **_kwargs: object) -> list[object]:
        await asyncio.sleep(0)
        return sentinel

    fuzzer = Fuzzer(settings)
    with patch("src.fuzzing.xss_scanner.XSSScanner.scan", new=_fast):
        with patch.object(fuzzer._loader, "load", return_value=["<script>x</script>"]):
            findings = await fuzzer.run([_make_vector()])

    assert findings == sentinel
