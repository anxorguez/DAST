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
