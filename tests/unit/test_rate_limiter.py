"""Unit tests for the global rate limiter."""

from __future__ import annotations

import asyncio
from time import monotonic

import pytest

from src.core.rate_limiter import GlobalRateLimiter, get_rate_limiter


def test_get_rate_limiter_disabled_for_non_positive_rps() -> None:
    assert get_rate_limiter(0) is None
    assert get_rate_limiter(-1) is None


def test_get_rate_limiter_returns_instance_for_positive_rps() -> None:
    limiter = get_rate_limiter(5)
    assert isinstance(limiter, GlobalRateLimiter)


def test_constructor_rejects_non_positive_rps() -> None:
    with pytest.raises(ValueError):
        GlobalRateLimiter(0)


@pytest.mark.asyncio
async def test_acquire_enforces_combined_rate_across_concurrent_callers() -> None:
    """At rps=10, four concurrent acquires must take at least ~0.3s total.

    The schedule issues a token every 0.1s (1/10 rps). With four concurrent
    callers serialised by the limiter, the wall-clock duration must be no
    less than ``3 × interval`` (the first acquire is instant; tokens 2-4
    are spaced 100 ms apart).
    """
    limiter = GlobalRateLimiter(10)
    start = monotonic()
    await asyncio.gather(*(limiter.acquire() for _ in range(4)))
    elapsed = monotonic() - start
    # Allow generous slack for test runner jitter; the lower bound is what matters.
    assert elapsed >= 0.28, f"limiter did not throttle: elapsed={elapsed:.3f}s"
