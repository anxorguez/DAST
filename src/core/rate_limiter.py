"""Global request rate limiter shared across all fuzzing scanners.

The previous implementation throttled inside each scanner instance, which
multiplied the effective rate by ``concurrent_vectors × scanners_per_vector``
and made ``--requests-per-second`` mostly cosmetic. This module exposes a
single token-bucket style limiter that is created once in the pipeline and
passed down to every scanner so the CLI flag corresponds 1:1 to outbound
HTTP rate.
"""

from __future__ import annotations

import asyncio
from time import monotonic


class GlobalRateLimiter:
    """Async global rate limiter with steady-pace token spacing.

    Each ``acquire()`` waits until at least ``1.0 / rps`` seconds have
    elapsed since the previous token was issued. Concurrent callers serialise
    behind a single lock, so the *combined* outbound rate across all scanners
    and vectors stays at the configured ``rps``.
    """

    def __init__(self, rps: float) -> None:
        if rps <= 0:
            raise ValueError("rps must be positive; use get_rate_limiter() to opt out")
        self._interval: float = 1.0 / rps
        self._lock: asyncio.Lock = asyncio.Lock()
        # ``_next_at`` is the monotonic timestamp at which the next token
        # becomes available. Initialised to "now" so the first acquire is
        # immediate.
        self._next_at: float = monotonic()

    async def acquire(self) -> None:
        """Block the caller until a token is available."""
        async with self._lock:
            now = monotonic()
            wait = self._next_at - now
            if wait > 0:
                await asyncio.sleep(wait)
                self._next_at += self._interval
            else:
                # Re-anchor the schedule to ``now`` to avoid runaway debt
                # after long idle gaps.
                self._next_at = now + self._interval


def get_rate_limiter(rps: int) -> GlobalRateLimiter | None:
    """Return a shared rate limiter, or ``None`` when throttling is disabled."""
    if rps <= 0:
        return None
    return GlobalRateLimiter(rps)
