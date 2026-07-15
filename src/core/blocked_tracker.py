"""Thread-safe counter for 403 responses classified by protection layer.

Used by HTTPClient to categorise blocked responses so the final report can
distinguish WAF/CRS blocks from cf_clearance rejections from generic 403s.
"""

from __future__ import annotations

import asyncio

import httpx


class BlockedResponseTracker:
    """Aggregates 403-response counts across all concurrent HTTPClient instances.

    Classification logic (first match wins):

    * ``cf_clearance`` — response carries an ``X-Cf-Sim-Challenge`` header.
    * ``waf_crs``      — response ``Server`` header contains ``Apache``
      (ModSecurity front-end). Also captures legitimate ``dvwa-origin`` 403s
      when scanning without a WAF; acceptable trade-off in experiment context.
    * ``unknown_403``  — 403 with no recognisable protection marker.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._counts: dict[str, int] = {
            "waf_crs": 0,
            "cf_clearance": 0,
            "unknown_403": 0,
        }

    async def record(self, response: httpx.Response) -> None:
        """Inspect *response* and increment the appropriate bucket if it is a 403."""
        if response.status_code != 403:
            return
        bucket = self._classify(response)
        async with self._lock:
            self._counts[bucket] += 1

    @staticmethod
    def _classify(response: httpx.Response) -> str:
        if response.headers.get("X-Cf-Sim-Challenge"):
            return "cf_clearance"
        server = response.headers.get("Server", "").lower()
        if "apache" in server:
            return "waf_crs"
        return "unknown_403"

    @property
    def counts(self) -> dict[str, int]:
        """Return a snapshot of current counts (no lock — read after scan ends)."""
        return dict(self._counts)
