"""Abstract base class shared by all vulnerability scanners."""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod

import httpx
from loguru import logger

from src.analysis.models import Confidence, RawFinding
from src.core.config import Settings
from src.core.http_client import HTTPClient
from src.core.rate_limiter import GlobalRateLimiter
from src.fuzzing import obfuscators
from src.vectors.models import AttackVector, VulnType

# Number of times each payload is retried to confirm a finding.
RETRY_COUNT = 3
# Minimum number of successful detections out of RETRY_COUNT to confirm.
CONFIRM_THRESHOLD = 2
# Abort a scanner on a vector after this many complete payload cycles produce
# zero valid HTTP responses (only network-level errors).  Protects against
# dead or unreachable endpoints that would otherwise exhaust every payload.
#
# IMPORTANT: the abort heuristic only counts *payload* requests, not baseline
# requests.  The baseline payload ``DAST_BASELINE_1337`` is benign and almost
# always succeeds even when the real payloads time out, so mixing it into the
# tally would mask a stuck endpoint and prevent the abort from ever firing.
NET_ERROR_ABORT_THRESHOLD = 3


def _format_exc(exc: BaseException) -> str:
    """Format *exc* for logging with type + meaningful message.

    ``str(exc)`` is empty for several httpx exception classes (notably
    ``ReadTimeout`` and ``ConnectTimeout``) — falling back to ``repr`` keeps
    log lines diagnosable when the message is missing.  The message is
    truncated to keep DEBUG output manageable.
    """
    msg = str(exc)
    if not msg:
        msg = repr(exc)
    if len(msg) > 200:
        msg = msg[:200] + "..."
    return f"{type(exc).__name__}: {msg}"


# Keywords that identify time-based payloads.  These must run sequentially
# because parallel execution corrupts timing measurements.
_TIME_BASED_KEYWORDS: tuple[str, ...] = (
    "sleep(",
    "waitfor delay",
    "pg_sleep(",
    "sleep ",
    "ping -c",
    "ping -n",
)


def _is_time_based(payload: str) -> bool:
    """Return True if *payload* uses a time-based delay technique."""
    lower = payload.lower()
    return any(kw in lower for kw in _TIME_BASED_KEYWORDS)


class BaseScanner(ABC):
    """Abstract base for all vulnerability scanners.

    Subclasses implement ``_detect`` which is called up to RETRY_COUNT
    times per payload. The scanner only emits a finding when at least
    CONFIRM_THRESHOLD attempts succeed.

    Concurrency model
    -----------------
    * Different payloads are tested concurrently, bounded by
      *concurrent_payloads* from Settings.
    * Time-based payloads run sequentially behind a dedicated lock to
      avoid corrupting timing measurements.
    * The retry loop (RETRY_COUNT attempts) within a single payload is
      always sequential.
    """

    VULN_TYPE: VulnType  # Must be set by every concrete subclass.

    # Encodings that this scanner's detection logic can survive.  The Fuzzer
    # computes ``settings.obfuscation_list ∩ SUPPORTED_ENCODINGS`` per scan,
    # falling back to ``("none",)`` if the intersection is empty.  Override in
    # subclasses; the base default is conservative.
    SUPPORTED_ENCODINGS: tuple[str, ...] = ("none",)

    def __init__(
        self,
        settings: Settings,
        http_client: HTTPClient,
        rate_limiter: GlobalRateLimiter | None = None,
    ) -> None:
        self._settings = settings
        self._http = http_client
        # Shared across all scanners so ``--requests-per-second`` corresponds
        # to the *combined* outbound rate, not per-scanner.
        self._rate_limiter = rate_limiter
        # Lock ensures time-based payloads don't run concurrently.
        self._time_based_lock: asyncio.Lock = asyncio.Lock()
        # Per-scan counters, reset at the start of each scan() call.
        # ``_payload_*`` counters intentionally exclude baseline requests so
        # the early-abort heuristic isn't masked by a successful baseline
        # against a stuck endpoint.  See ``_send`` and the abort check below.
        self._payload_net_error_tally: int = 0
        self._payload_response_tally: int = 0
        # Findings accumulated during the current scan() call.  Exposed so
        # the Fuzzer can recover partial results when the per-vector wall
        # clock cancels scan() mid-flight; without this they would be lost
        # along with the cancelled gather().
        self._partial_findings: list[RawFinding] = []
        # Health flags consumed by the Fuzzer to populate scanner_health
        # in the final report.  See ``ScanHealth``.
        self._aborted_early: bool = False

    # -------------------------------------------------------------------
    # Public interface
    # -------------------------------------------------------------------

    async def scan(
        self,
        vector: AttackVector,
        payloads: list[str],
        semaphore: asyncio.Semaphore | None = None,
    ) -> list[RawFinding]:
        """Scan *vector* with *payloads* and return confirmed findings.

        Concurrent payloads are bounded by *concurrent_payloads* from
        Settings (or the optional external *semaphore*).  Time-based
        payloads bypass the pool and run behind a dedicated serial lock.

        Early abort: if at least NET_ERROR_ABORT_THRESHOLD complete payload
        cycles have been attempted and every payload _send call raised a
        network exception (no valid HTTP response at all from a real payload),
        remaining payloads are skipped.  This avoids exhausting all payloads
        on dead/unreachable endpoints.

        Baseline requests (sent via :meth:`_send_baseline`) are deliberately
        excluded from these counters.  The baseline payload is benign and
        almost always returns a valid response — mixing it into the tally
        would prevent the abort from ever firing when the real payloads
        consistently time out.

        Args:
            vector: The injection target.
            payloads: Payload strings to test.
            semaphore: Optional external semaphore (unused, kept for API
                compatibility with the Fuzzer's vector-level semaphore).

        Returns:
            All confirmed RawFinding instances for this vector.
        """
        # Reset payload-only counters for this scan call.
        self._payload_net_error_tally = 0
        self._payload_response_tally = 0
        # Reset partial-findings buffer.  Stored on the instance so
        # cancellation (per-vector timeout in the Fuzzer) can still recover
        # whatever was confirmed before the cancel.
        self._partial_findings = []
        self._aborted_early = False

        effective_encodings = self._compute_effective_encodings()

        max_concurrent = max(1, self._settings.concurrent_payloads)
        payload_sem = asyncio.Semaphore(max_concurrent)

        findings = self._partial_findings
        findings_lock = asyncio.Lock()

        abort = asyncio.Event()
        payloads_attempted = 0

        # Cross-product: each (payload, encoding) pair is one atomic unit of work.
        work = [(p, enc) for p in payloads for enc in effective_encodings]

        async def _scan_one(payload: str, encoding: str) -> None:
            nonlocal payloads_attempted
            if abort.is_set():
                return

            if _is_time_based(payload):
                # Time-based payloads run serially to preserve timing accuracy.
                async with self._time_based_lock:
                    if self._rate_limiter is not None:
                        await self._rate_limiter.acquire()
                    hits = await self._retry_detect(vector, payload, encoding)
            else:
                async with payload_sem:
                    if abort.is_set():
                        return
                    if self._rate_limiter is not None:
                        await self._rate_limiter.acquire()
                    hits = await self._retry_detect(vector, payload, encoding)

            if hits:
                async with findings_lock:
                    findings.extend(hits)

            payloads_attempted += 1
            # Abort heuristic: only payload responses count toward
            # ``_payload_response_tally``.  Baseline requests are excluded
            # because they use a benign string and would otherwise mask a
            # stuck endpoint where every real payload times out.
            if (
                not abort.is_set()
                and payloads_attempted >= NET_ERROR_ABORT_THRESHOLD
                and self._payload_response_tally == 0
            ):
                logger.warning(
                    "Early abort: {vt} scanner on {url} [{field}] — "
                    "{a} payload(s) attempted with 0 valid HTTP responses "
                    "({e} network error(s)); skipping {rem} remaining payload(s)",
                    vt=self.VULN_TYPE.value,
                    url=vector.target_url,
                    field=vector.field_name,
                    a=payloads_attempted,
                    e=self._payload_net_error_tally,
                    rem=len(work) - payloads_attempted,
                )
                self._aborted_early = True
                abort.set()

        tasks = [asyncio.create_task(_scan_one(p, enc)) for p, enc in work]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            # The per-vector timeout in Fuzzer cancelled us.  Make sure the
            # in-flight tasks settle before returning so ``_partial_findings``
            # is fully consistent — otherwise a task mid-extend could leave
            # the list racy or the response tally off.  Then re-raise so the
            # caller sees the cancellation; the Fuzzer reads
            # ``self._partial_findings`` from its except handler.
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        return findings

    @property
    def partial_findings(self) -> list[RawFinding]:
        """Findings accumulated during the most recent (or in-flight) scan.

        Read by :class:`~src.fuzzing.fuzzer.Fuzzer` after a per-vector timeout
        cancels :meth:`scan` so confirmed evidence already collected is not
        lost together with the cancelled task.
        """
        return self._partial_findings

    @property
    def aborted_early(self) -> bool:
        """True if scan() hit the 0-valid-responses early-abort heuristic."""
        return self._aborted_early

    # -------------------------------------------------------------------
    # Abstract method for subclasses
    # -------------------------------------------------------------------

    @abstractmethod
    async def _detect(
        self, vector: AttackVector, payload: str, encoding: str = "none"
    ) -> RawFinding | None:
        """Attempt to detect a vulnerability for one payload against one vector.

        Returns:
            A RawFinding if evidence is found, otherwise None.
        """
        ...

    # -------------------------------------------------------------------
    # Shared helpers
    # -------------------------------------------------------------------

    def _compute_effective_encodings(self) -> tuple[str, ...]:
        """Return the intersection of requested and supported encodings.

        Falls back to ``("none",)`` if the intersection is empty so the
        scanner always runs at minimum with the unencoded payload.
        """
        requested = self._settings.obfuscation_list or ["none"]
        effective = tuple(e for e in requested if e in self.SUPPORTED_ENCODINGS) or ("none",)
        if set(effective) != set(requested):
            logger.debug(
                "{vt}: encoding intersection {eff} (requested={req}, supported={sup})",
                vt=self.VULN_TYPE.value,
                eff=effective,
                req=requested,
                sup=self.SUPPORTED_ENCODINGS,
            )
        return effective

    async def _retry_detect(
        self, vector: AttackVector, payload: str, encoding: str = "none"
    ) -> list[RawFinding]:
        """Run _detect up to RETRY_COUNT times and return hits if ≥ CONFIRM_THRESHOLD."""
        confirmed_hits: list[RawFinding] = []
        for _ in range(RETRY_COUNT):
            hit = await self._detect(vector, payload, encoding)
            if hit is not None:
                confirmed_hits.append(hit)
        if len(confirmed_hits) >= CONFIRM_THRESHOLD:
            return confirmed_hits
        return []

    async def _send(
        self,
        vector: AttackVector,
        payload: str,
        no_retry: bool = False,
        is_baseline: bool = False,
        encoding: str = "none",
    ) -> tuple[httpx.Response, int]:
        """Send an HTTP request with *payload* injected into *vector*.

        The ``encoding`` parameter selects an optional obfuscation transform.
        For ``none``, ``base64`` and ``sql_comment`` we go through the normal
        httpx params/data path (httpx percent-encodes the value as usual, and
        PHP decodes ``/**/`` back before it reaches MySQL).  For ``url`` and
        ``double_url`` we MUST bypass httpx auto-encoding and build the query
        string / form body manually, otherwise ``url`` becomes ``double_url`` on
        the wire and ``double_url`` becomes triple-encoded.

        For real payloads (``is_baseline=False``), updates
        ``_payload_response_tally`` on success and ``_payload_net_error_tally``
        on any network exception, enabling the early-abort check in
        :meth:`scan`.  Baseline requests bypass these counters by design — see
        the docstring of :meth:`scan` for the rationale.

        Returns:
            Tuple of (response, elapsed_milliseconds).
        """
        encoded_payload = obfuscators.apply(encoding, payload)
        start = time.monotonic()
        try:
            if encoding in (
                obfuscators.ENCODING_NONE,
                obfuscators.ENCODING_BASE64,
                obfuscators.ENCODING_SQL_COMMENT,
            ):
                params = {**vector.extra_params, vector.field_name: encoded_payload}
                if vector.method == "POST":
                    if no_retry:
                        response = await self._http.post_no_retry(vector.target_url, data=params)
                    else:
                        response = await self._http.post(vector.target_url, data=params)
                else:
                    if no_retry:
                        response = await self._http.get_no_retry(vector.target_url, params=params)
                    else:
                        response = await self._http.get(vector.target_url, params=params)
            else:
                # url / double_url: build the wire string manually so httpx does
                # NOT percent-encode our already-encoded payload again.  Note the
                # extra_params are URL-encoded normally (via quote) — only the
                # injected field carries the obfuscated form.
                from urllib.parse import quote as _q

                extra_pairs = "&".join(
                    f"{_q(k, safe='')}={_q(v, safe='')}" for k, v in vector.extra_params.items()
                )
                field_pair = f"{_q(vector.field_name, safe='')}={encoded_payload}"
                raw_query = "&".join(p for p in (extra_pairs, field_pair) if p)

                if vector.method == "POST":
                    headers = {"Content-Type": "application/x-www-form-urlencoded"}
                    if no_retry:
                        response = await self._http.post_no_retry(
                            vector.target_url,
                            content=raw_query.encode("ascii"),
                            headers=headers,
                        )
                    else:
                        response = await self._http.post(
                            vector.target_url,
                            content=raw_query.encode("ascii"),
                            headers=headers,
                        )
                else:
                    sep = "&" if "?" in vector.target_url else "?"
                    target = f"{vector.target_url}{sep}{raw_query}"
                    if no_retry:
                        response = await self._http.get_no_retry(target)
                    else:
                        response = await self._http.get(target)
        except Exception:
            if not is_baseline:
                self._payload_net_error_tally += 1
            raise

        elapsed_ms = int((time.monotonic() - start) * 1000)
        if not is_baseline:
            self._payload_response_tally += 1
        return response, elapsed_ms

    async def _send_baseline(self, vector: AttackVector) -> tuple[httpx.Response, int]:
        """Send a benign baseline request for comparison.

        Baseline requests are excluded from the abort heuristic counters; see
        :meth:`scan` for why.  Always sent without obfuscation so the response
        is comparable to the plain-text page.
        """
        return await self._send(vector, "DAST_BASELINE_1337", is_baseline=True)

    @staticmethod
    def _truncate(text: str, max_len: int = 500) -> str:
        if len(text) <= max_len:
            return text
        return text[:max_len] + "..."

    def _make_finding(
        self,
        vector: AttackVector,
        payload: str,
        response: httpx.Response,
        elapsed_ms: int,
        confidence: Confidence,
        evidence: str,
        encoding: str = "none",
    ) -> RawFinding:
        snippet = self._truncate(response.text)
        if encoding != "none":
            evidence = f"[obfuscation={encoding}] {evidence}"
        return RawFinding(
            vector=vector,
            vuln_type=self.VULN_TYPE,
            payload=payload,
            response_snippet=snippet,
            confidence=confidence,
            evidence=evidence,
            response_time_ms=elapsed_ms,
            encoding=encoding,
        )
