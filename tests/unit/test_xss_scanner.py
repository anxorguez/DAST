"""Unit tests for XSSScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from src.core.config import Settings
from src.fuzzing.base_scanner import NET_ERROR_ABORT_THRESHOLD
from src.fuzzing.xss_scanner import XSSScanner
from src.vectors.models import AttackVector, SurfaceType, VulnType


def _make_vector(url: str = "http://localhost/search", field: str = "q") -> AttackVector:
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


def _mock_response(text: str) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.text = text
    resp.elapsed = MagicMock()
    resp.elapsed.total_seconds.return_value = 0.05
    return resp


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        target_url="http://localhost",
        output_dir="/tmp/dast",
        max_payloads_per_vector=10,
    )


@pytest.fixture()
def mock_http() -> MagicMock:
    client = MagicMock()
    client.get = AsyncMock()
    client.post = AsyncMock()
    client.get_no_retry = AsyncMock()
    client.post_no_retry = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_reflected_payload_detected(settings: Settings, mock_http: MagicMock) -> None:
    payload = "<script>alert(1)</script>"
    html = f"<html><body>Search results for: {payload}</body></html>"
    mock_http.get = AsyncMock(return_value=_mock_response(html))
    mock_http.get_no_retry = AsyncMock(return_value=_mock_response(html))

    scanner = XSSScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), payload)

    assert finding is not None
    assert finding.vuln_type == VulnType.XSS


@pytest.mark.asyncio
async def test_no_finding_when_payload_not_reflected(
    settings: Settings, mock_http: MagicMock
) -> None:
    payload = "<script>alert(1)</script>"
    html = "<html><body>Search results for: &lt;script&gt;alert(1)&lt;/script&gt;</body></html>"
    mock_http.get = AsyncMock(return_value=_mock_response(html))
    mock_http.get_no_retry = AsyncMock(return_value=_mock_response(html))

    scanner = XSSScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), payload)

    # Escaped output means the payload was not injected unescaped
    assert finding is None


@pytest.mark.asyncio
async def test_event_handler_partial_match(settings: Settings, mock_http: MagicMock) -> None:
    payload = "<img src=x onerror=alert(1)>"
    html = "<html><body><img src=x onerror=alert(1)></body></html>"
    mock_http.get = AsyncMock(return_value=_mock_response(html))
    mock_http.get_no_retry = AsyncMock(return_value=_mock_response(html))

    scanner = XSSScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), payload)

    assert finding is not None
    assert finding.vuln_type == VulnType.XSS


@pytest.mark.asyncio
async def test_no_false_positive_on_native_html_tags(
    settings: Settings, mock_http: MagicMock
) -> None:
    """Regression: native <img> / <body> tags in the page must not trigger XSS.

    Reproduces the DVWA login page case: the page always contains <body> and
    <img src="dvwa/images/login_logo.png"> natively, even when the payload is
    not reflected. Earlier Strategy 2 matched bare fragments like '<img' and
    '<body' and flagged 40 false positives.
    """
    payload = "<IMG SRC=x ONERROR=alert(1)>"
    # Page contains native <body> and <img> but NOT the payload.
    html = (
        '<html><body><form action="login.php" method="post">'
        '<input name="username" type="text">'
        '<input name="password" type="password">'
        '<p><img src="dvwa/images/login_logo.png" /></p>'
        "</form></body></html>"
    )
    mock_http.get = AsyncMock(return_value=_mock_response(html))
    mock_http.get_no_retry = AsyncMock(return_value=_mock_response(html))

    scanner = XSSScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), payload)

    assert finding is None


@pytest.mark.asyncio
async def test_real_reflection_detected_against_clean_baseline(
    settings: Settings, mock_http: MagicMock
) -> None:
    """A genuinely reflected payload must still be detected when baseline differs."""
    payload = "<img src=x onerror=alert(1)>"
    baseline_html = "<html><body>Hello, DAST_BASELINE_1337!</body></html>"
    reflected_html = f"<html><body>Hello, {payload}!</body></html>"

    def _response_by_params(*args: object, **kwargs: object) -> MagicMock:
        params = kwargs.get("params") or {}
        if isinstance(params, dict) and any(payload in str(v) for v in params.values()):
            return _mock_response(reflected_html)
        return _mock_response(baseline_html)

    mock_http.get = AsyncMock(side_effect=_response_by_params)
    mock_http.get_no_retry = AsyncMock(side_effect=_response_by_params)

    scanner = XSSScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), payload)

    assert finding is not None
    assert finding.vuln_type == VulnType.XSS


# ---------------------------------------------------------------------------
# Early-abort tests (BaseScanner behaviour exercised via XSSScanner)
# ---------------------------------------------------------------------------


@pytest.fixture()
def settings_low_concurrency() -> Settings:
    return Settings(
        target_url="http://localhost",
        output_dir="/tmp/dast",
        concurrent_payloads=2,
    )


@pytest.mark.asyncio
async def test_early_abort_on_all_network_errors(
    settings_low_concurrency: Settings, mock_http: MagicMock
) -> None:
    """scan() must abort early when every _send raises a network exception.

    With concurrent_payloads=2 and NET_ERROR_ABORT_THRESHOLD=3:
    - First two payload cycles run and finish (payloads_attempted=2).
    - Next two run, payloads_attempted reaches 4 >= threshold → abort set.
    - Remaining payloads see abort and skip immediately.
    Total HTTP calls must be far fewer than 20 payloads × 3 retries.
    """
    mock_http.get = AsyncMock(side_effect=httpx.TimeoutException("dead endpoint"))

    scanner = XSSScanner(settings_low_concurrency, mock_http)
    payloads = [f"<script>x{i}</script>" for i in range(20)]
    findings = await scanner.scan(_make_vector(), payloads)

    assert findings == []
    # Without abort: 20 payloads × 3 _retry_detect calls = 60+ HTTP requests.
    # With abort after ~4 complete cycles: at most ~4 * 3 + baseline = ~15 calls.
    assert mock_http.get.call_count < 30


@pytest.mark.asyncio
async def test_no_abort_when_endpoint_responds(
    settings_low_concurrency: Settings, mock_http: MagicMock
) -> None:
    """scan() must NOT abort when _send returns valid HTTP responses.

    Even if the response contains no finding (e.g. 200 OK, no reflection),
    a valid HTTP response resets the network-error counter — the endpoint is
    reachable and we must test all payloads.
    """
    safe_html = "<html><body>hello</body></html>"
    mock_http.get = AsyncMock(return_value=_mock_response(safe_html))

    scanner = XSSScanner(settings_low_concurrency, mock_http)
    payloads = [f"<script>x{i}</script>" for i in range(10)]
    findings = await scanner.scan(_make_vector(), payloads)

    assert findings == []
    # All 10 payloads should have been attempted (no abort).
    # Each payload = 3 _retry_detect × 1 HTTP call (baseline cached after first).
    # So roughly 30+ calls (10×3) plus 1 baseline.
    assert mock_http.get.call_count >= 10 * 3


@pytest.mark.asyncio
async def test_abort_threshold_is_module_constant() -> None:
    """NET_ERROR_ABORT_THRESHOLD must be a positive integer >= 1."""
    assert isinstance(NET_ERROR_ABORT_THRESHOLD, int)
    assert NET_ERROR_ABORT_THRESHOLD >= 1


@pytest.mark.asyncio
async def test_baseline_success_does_not_block_abort(
    settings_low_concurrency: Settings, mock_http: MagicMock
) -> None:
    """Baseline must NOT count toward valid-response tally.

    Regression: the previous abort logic incremented a single
    ``_valid_response_tally`` counter from any successful response, including
    the benign baseline (``DAST_BASELINE_1337``).  As a result, when the real
    payloads all timed out but the baseline succeeded, the abort heuristic
    saw a non-zero tally and the scanner kept burning every remaining payload
    at full request_timeout cost.

    The fix introduces a payload-only counter so a healthy baseline can no
    longer mask an otherwise-stuck endpoint.  Here we simulate exactly that:
    baseline returns 200 OK, every payload times out — the scanner must
    still abort early.
    """
    safe_html = "<html><body>baseline ok</body></html>"
    baseline_response = _mock_response(safe_html)

    def _route(*args: object, **kwargs: object) -> MagicMock:
        params = kwargs.get("params") or {}
        if isinstance(params, dict) and any(
            "DAST_BASELINE_1337" in str(v) for v in params.values()
        ):
            return baseline_response
        raise httpx.TimeoutException("payload timeout")

    mock_http.get = AsyncMock(side_effect=_route)

    scanner = XSSScanner(settings_low_concurrency, mock_http)
    payloads = [f"<script>x{i}</script>" for i in range(20)]
    findings = await scanner.scan(_make_vector(), payloads)

    assert findings == []
    # Without the fix: baseline succeeds → tally > 0 → abort never fires →
    # 20 payloads × 3 retries ≈ 60 calls plus baselines.
    # With the fix: abort fires after ~3 payloads of timeouts → < 30 calls.
    assert mock_http.get.call_count < 30, (
        f"baseline must not block abort heuristic — got {mock_http.get.call_count} HTTP calls"
    )


@pytest.mark.asyncio
async def test_format_exc_includes_type_for_empty_message() -> None:
    """_format_exc must surface the exception type even when str(exc) is empty.

    httpx.ReadTimeout and ConnectTimeout produce empty strings, which used to
    log as ``error: `` and made post-mortem debugging impossible.
    """
    from src.fuzzing.base_scanner import _format_exc

    formatted = _format_exc(httpx.ReadTimeout(""))
    assert "ReadTimeout" in formatted
    # Must not be just ": " or empty.
    assert formatted.endswith(": ") is False
    assert len(formatted) > len("ReadTimeout: ")
