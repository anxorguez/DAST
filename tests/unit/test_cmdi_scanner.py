"""Unit tests for CMDiScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analysis.models import Confidence
from src.core.config import Settings
from src.fuzzing.cmdi_scanner import CMDiScanner
from src.vectors.models import AttackVector, SurfaceType, VulnType


def _make_vector(
    url: str = "http://localhost/vulnerabilities/exec/",
    field: str = "ip",
) -> AttackVector:
    return AttackVector(
        source_url=url,
        target_url=url,
        method="POST",
        surface=SurfaceType.FORM_FIELD,
        field_name=field,
        field_context="<form action='exec' method='POST'>",
        applicable_vulns=[VulnType.CMDI],
        extra_params={"Submit": "Submit"},
    )


def _mock_response(text: str, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = {}
    return resp


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        target_url="http://localhost",
        output_dir="/tmp/dast",
        max_payloads_per_vector=10,
        concurrent_payloads=1,
    )


@pytest.fixture()
def mock_http() -> MagicMock:
    client = MagicMock()
    client.get = AsyncMock()
    client.get_no_retry = AsyncMock()
    client.post = AsyncMock()
    client.post_no_retry = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_confirmed_on_id_output(settings: Settings, mock_http: MagicMock) -> None:
    """``id`` output (uid=N(name)) yields CONFIRMED."""
    body = "<pre>PING 127.0.0.1\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n</pre>"
    mock_http.post = AsyncMock(return_value=_mock_response(body))

    scanner = CMDiScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), "; id")

    assert finding is not None
    assert finding.vuln_type == VulnType.CMDI
    assert finding.confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_confirmed_on_whoami_output(settings: Settings, mock_http: MagicMock) -> None:
    """Bare ``www-data`` (whoami) yields CONFIRMED.

    Regression for the cmdi 0-recall analysis: the previous pattern set
    only matched ``id`` and ``/etc/passwd`` — ``; whoami`` against DVWA
    produced ``www-data`` and was silently ignored.
    """
    body = "<pre>PING 127.0.0.1 (127.0.0.1)\nwww-data\n</pre>"
    mock_http.post = AsyncMock(return_value=_mock_response(body))

    scanner = CMDiScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), "; whoami")

    assert finding is not None
    assert finding.confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_confirmed_on_ls_output(settings: Settings, mock_http: MagicMock) -> None:
    """``ls -la`` header + permission line yields CONFIRMED."""
    body = (
        "<pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n"
        "total 24\n"
        "drwxr-xr-x 2 root root 4096 Jan  1 00:00 .\n"
        "drwxr-xr-x 7 root root 4096 Jan  1 00:00 ..\n"
        "-rw-r--r-- 1 root root  102 Jan  1 00:00 index.php\n"
        "</pre>"
    )
    mock_http.post = AsyncMock(return_value=_mock_response(body))

    scanner = CMDiScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), "; ls -la")

    assert finding is not None
    assert finding.confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_confirmed_on_ifconfig_output(settings: Settings, mock_http: MagicMock) -> None:
    """``ifconfig`` ``inet`` line with dotted-quad yields CONFIRMED."""
    body = (
        "<pre>eth0: flags=4163  mtu 1500\n"
        "        inet 172.18.0.4  netmask 255.255.0.0  broadcast 172.18.255.255\n"
        "        ether 02:42:ac:12:00:04  txqueuelen 0\n"
        "</pre>"
    )
    mock_http.post = AsyncMock(return_value=_mock_response(body))

    scanner = CMDiScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), "; ifconfig")

    assert finding is not None
    assert finding.confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_confirmed_on_passwd_leak(settings: Settings, mock_http: MagicMock) -> None:
    """``cat /etc/passwd`` content yields CONFIRMED."""
    body = (
        "<pre>root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "</pre>"
    )
    mock_http.post = AsyncMock(return_value=_mock_response(body))

    scanner = CMDiScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), "; cat /etc/passwd")

    assert finding is not None
    assert finding.confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_no_finding_on_clean_ping_output(settings: Settings, mock_http: MagicMock) -> None:
    """Plain ping output without injected command response → no finding.

    A normal DVWA response to a benign IP contains the ping framing but no
    command-injection signal.  The scanner must not flag it.  ``inet`` /
    ``bytes from`` patterns are gated on injected output that *follows*
    the ping; a clean ping output without further command output should
    not trigger them on its own — the body contains a plain ``PING ...``
    summary that does not include the ``inet`` ifconfig line, ``uid=``,
    or any other injected-command signature.
    """
    body = (
        "<pre>--- 127.0.0.1 ping statistics ---\n"
        "4 packets transmitted, 4 received, 0% packet loss, time 3003ms\n"
        "rtt min/avg/max/mdev = 0.025/0.038/0.063/0.014 ms\n"
        "</pre>"
    )
    mock_http.post = AsyncMock(return_value=_mock_response(body))

    scanner = CMDiScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), "127.0.0.1")

    assert finding is None


@pytest.mark.asyncio
async def test_no_finding_on_empty_response(settings: Settings, mock_http: MagicMock) -> None:
    """Empty response body produces no finding."""
    mock_http.post = AsyncMock(return_value=_mock_response(""))

    scanner = CMDiScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), "; id")

    assert finding is None
