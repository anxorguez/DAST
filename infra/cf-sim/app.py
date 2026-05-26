"""cf-sim — a minimal Cloudflare ``cf_clearance`` challenge simulator.

It implements the *minimum* cf_clearance contract:

* issues a ``cf_clearance`` cookie after a JavaScript challenge that only a
  real browser (which executes JS) can solve;
* binds the cookie to the ``User-Agent`` that requested it;
* answers ``403`` — with an identifiable ``X-Cf-Sim-Challenge`` marker —
  whenever the cookie is missing, unknown, bound to a different UA, or
  expired;
* otherwise proxies the request to the real backend (DVWA).

It deliberately does **not** imitate TLS/JA3 fingerprinting, Bot
Management, or a real Turnstile widget — see ``README.md`` for scope.

The ``X-Cf-Sim-Challenge: <reason>`` header is the API of this simulator
towards the DAST ``HTTPClient``: the bridge uses it to tell a recoverable
condition (``expired`` / ``missing`` → refresh the cookie) apart from a
permanent failure (``ua_mismatch`` / ``invalid_token`` → the session is
dead, refreshing will not help).
"""

from __future__ import annotations

import hashlib
import os
import string
import time
import uuid
from urllib.parse import parse_qs

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.middleware.base import RequestResponseEndpoint

# --- Configuration ---------------------------------------------------------
BACKEND = os.environ.get("BACKEND", "http://dvwa-origin:80").rstrip("/")
CLEARANCE_TTL_SECONDS = int(os.environ.get("CLEARANCE_TTL_SECONDS", "1800"))

_SECRET = "cf-sim-secret"
_COOKIE_NAME = "cf_clearance"
_B64_ALPHABET = set(string.ascii_letters + string.digits + "+/=")
_HOP_BY_HOP = {
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
}

# In-memory clearance store: token -> {"ua": str, "ip": str, "expires_at": float}
valid_tokens: dict[str, dict[str, object]] = {}

app = FastAPI(title="cf-sim", docs_url=None, redoc_url=None)

# HTML served by the challenge page.  The inline script computes a value the
# way a real browser would (it needs ``navigator`` and ``btoa``) and submits
# it.  A bare httpx request never runs the script, so it never reaches the
# POST and never obtains a cookie.
_CHALLENGE_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Just a moment...</title></head>
<body>
  <p>Checking your browser before accessing the site...</p>
  <form id="cf-form" method="POST" action="/cdn-cgi/challenge">
    <input type="hidden" name="answer" id="cf-answer">
    <input type="hidden" name="ret" id="cf-ret" value="__RET__">
  </form>
  <script>
    // Only a real browser can produce this value: it needs navigator + btoa.
    document.getElementById('cf-answer').value =
        btoa(navigator.userAgent + Date.now());
    document.getElementById('cf-form').submit();
  </script>
</body>
</html>
"""


def _derive_token(ua: str, ip: str, nonce: str) -> str:
    """Return a 32-char clearance token bound to *ua*, *ip* and *nonce*."""
    raw = f"{ua}|{ip}|{nonce}|{_SECRET}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def _client_ip(request: Request) -> str:
    """Best-effort client IP — used only as a token-derivation input."""
    return request.client.host if request.client else "unknown"


def _looks_base64(value: str) -> bool:
    """True if *value* is a plausible base64 string from a browser."""
    return bool(value) and all(c in _B64_ALPHABET for c in value)


def _challenge_response(reason: str, ret_path: str) -> HTMLResponse:
    """Build a 403 carrying the ``X-Cf-Sim-Challenge`` marker.

    The body contains a ``<meta http-equiv="refresh">`` that bounces a real
    browser to the JS challenge page; a plain HTTP client simply reads the
    403 and the marker header.
    """
    body = (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f'<meta http-equiv="refresh" content="0; url=/cdn-cgi/challenge-page?ret={ret_path}">'
        "<title>Just a moment...</title></head>"
        "<body><p>Checking your browser before accessing the site "
        f"(reason: {reason}).</p></body></html>"
    )
    return HTMLResponse(
        content=body,
        status_code=403,
        headers={"X-Cf-Sim-Challenge": reason},
    )


@app.get("/cdn-cgi/challenge-page", response_class=HTMLResponse)
async def challenge_page(ret: str = "/") -> HTMLResponse:
    """Serve the JavaScript challenge page (bypasses clearance checks)."""
    safe_ret = ret.replace('"', "%22").replace("<", "%3C").replace(">", "%3E")
    return HTMLResponse(_CHALLENGE_HTML.replace("__RET__", safe_ret))


@app.post("/cdn-cgi/challenge")
async def solve_challenge(request: Request) -> Response:
    """Validate the browser-computed answer and issue a clearance cookie."""
    raw = (await request.body()).decode("utf-8", errors="replace")
    form = parse_qs(raw)
    answer = (form.get("answer") or [""])[0]
    ret = (form.get("ret") or ["/"])[0] or "/"

    # The answer must look like the base64 a real browser produced.
    if len(answer) < 16 or not _looks_base64(answer):
        return _challenge_response("invalid_token", ret)

    ua = request.headers.get("user-agent", "")
    ip = _client_ip(request)
    token = _derive_token(ua, ip, uuid.uuid4().hex)
    valid_tokens[token] = {
        "ua": ua,
        "ip": ip,
        "expires_at": time.time() + CLEARANCE_TTL_SECONDS,
    }

    redirect = RedirectResponse(url=ret, status_code=302)
    redirect.set_cookie(
        _COOKIE_NAME,
        token,
        max_age=CLEARANCE_TTL_SECONDS,
        path="/",
        httponly=False,
    )
    return redirect


async def _forward(request: Request) -> Response:
    """Proxy a cleared request to the backend and relay the response."""
    body = await request.body()
    upstream_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")
    }
    url = f"{BACKEND}{request.url.path}"

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=30.0,
        trust_env=False,  # equivalent to proxy=False — never use an env proxy
        verify=False,
    ) as client:
        upstream = await client.request(
            request.method,
            url,
            params=dict(request.query_params),
            headers=upstream_headers,
            content=body,
        )

    response = Response(content=upstream.content, status_code=upstream.status_code)
    # Rebuild headers preserving multiple Set-Cookie entries; drop hop-by-hop
    # headers and let Starlette recompute Content-Length for the (already
    # decompressed) body.
    raw_headers: list[tuple[bytes, bytes]] = [
        (k.encode("latin-1"), v.encode("latin-1"))
        for k, v in upstream.headers.multi_items()
        if k.lower() not in _HOP_BY_HOP
    ]
    raw_headers.append((b"content-length", str(len(upstream.content)).encode("latin-1")))
    response.raw_headers = raw_headers
    return response


@app.middleware("http")
async def verify_clearance(request: Request, call_next: RequestResponseEndpoint) -> Response:
    """Gate every non-``/cdn-cgi/*`` request behind a valid clearance cookie."""
    path = request.url.path
    if path.startswith("/cdn-cgi/"):
        # Challenge endpoints are always reachable.
        return await call_next(request)

    ret_path = path
    if request.url.query:
        ret_path = f"{path}?{request.url.query}"

    token = request.cookies.get(_COOKIE_NAME)
    ua = request.headers.get("user-agent", "")

    if not token:
        return _challenge_response("missing", ret_path)

    record = valid_tokens.get(token)
    if record is None:
        return _challenge_response("invalid_token", ret_path)

    if record["ua"] != ua:
        # The cookie was minted for a different browser — kill it.
        valid_tokens.pop(token, None)
        return _challenge_response("ua_mismatch", ret_path)

    if float(record["expires_at"]) < time.time():  # type: ignore[arg-type]
        valid_tokens.pop(token, None)
        return _challenge_response("expired", ret_path)

    return await _forward(request)
