#!/usr/bin/env bash
# start.sh — Initialise the DAST testing environment.
# Starts DVWA + MariaDB, waits for health, and runs DVWA DB setup.
set -euo pipefail

DVWA_URL="http://localhost:8080"
WAF_URL="http://localhost:8088"
CFSIM_URL="http://localhost:8089/cdn-cgi/challenge-page"
HEALTH_TIMEOUT=60
HEALTH_INTERVAL=3

# ---------------------------------------------------------------------------
# 1. Verify Docker and docker compose are installed.
# ---------------------------------------------------------------------------
if ! command -v docker &>/dev/null; then
    echo "[ERROR] docker is not installed or not in PATH. Aborting." >&2
    exit 1
fi

if ! docker compose version &>/dev/null; then
    echo "[ERROR] docker compose (v2) is not installed. Aborting." >&2
    exit 1
fi

echo "[INFO] Docker and docker compose are available."

# ---------------------------------------------------------------------------
# 2. Ensure .env exists. If not, copy from .env.example.
# ---------------------------------------------------------------------------
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "[WARN] .env file not found. Copied .env.example to .env."
        echo "[WARN] Review .env and set the correct values before running scans."
    else
        echo "[ERROR] Neither .env nor .env.example found. Aborting." >&2
        exit 1
    fi
else
    echo "[INFO] .env file found."
fi

# ---------------------------------------------------------------------------
# 3. Create the reports directory if it does not exist.
# ---------------------------------------------------------------------------
mkdir -p reports
echo "[INFO] reports/ directory ready."

# ---------------------------------------------------------------------------
# 4. Pull latest images (skip services that are built locally).
# ---------------------------------------------------------------------------
echo "[INFO] Pulling latest container images..."
docker compose pull --ignore-buildable

# ---------------------------------------------------------------------------
# 5. Start the DVWA backend, its MariaDB database, the ModSecurity WAF and
#    the cf_clearance simulator in the background.
# ---------------------------------------------------------------------------
echo "[INFO] Starting dvwa-origin, db, dvwa-waf and cf-sim services..."
docker compose up -d dvwa-origin db dvwa-waf cf-sim

# ---------------------------------------------------------------------------
# 6. Health-check loop: wait until DVWA responds on port 8080.
# ---------------------------------------------------------------------------
echo "[INFO] Waiting for DVWA to become ready (timeout: ${HEALTH_TIMEOUT}s)..."
elapsed=0
until curl --silent --max-time 3 --output /dev/null --write-out "%{http_code}" \
        "${DVWA_URL}" | grep -qE "^(200|302)$"; do
    if [ "${elapsed}" -ge "${HEALTH_TIMEOUT}" ]; then
        echo "[ERROR] DVWA did not respond within ${HEALTH_TIMEOUT} seconds. Aborting." >&2
        echo "[ERROR] Check logs with: docker compose logs dvwa-origin" >&2
        exit 1
    fi
    sleep "${HEALTH_INTERVAL}"
    elapsed=$((elapsed + HEALTH_INTERVAL))
    echo "[INFO] Still waiting... (${elapsed}s elapsed)"
done
echo "[INFO] DVWA is up and responding."

# ---------------------------------------------------------------------------
# 7. Initialise DVWA database via its setup endpoint.
# ---------------------------------------------------------------------------
echo "[INFO] Running DVWA database setup..."
setup_response=$(curl --silent --max-time 15 \
    --request POST \
    --data "create_db=Create+%2F+Reset+Database" \
    "${DVWA_URL}/setup.php" \
    --write-out "%{http_code}" \
    --output /dev/null) || true

if [ "${setup_response}" = "200" ] || [ "${setup_response}" = "302" ]; then
    echo "[INFO] DVWA database initialised successfully."
else
    echo "[WARN] DVWA setup returned HTTP ${setup_response}. The DB may already be set up."
fi

# ---------------------------------------------------------------------------
# 7b. Wait until /index.php no longer redirects to setup.php
# ---------------------------------------------------------------------------
echo "[INFO] Verifying DVWA database initialisation (timeout: ${HEALTH_TIMEOUT}s)..."
elapsed=0
until ! curl --silent --max-time 5 --location \
        --write-out "%{url_effective}" --output /dev/null \
        "${DVWA_URL}/index.php" | grep -q "setup\.php"; do
    if [ "${elapsed}" -ge "${HEALTH_TIMEOUT}" ]; then
        echo "[ERROR] DVWA DB did not finish initialising within ${HEALTH_TIMEOUT}s. Aborting." >&2
        exit 1
    fi
    sleep "${HEALTH_INTERVAL}"
    elapsed=$((elapsed + HEALTH_INTERVAL))
    echo "[INFO] Still waiting for DB... (${elapsed}s elapsed)"
done
echo "[INFO] DVWA database verified — ready to scan."

# ---------------------------------------------------------------------------
# 7c. Wait until dvwa-waf responds on port 8088 (proxies to dvwa-origin).
# ---------------------------------------------------------------------------
echo "[INFO] Waiting for dvwa-waf to become ready (timeout: ${HEALTH_TIMEOUT}s)..."
elapsed=0
until curl --silent --max-time 3 --output /dev/null --write-out "%{http_code}" \
        "${WAF_URL}" | grep -qE "^(200|302|403)$"; do
    if [ "${elapsed}" -ge "${HEALTH_TIMEOUT}" ]; then
        echo "[ERROR] dvwa-waf did not respond within ${HEALTH_TIMEOUT}s. Aborting." >&2
        echo "[ERROR] Check logs with: docker compose logs dvwa-waf" >&2
        exit 1
    fi
    sleep "${HEALTH_INTERVAL}"
    elapsed=$((elapsed + HEALTH_INTERVAL))
    echo "[INFO] Still waiting for dvwa-waf... (${elapsed}s elapsed)"
done
echo "[INFO] dvwa-waf is up. Internal alias 'dvwa' now resolves to the WAF."

# ---------------------------------------------------------------------------
# 7d. Wait until cf-sim responds on port 8089 (proxies to dvwa-origin).
# ---------------------------------------------------------------------------
echo "[INFO] Waiting for cf-sim to become ready (timeout: ${HEALTH_TIMEOUT}s)..."
elapsed=0
until curl --silent --max-time 3 --output /dev/null --write-out "%{http_code}" \
        "${CFSIM_URL}" | grep -qE "^(200|302|403)$"; do
    if [ "${elapsed}" -ge "${HEALTH_TIMEOUT}" ]; then
        echo "[ERROR] cf-sim did not respond within ${HEALTH_TIMEOUT}s. Aborting." >&2
        echo "[ERROR] Check logs with: docker compose logs cf-sim" >&2
        exit 1
    fi
    sleep "${HEALTH_INTERVAL}"
    elapsed=$((elapsed + HEALTH_INTERVAL))
    echo "[INFO] Still waiting for cf-sim... (${elapsed}s elapsed)"
done
echo "[INFO] cf-sim is up. Internal alias 'dvwa-cf' resolves to the simulator."

# ---------------------------------------------------------------------------
# 8. Print usage instructions.
# ---------------------------------------------------------------------------
cat <<'EOF'

[INFO] Environment is ready.

The internal hostname `dvwa` now resolves to the ModSecurity WAF in front
of the actual DVWA backend (which is reachable as `dvwa-origin`).

To run a scan against DVWA THROUGH the WAF (default scenario):

    docker compose run --rm dast-app --url http://dvwa \
        --concurrent-vectors 5 --concurrent-payloads 10 --requests-per-second 0 \
        --depth 3 --max-pages 100 --max-payloads-per-vector 50 \
        --payload-types sqli,xss,cmdi,ssrf,xxe,deserialization,path_traversal,open_redirect \
        --request-timeout 30

To run a scan against DVWA BYPASSING the WAF (baseline, v3-style):

    docker compose run --rm dast-app --url http://dvwa-origin \
        --concurrent-vectors 5 --concurrent-payloads 10 --requests-per-second 0 \
        --depth 3 --max-pages 100 --max-payloads-per-vector 50 \
        --payload-types sqli,xss,cmdi,ssrf,xxe,deserialization,path_traversal,open_redirect \
        --request-timeout 30

To exercise the obfuscation layer against the WAF:

    docker compose run --rm dast-app --url http://dvwa \
        --obfuscation none,double_url,base64 \
        --concurrent-vectors 5 --concurrent-payloads 10 ...

To exercise the cf_clearance bridge against the simulator:

    docker compose run --rm dast-app --url http://dvwa-cf \
        --cf-clearance-mode refresh \
        --concurrent-vectors 5 --concurrent-payloads 10 \
        --depth 3 --max-pages 100 --max-payloads-per-vector 50 \
        --payload-types sqli,xss \
        --request-timeout 30

Reports are saved to ./reports/outputs/<scan_name>/ on the host.
Inspect WAF blocks: docker compose logs dvwa-waf | grep ModSecurity

To stop the environment when finished, run:

    ./stop.sh

EOF
