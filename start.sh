#!/usr/bin/env bash
# start.sh — Initialise the DAST testing environment.
# Starts DVWA + MariaDB, waits for health, and runs DVWA DB setup.
set -euo pipefail

DVWA_URL="http://localhost:8080"
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
# 5. Start DVWA and its MariaDB database in the background.
# ---------------------------------------------------------------------------
echo "[INFO] Starting dvwa and db services..."
docker compose up -d dvwa db

# ---------------------------------------------------------------------------
# 6. Health-check loop: wait until DVWA responds on port 8080.
# ---------------------------------------------------------------------------
echo "[INFO] Waiting for DVWA to become ready (timeout: ${HEALTH_TIMEOUT}s)..."
elapsed=0
until curl --silent --max-time 3 --output /dev/null --write-out "%{http_code}" \
        "${DVWA_URL}" | grep -qE "^(200|302)$"; do
    if [ "${elapsed}" -ge "${HEALTH_TIMEOUT}" ]; then
        echo "[ERROR] DVWA did not respond within ${HEALTH_TIMEOUT} seconds. Aborting." >&2
        echo "[ERROR] Check logs with: docker compose logs dvwa" >&2
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
# 8. Print usage instructions.
# ---------------------------------------------------------------------------
cat <<'EOF'

[INFO] Environment is ready.

To run a scan against DVWA:

    docker compose run --rm dast-app --url http://dvwa --profile default

To run with verbose logging:

    docker compose run --rm dast-app --url http://dvwa --profile default --log-level DEBUG

To target a different application (update TARGET_URL in .env first):

    docker compose run --rm dast-app --url http://your-app --profile aggressive

Scan reports are saved to ./reports/<scan_id>/ on the host.

To stop the environment when finished, run:

    ./stop.sh

EOF
