#!/usr/bin/env bash
# entrypoint.sh — Docker container entrypoint for the dast-app service.
# Applies a minimal iptables firewall, validates configuration, then
# launches the Python application.
set -uo pipefail

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
log_info()  { echo "[INFO]  $(date '+%Y-%m-%d %H:%M:%S') | entrypoint | $*"; }
log_warn()  { echo "[WARN]  $(date '+%Y-%m-%d %H:%M:%S') | entrypoint | $*"; }
log_error() { echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') | entrypoint | $*" >&2; }

# ---------------------------------------------------------------------------
# 1-5. Minimal iptables firewall — principle of least privilege.
# ---------------------------------------------------------------------------
apply_firewall() {
    log_info "Applying iptables firewall rules..."

    # Default policies
    iptables -P INPUT DROP   2>/dev/null || true
    iptables -P FORWARD DROP 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true   # start permissive, tighten below

    # Allow loopback
    iptables -A INPUT  -i lo -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true

    # Allow established / related inbound traffic
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

    # Allow DNS only to Docker's internal resolver (127.0.0.11)
    iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.11 -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p tcp --dport 53 -d 127.0.0.11 -j ACCEPT 2>/dev/null || true

    # Allow traffic to the Docker internal network (covers inter-service communication)
    iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT 2>/dev/null || true

    # Resolve TARGET_URL hostname and allow explicit outbound traffic to it.
    if [ -n "${TARGET_URL:-}" ]; then
        target_host=$(echo "$TARGET_URL" | sed -E 's|^https?://||' | cut -d'/' -f1 | cut -d':' -f1)
        if [ -n "$target_host" ]; then
            target_ip=$(getent hosts "$target_host" 2>/dev/null | awk '{print $1; exit}' || true)
            if [ -n "$target_ip" ]; then
                iptables -A OUTPUT -d "$target_ip" -j ACCEPT 2>/dev/null || true
                log_info "Firewall: allowed outbound to target ${target_host} (${target_ip})"
            else
                log_warn "Firewall: could not resolve ${target_host}; skipping explicit allow rule."
            fi
        fi
    fi

    # Drop all other outbound traffic not explicitly allowed above.
    # NOTE: The final DROP rule is intentionally placed after the ACCEPT rules above.
    iptables -A OUTPUT -j DROP 2>/dev/null || true

    log_info "Firewall rules applied."
}

# Apply firewall only when running as root and iptables is available.
if [ "$(id -u)" = "0" ] && command -v iptables &>/dev/null; then
    apply_firewall
else
    log_warn "Skipping iptables setup (not root or iptables not available)."
fi

# ---------------------------------------------------------------------------
# 6. Validate TARGET_URL
# ---------------------------------------------------------------------------
if [ -z "${TARGET_URL:-}" ]; then
    log_error "TARGET_URL environment variable is not set. Aborting."
    exit 1
fi
log_info "Target URL: ${TARGET_URL}"

# ---------------------------------------------------------------------------
# 7. Check that TARGET_URL is reachable (non-fatal warning).
# ---------------------------------------------------------------------------
if curl --silent --max-time 5 --output /dev/null "${TARGET_URL}"; then
    log_info "Target is reachable."
else
    log_warn "Target did not respond within 5 seconds. Proceeding anyway."
fi

# ---------------------------------------------------------------------------
# 7b. Auto-initialise DVWA if the target redirects to /setup.php.
#     This happens when running `docker compose run dast-app` directly
#     without going through start.sh, which normally initialises the DB.
# ---------------------------------------------------------------------------
_effective_url=$(curl --silent --max-time 10 --location \
    --write-out "%{url_effective}" --output /dev/null \
    "${TARGET_URL}/index.php" 2>/dev/null || true)

if echo "${_effective_url}" | grep -q "setup\.php"; then
    log_info "DVWA database not initialised — running setup automatically..."
    curl --silent --max-time 15 \
        --request POST \
        --data "create_db=Create+%2F+Reset+Database" \
        "${TARGET_URL}/setup.php" \
        --output /dev/null || true

    SETUP_TIMEOUT=60
    SETUP_INTERVAL=3
    _elapsed=0
    until ! curl --silent --max-time 5 --location \
            --write-out "%{url_effective}" --output /dev/null \
            "${TARGET_URL}/index.php" 2>/dev/null \
          | grep -q "setup\.php"; do
        if [ "${_elapsed}" -ge "${SETUP_TIMEOUT}" ]; then
            log_error "DVWA DB did not finish initialising within ${SETUP_TIMEOUT}s. Aborting."
            exit 1
        fi
        sleep "${SETUP_INTERVAL}"
        _elapsed=$((_elapsed + SETUP_INTERVAL))
        log_info "Waiting for DVWA DB... (${_elapsed}s elapsed)"
    done
    log_info "DVWA database initialised successfully."
fi

# ---------------------------------------------------------------------------
# 8. Create per-scan output directory.
# ---------------------------------------------------------------------------
SCAN_ID="$(date +%Y%m%d_%H%M%S)_$(head -c 4 /dev/urandom | xxd -p)"
SCAN_DIR="${OUTPUT_DIR:-/app/reports}/${SCAN_ID}"
mkdir -p "${SCAN_DIR}"
export SCAN_ID
export SCAN_DIR
log_info "Scan output directory: ${SCAN_DIR}"

# ---------------------------------------------------------------------------
# 9. Execute the Python application, forwarding all arguments.
# ---------------------------------------------------------------------------
log_info "Launching DAST scanner..."
python -m src.main "$@"
EXIT_CODE=$?

# ---------------------------------------------------------------------------
# 10. Report exit code.
# ---------------------------------------------------------------------------
if [ "${EXIT_CODE}" -ne 0 ]; then
    log_error "DAST scanner exited with code ${EXIT_CODE}."
fi

exit "${EXIT_CODE}"
