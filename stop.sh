#!/usr/bin/env bash
# stop.sh — Stop the DAST testing environment.
set -euo pipefail

# ---------------------------------------------------------------------------
# 1. Stop running containers (keeps them and their data intact).
# ---------------------------------------------------------------------------
echo "[INFO] Stopping running containers..."
docker compose stop
echo "[INFO] Containers stopped."

# ---------------------------------------------------------------------------
# 2. Optionally remove containers and the virtual network.
# ---------------------------------------------------------------------------
read -r -p "Remove containers and virtual network? [s/N] " answer_down
if [ "${answer_down,,}" = "s" ]; then
    echo "[INFO] Removing containers and network..."
    docker compose down
    echo "[INFO] Containers and network removed."
fi

# ---------------------------------------------------------------------------
# 3. Optionally remove persistent data volumes (DVWA database).
# ---------------------------------------------------------------------------
read -r -p "Remove data volumes (DVWA database)? [s/N] " answer_volumes
if [ "${answer_volumes,,}" = "s" ]; then
    echo "[INFO] Removing volumes..."
    docker compose down -v
    echo "[INFO] Volumes removed."
fi

# ---------------------------------------------------------------------------
# 4. List generated scan reports, if any.
# ---------------------------------------------------------------------------
echo ""
if [ -d "reports" ]; then
    scan_dirs=()
    while IFS= read -r -d '' d; do
        scan_dirs+=("$d")
    done < <(find reports -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)

    if [ "${#scan_dirs[@]}" -eq 0 ]; then
        echo "[INFO] No scan reports found in ./reports/"
    else
        echo "[INFO] Scan reports in ./reports/:"
        printf "  %-40s  %-20s  %s\n" "SCAN ID" "DATE" "SIZE"
        printf "  %-40s  %-20s  %s\n" "-------" "----" "----"
        for d in "${scan_dirs[@]}"; do
            dir_name=$(basename "$d")
            dir_date=$(date -r "$d" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "unknown")
            dir_size=$(du -sh "$d" 2>/dev/null | cut -f1 || echo "unknown")
            printf "  %-40s  %-20s  %s\n" "$dir_name" "$dir_date" "$dir_size"
        done
    fi
else
    echo "[INFO] ./reports/ directory does not exist."
fi

echo ""
echo "[INFO] Done."
