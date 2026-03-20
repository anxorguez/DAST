"""Loads payload lists from the payloads/ directory."""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from src.core.exceptions import PayloadLoadError
from src.vectors.models import VulnType

_PAYLOAD_BASE = Path(__file__).parent.parent.parent / "payloads"

_VULN_DIR: dict[VulnType, str] = {
    VulnType.SQLI: "sqli",
    VulnType.XSS: "xss",
    VulnType.CMDI: "cmdi",
}


class PayloadLoader:
    """Reads payload text files and returns deduplicated payload lists."""

    def load(self, vuln_type: VulnType, max_count: int = 50) -> list[str]:
        """Load payloads for *vuln_type* from all files in its directory.

        Files are read in sorted order. Lines starting with '#' and blank
        lines are ignored. Duplicates are removed while preserving order.

        Args:
            vuln_type: The vulnerability type whose payloads to load.
            max_count: Hard cap on the number of payloads returned.

        Returns:
            List of payload strings, up to *max_count* entries.
        """
        dir_path = _PAYLOAD_BASE / _VULN_DIR[vuln_type]

        if not dir_path.is_dir():
            raise PayloadLoadError(
                f"Payload directory not found: {dir_path}"
            )

        payloads: list[str] = []
        seen: set[str] = set()

        for filepath in sorted(dir_path.glob("*.txt")):
            try:
                with filepath.open(encoding="utf-8") as fh:
                    for line in fh:
                        stripped = line.rstrip("\n")
                        if not stripped or stripped.startswith("#"):
                            continue
                        if stripped not in seen:
                            seen.add(stripped)
                            payloads.append(stripped)
                            if len(payloads) >= max_count:
                                return payloads
            except OSError as exc:
                logger.warning(
                    "Could not read payload file {f}: {err}", f=filepath, err=exc
                )

        logger.debug(
            "Loaded {n} payloads for {vt}", n=len(payloads), vt=vuln_type.value
        )
        return payloads

    def load_subtype(
        self, vuln_type: VulnType, subtype: str, max_count: int = 50
    ) -> list[str]:
        """Load payloads from a specific subtype file (e.g. 'time_based' for sqli).

        Args:
            vuln_type: The vulnerability type directory.
            subtype: The filename without extension (e.g. 'error_based').
            max_count: Hard cap on the number of payloads returned.

        Returns:
            List of payload strings, or an empty list if the file is not found.
        """
        filepath = _PAYLOAD_BASE / _VULN_DIR[vuln_type] / f"{subtype}.txt"
        if not filepath.exists():
            logger.debug("Payload file not found: {f}", f=filepath)
            return []

        payloads: list[str] = []
        seen: set[str] = set()
        try:
            with filepath.open(encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.rstrip("\n")
                    if not stripped or stripped.startswith("#"):
                        continue
                    if stripped not in seen:
                        seen.add(stripped)
                        payloads.append(stripped)
                        if len(payloads) >= max_count:
                            break
        except OSError as exc:
            logger.warning(
                "Could not read payload file {f}: {err}", f=filepath, err=exc
            )

        return payloads
