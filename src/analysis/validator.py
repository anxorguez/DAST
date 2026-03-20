"""Validates and deduplicates raw findings using a 2-of-3 confirmation rule."""

from __future__ import annotations

from collections import defaultdict

from loguru import logger

from src.analysis.models import Confidence, RawFinding, ValidatedFinding


class Validator:
    """Deduplicates RawFinding instances and applies the confirmation threshold.

    A finding is confirmed when the same (target_url, field_name, vuln_type,
    payload) combination appears in at least CONFIRM_THRESHOLD raw findings.
    This corresponds to 2 out of 3 retry attempts succeeding in the scanner.
    """

    CONFIRM_THRESHOLD: int = 2

    def validate(self, raw_findings: list[RawFinding]) -> list[ValidatedFinding]:
        """Return a deduplicated list of ValidatedFinding instances.

        Groups raw findings by their deduplication key and keeps only groups
        that meet the confirmation threshold. Within each group the finding
        with the strongest evidence (highest confidence) is selected.
        """
        # Group by (url, field, vuln_type, payload)
        groups: dict[tuple[str, str, str, str], list[RawFinding]] = defaultdict(list)
        for rf in raw_findings:
            key = (
                rf.vector.target_url,
                rf.vector.field_name,
                rf.vuln_type.value,
                rf.payload,
            )
            groups[key].append(rf)

        validated: list[ValidatedFinding] = []
        for key, group in groups.items():
            if len(group) < self.CONFIRM_THRESHOLD:
                logger.debug(
                    "Discarded finding {k}: only {n}/{t} confirmations",
                    k=key,
                    n=len(group),
                    t=self.CONFIRM_THRESHOLD,
                )
                continue

            best = self._select_best(group)
            validated.append(ValidatedFinding(raw=best))

        logger.info(
            "Validation: {raw} raw -> {val} confirmed finding(s)",
            raw=len(raw_findings),
            val=len(validated),
        )
        return validated

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    _CONFIDENCE_RANK: dict[Confidence, int] = {
        Confidence.POSSIBLE: 0,
        Confidence.LIKELY: 1,
        Confidence.CONFIRMED: 2,
    }

    def _select_best(self, group: list[RawFinding]) -> RawFinding:
        """Return the finding with the highest confidence in the group."""
        return max(group, key=lambda f: self._CONFIDENCE_RANK.get(f.confidence, 0))
