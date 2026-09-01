"""Custom Click parameter types shared by main.py."""

from __future__ import annotations

import click


class UnlimitedInt(click.ParamType[int | None]):
    """Integer accepting "unlimited"/"none"/"inf"/-1 as a sentinel for no cap.

    Returns:
        * int (>= 1) for explicit caps.
        * None when the user requested unlimited.

    Rejects 0 and negative values other than -1: those are almost always
    user error, and accepting them silently would let a typo turn into a
    no-op scan.
    """

    name = "unlimited_int"
    _SENTINELS = frozenset({"unlimited", "none", "inf", "-1"})

    def convert(
        self,
        value: object,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> int | None:
        if value is None:
            return None
        s = str(value).strip().lower()
        if s in self._SENTINELS:
            return None
        try:
            n = int(s)
        except ValueError:
            self.fail(f"{value!r} is not a valid integer or 'unlimited'.", param, ctx)
        if n < 1:
            self.fail(
                f"{value!r} must be >= 1 or one of 'unlimited'/'none'/'inf'/-1.",
                param,
                ctx,
            )
        return n


UNLIMITED_INT = UnlimitedInt()
