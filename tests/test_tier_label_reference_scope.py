"""Meta-test: _tier_label is only defined once and referenced only inside _print_human.

Prevents accidental use of the fallback tier mapper in scan branches,
CI guards, or any other code path.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _extract_def_block(src: str, func_name: str) -> tuple[int, int, str]:
    """
    Extract a top-level ``def func_name(...):`` block using indentation.
    Returns (start_idx, end_idx, block_text).
    Assumes ``def`` is at column 0 (true for __main__.py helpers).
    """
    m = re.search(
        rf"^def {re.escape(func_name)}\s*\(.*\).*:\s*$",
        src,
        flags=re.MULTILINE,
    )
    if not m:
        raise AssertionError(f"Did not find top-level function def for {func_name!r}")

    start = m.start()

    # Find next top-level def/class after this function to bound the block.
    next_m = re.search(
        r"^(?:def|class)\s+\w+\s*\(?.*\)?:\s*$",
        src[m.end():],
        flags=re.MULTILINE,
    )
    end = m.end() + next_m.start() if next_m else len(src)

    return start, end, src[start:end]


def test_tier_label_only_referenced_inside_print_human() -> None:
    main_path = REPO_ROOT / "src" / "code_audit" / "__main__.py"
    assert main_path.exists(), f"Missing file: {main_path}"
    src = main_path.read_text(encoding="utf-8")

    # All occurrences in the whole file
    all_hits = [m.start() for m in re.finditer(r"\b_tier_label\b", src)]
    assert all_hits, "Expected at least one reference to _tier_label in __main__.py"

    # Extract the _tier_label definition block (allowed: the def itself)
    def_start, def_end, _ = _extract_def_block(src, "_tier_label")

    # Extract _print_human block (allowed: the only call-site)
    ph_start, ph_end, _ = _extract_def_block(src, "_print_human")

    # Every occurrence must be inside one of the two allowed ranges
    outside = [
        pos for pos in all_hits
        if not (def_start <= pos < def_end or ph_start <= pos < ph_end)
    ]

    assert not outside, (
        "Found _tier_label referenced outside its definition and _print_human().\n"
        f"Offending positions: {outside}\n"
        "Lines: "
        + ", ".join(str(src[:pos].count("\n") + 1) for pos in outside)
        + "\nMove all _tier_label usage into _print_human() only."
    )
