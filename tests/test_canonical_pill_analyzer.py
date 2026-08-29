"""Unit tests for the unsourced-imperative canonicalization ("poison pill") detector.

Surfaces canonical prohibitions written with no authority behind them — a
descriptive observation frozen into permanent law. Leads, not verdicts: every
finding is a CANDIDATE with ``context_confirmed=False``.

Includes the born-from-the-bug acceptance test in **both arms**, reconstructed from
the real ``IBG_ROLE_DEFINITION.md`` that motivated the detector:

  - FIRES: the unsourced ``NEVER`` rows, the ``No feedback loop exists`` declarative,
    and the footer restatement.
  - SILENT: ``IBG math is LOCKED`` (its section cites Sevy & Mottola and ±0.01in),
    the tolerance row, and ``see <ref>``-backed prohibitions.

The silent arm is the one that matters most: a detector that flags the
Sevy-Mottola lock is miscalibrated, and one that misses the ``NEVER`` pill is
useless. Both arms hold or the detector is not doing its job.
"""
from __future__ import annotations

from pathlib import Path

from code_audit.analyzers.canonical_pill import CanonicalPillAnalyzer
from code_audit.model import AnalyzerType, Severity

# The real doc that motivated the detector, reconstructed verbatim in shape.
IBG_DOC = """# Image Body Generator (IBG) — Role Definition

**Status:** ACTIVE GOVERNANCE
**Effective:** 2026-05-11

---

## Canonical Role

IBG is a **parametric geometry completor**, not an image processor.

---

## What IBG Does

| Function | Method | Status |
|----------|--------|--------|
| Complete partial DXF from vectorizer | `complete_from_dxf()` | PRODUCTION |
| Export solved model to DXF | `save_dxf()` | PRODUCTION |

---

## What IBG Does NOT Do

| Capability | Status | Reason |
|------------|--------|--------|
| Image processing | NEVER | Works on DXF geometry only |
| Strategy caching (Loop 2) | NEVER | Not a learning system |
| ML classification | NEVER | Uses deterministic lutherie math |
| Photo input | NEVER | Requires vectorizer preprocessing |

---

## Math Authority

IBG math is LOCKED. Source references:

- **Jon Sevy** — "Calculating Arc Parameters," American Lutherie #58
- **R. Mottola** — "Calculating Side Contours," American Lutherie #78

Verification: ±0.01 inch tolerance against published spreadsheet values.

---

## Position in Pipeline

IBG is a **one-way consumer** of vectorizer output. No feedback loop exists upstream.

---

*IBG role definition. No learning systems. No image processing.*
"""


def _run(root: Path):
    return CanonicalPillAnalyzer().run(root, [])


def _doc(root: Path, rel: str, body: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _snippets(findings) -> list[str]:
    return [f.snippet for f in findings]


def _fired_on(findings, needle: str) -> bool:
    return any(needle in s for s in _snippets(findings))


# ── acceptance: the born-from-the-bug doc, FIRES arm ────────────────────
def test_acceptance_ibg_named_pills_fire(tmp_path):
    _doc(tmp_path, "docs/governance/IBG_ROLE_DEFINITION.md", IBG_DOC)
    f = _run(tmp_path)
    assert _fired_on(f, "| Strategy caching (Loop 2) | NEVER |")
    assert _fired_on(f, "| ML classification | NEVER |")
    assert _fired_on(f, "No feedback loop exists upstream.")
    assert _fired_on(f, "No learning systems.")


def test_acceptance_all_four_unsourced_never_rows_fire(tmp_path):
    """Structurally-identical rows all fire; the human rules which are defensible.

    `Image processing | NEVER` is indistinguishable from `Strategy caching | NEVER`
    by any mechanical test — same table, same unsourced imperative, same prose
    reason. Suppressing either would mean the detector making the semantic ruling
    it exists not to make.
    """
    _doc(tmp_path, "docs/governance/IBG_ROLE_DEFINITION.md", IBG_DOC)
    never = [f for f in _run(tmp_path) if f.metadata["token"] == "NEVER"]
    assert len(never) == 4
    assert all(f.metadata["tell"] == "unsourced imperative" for f in never)


# ── acceptance: the KEEP rows, SILENT arm ───────────────────────────────
def test_acceptance_sourced_math_lock_stays_silent(tmp_path):
    """The calibration that matters most — a cited authority is not a pill."""
    _doc(tmp_path, "docs/governance/IBG_ROLE_DEFINITION.md", IBG_DOC)
    f = _run(tmp_path)
    assert not _fired_on(f, "IBG math is LOCKED")
    assert not _fired_on(f, "±0.01 inch tolerance")


def test_reason_is_not_a_citation(tmp_path):
    """A prose rationale is the author explaining themselves, not an authority."""
    _doc(tmp_path, "g.md",
         "**Status:** CANONICAL\n\n## Rules\n\n"
         "| Caching | NEVER | Not a learning system |\n")
    assert len(_run(tmp_path)) == 1


def test_citation_forms_silence_the_prohibition(tmp_path):
    for i, cited in enumerate((
        "Locking per https://example.org/spec — MUST NOT be changed.",
        "MUST NOT exceed the bound (see § 4.2).",
        "Tolerance is LOCKED at ±0.01 inch against published values.",
        "Pinned to v2.14.1; downgrades are FORBIDDEN.",
        "Per ISO 9001 the interface is LOCKED.",
        "Smith et al. show this; the constant is LOCKED.",
        "| Blueprint Reader MVP | `86c49526` | LOCKED |",
    )):
        root = tmp_path / f"c{i}"
        _doc(root, "g.md", f"**Status:** CANONICAL\n\n## Rules\n\n{cited}\n")
        assert _run(root) == [], cited


def test_pinned_commit_sha_is_a_citation(tmp_path):
    """A pinned commit is the strongest version pin there is — a checkable source.

    Found by dogfooding the real BLUEPRINT_READER_PROTECTION_RULES.md, whose
    Protected Systems table cites commits rather than prose refs.
    """
    _doc(tmp_path, "g.md",
         "**Status:** ACTIVE GOVERNANCE\n\n## Protected Systems\n\n"
         "| System | Commit | Status |\n"
         "| Blueprint Reader MVP | `86c49526` | LOCKED |\n")
    assert _run(tmp_path) == []


def test_plain_number_and_hex_word_are_not_citations(tmp_path):
    """`deadbeef` and `12345678` must not pass as commit pins."""
    for i, body in enumerate(("The value deadbeef is LOCKED.",
                              "Row 12345678 is LOCKED.")):
        root = tmp_path / f"n{i}"
        _doc(root, "g.md", f"**Status:** CANONICAL\n\n## Rules\n\n{body}\n")
        assert len(_run(root)) == 1, body


# ── section-scoped adjacency ────────────────────────────────────────────
def test_citation_covers_whole_section_not_just_its_line(tmp_path):
    """Sevy/Mottola sit on bullets *under* the heading, not on the LOCKED line."""
    _doc(tmp_path, "g.md",
         "**Status:** CANONICAL\n\n## Math Authority\n\n"
         "The math is LOCKED. Source references:\n\n"
         "- **Jon Sevy** — \"Calculating Arc Parameters,\" American Lutherie #58\n")
    assert _run(tmp_path) == []


def test_citation_in_a_different_section_does_not_silence(tmp_path):
    """Doc-level scope would silence the pills; adjacency stops at the heading."""
    _doc(tmp_path, "g.md",
         "**Status:** CANONICAL\n\n"
         "## Math Authority\n\nLOCKED per https://example.org/paper\n\n"
         "## Constraints\n\n| Strategy caching | NEVER | Not a learning system |\n")
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["section"] == "Constraints"


def test_subsection_does_not_inherit_parent_citation(tmp_path):
    _doc(tmp_path, "g.md",
         "**Status:** CANONICAL\n\n## Authority\n\nSee https://example.org/spec\n\n"
         "### Constraints\n\nCaching is PROHIBITED.\n")
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["section"] == "Constraints"


# ── register: case sensitivity and the canonical gate ───────────────────
def test_lowercase_prose_never_is_silent(tmp_path):
    """Canonical prohibitions get shouted; casual prose doesn't."""
    _doc(tmp_path, "g.md",
         "**Status:** CANONICAL\n\n## Rules\n\nWe never got around to caching.\n")
    assert _run(tmp_path) == []


def test_prohibition_outside_canonical_register_is_silent(tmp_path):
    """An ordinary README MUST NOT is not a canonical prohibition."""
    _doc(tmp_path, "README.md",
         "# Setup\n\n## Installing\n\nYou MUST NOT run this as root.\n")
    assert _run(tmp_path) == []


def test_prescriptive_heading_alone_is_enough_register(tmp_path):
    _doc(tmp_path, "README.md",
         "# Setup\n\n## Constraints\n\nCaching is PROHIBITED.\n")
    assert len(_run(tmp_path)) == 1


def test_may_not_is_a_prohibition_not_a_permission(tmp_path):
    _doc(tmp_path, "g.md",
         "**Status:** CANONICAL\n\n## Rules\n\nAgents may NOT bypass BOE authority.\n")
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["token"] == "may NOT"


# ── tells and the strength ladder ───────────────────────────────────────
def test_present_indicative_in_prescriptive_section_fires(tmp_path):
    _doc(tmp_path, "g.md",
         "# D\n\n## Position in Pipeline\n\nNo feedback loop exists upstream.\n")
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["tell"] == "present-indicative-as-law"


def test_prohibition_co_located_with_declarative_raises_to_high(tmp_path):
    _doc(tmp_path, "g.md",
         "**Status:** CANONICAL\n\n## Rules\n\n"
         "Caching is NEVER used and no cache exists in the pipeline.\n")
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].metadata["candidate_strength"] == "HIGH"
    assert f[0].confidence == 0.7


def test_plain_prohibition_is_medium(tmp_path):
    _doc(tmp_path, "g.md",
         "**Status:** CANONICAL\n\n## Rules\n\n| Caching | NEVER | reasons |\n")
    f = _run(tmp_path)
    assert f[0].metadata["candidate_strength"] == "MEDIUM"
    assert f[0].confidence == 0.5


def test_closing_restatement_needs_governance_register(tmp_path):
    _doc(tmp_path, "notes.md", "# Notes\n\n*No learning systems. No caching.*\n")
    assert _run(tmp_path) == []


# ── tertiary tell: metadata only, never a severity judgment ─────────────
def test_contradiction_recorded_as_metadata_only(tmp_path):
    """The line-45 proof is evidence for the human, not a confidence change."""
    _doc(tmp_path, "docs/a.md",
         "**Status:** CANONICAL\n\n## Rules\n\n| Strategy caching | NEVER | none |\n")
    _doc(tmp_path, "docs/b.md",
         "# Map\n\n| IBG Morphology Layer | Shape intelligence | EVOLUTIONARY |\n")
    f = [x for x in _run(tmp_path) if x.location.path == "docs/a.md"]
    assert len(f) == 1
    assert any(ref.startswith("docs/b.md:") for ref in f[0].metadata["contradiction_refs"])
    # Metadata only: the ladder is untouched by the contradiction.
    assert f[0].metadata["candidate_strength"] == "MEDIUM"
    assert f[0].confidence == 0.5
    assert f[0].severity is Severity.LOW


def test_contradiction_refs_empty_without_a_companion(tmp_path):
    _doc(tmp_path, "docs/a.md",
         "**Status:** CANONICAL\n\n## Rules\n\n| Caching | NEVER | none |\n")
    f = _run(tmp_path)
    assert f[0].metadata["contradiction_refs"] == []


# ── leads-not-verdicts contract ─────────────────────────────────────────
def test_every_finding_is_an_unconfirmed_candidate(tmp_path):
    _doc(tmp_path, "docs/governance/IBG_ROLE_DEFINITION.md", IBG_DOC)
    f = _run(tmp_path)
    assert f
    for finding in f:
        assert finding.type is AnalyzerType.CANONICAL_PILL
        assert finding.severity is Severity.LOW      # advisory: never fails a build
        assert finding.metadata["candidate"] is True
        assert finding.metadata["context_confirmed"] is False
        assert finding.metadata["rule_id"] == "CANON_PILL_001"
        assert "confirm whether this is a real rule" in finding.message
        assert "poison pill" not in finding.message.lower()


# ── scanning mechanics ──────────────────────────────────────────────────
def test_fenced_code_is_ignored(tmp_path):
    _doc(tmp_path, "g.md",
         "**Status:** CANONICAL\n\n## Rules\n\n```\nvalue = NEVER\n```\n")
    assert _run(tmp_path) == []


def test_no_markdown_no_findings(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert _run(tmp_path) == []


def test_excluded_directories_are_not_scanned(tmp_path):
    _doc(tmp_path, "node_modules/pkg/g.md",
         "**Status:** CANONICAL\n\n## Rules\n\nCaching is PROHIBITED.\n")
    assert _run(tmp_path) == []


def test_findings_are_deterministic_and_ordered(tmp_path):
    _doc(tmp_path, "docs/governance/IBG_ROLE_DEFINITION.md", IBG_DOC)
    first = _run(tmp_path)
    second = _run(tmp_path)
    assert [f.fingerprint for f in first] == [f.fingerprint for f in second]
    keys = [(f.location.path, f.location.line_start) for f in first]
    assert keys == sorted(keys)
