"""Unsourced-imperative canonicalization detector — the "poison pill" guard.

Surfaces **unsourced imperative prohibitions** in canonical governance / spec prose:
a permanent-sounding rule (``NEVER``, ``MUST NOT``, ``LOCKED`` …) written with no
authority behind it. The failure mode is a *descriptive observation frozen into
permanent law*: someone writes down what the system happens not to do today, the
line hardens into a canonical prohibition, and a still-developmental capability is
locked out by an accident of register.

Born from the IBG governance audit: four descriptive observations
(``Strategy caching | NEVER``, ``ML classification | NEVER``, ``No feedback loop
exists``, and a footer restating them) became permanent prohibitions on an
evolutionary capability — while the *same author, same day* wrote the contradicting
line ``IBG Morphology Layer | Shape intelligence | EVOLUTIONARY``. Third instance of
the over-strict-canonicalization class (RMOS ``extra="forbid"``, the CBSP21
freeze-gate, now the IBG ``NEVER``s).

**This detector surfaces candidates. It does not rule.** Whether an unsourced rule
is legitimately self-evident or an observation frozen into law is a human judgment
the detector is not entitled to make. Every finding is a CANDIDATE carrying
``context_confirmed=False``.

The KEEP / OVERREACH split — the whole detector — is *citation, not rationale*:

  - ``IBG math is LOCKED`` in a section citing Sevy & Mottola and ±0.01in
    → **silent** (a source you could go check).
  - ``| Strategy caching | NEVER | Not a learning system |``
    → **candidate** ("Not a learning system" is the author explaining themselves,
    not pointing at an authority). A reason is not a citation. This is the crux:
    the pill exists *because* someone wrote a reason and mistook it for a source.

Tells, in confidence order:

  1. PRIMARY — *unsourced imperative*: an uppercase prohibition token on a line whose
     enclosing section carries no citation. Candidate, MEDIUM strength.
  2. SECONDARY — *present-indicative-as-law*: an absence/negation declarative
     ("No feedback loop exists", "…, not an image processor") inside a prescriptive
     section. A description sitting where a rule is read. Raised to HIGH strength
     when co-located on a line that also carries a prohibition token.
  3. TERTIARY — *intra-doc contradiction*: an opposing permission token
     (``EVOLUTIONARY`` / ``ALLOWED`` / ``MAY``) in the same doc or a same-directory
     companion. Attached as **metadata only** (``contradiction_refs``) — the
     contradiction is thematic, not mechanically subject-matched, so it is evidence
     handed to the human, never a severity judgment made by the detector.

Calibration decisions worth knowing before changing anything:

  - **Citation adjacency is section-scoped** — a citation anywhere between the
    enclosing heading and the next heading of equal-or-higher level covers every
    prohibition in that section. Line-level adjacency fails the calibration outright:
    the Sevy/Mottola refs sit on bullet lines *under* ``## Math Authority``, not on
    the ``LOCKED`` line itself. Doc-level scope would silence the pills too.
  - **Tokens match case-sensitively, uppercase only.** Canonical prohibitions get
    shouted; casual prose doesn't. This silences "we never got around to X" for
    free, with no section logic at all.
  - **PRIMARY requires canonical register** — a prescriptive heading or a doc-level
    governance status marker. Without that gate every README ``MUST NOT`` in
    ordinary technical prose becomes noise and the detector gets muted.
  - **Structurally-identical rows all fire.** ``Image processing | NEVER`` is
    indistinguishable from ``Strategy caching | NEVER`` by any mechanical test —
    the difference is purely semantic. Firing on both is correct: the human rules
    one defensible and one overreach in five seconds. Suppressing either would
    require the detector to make the semantic ruling it exists not to make.

Scan scope: ``**/*.md`` / ``.mdx`` via a pruned walk. Markdown-only in v1 — the
*code* form of over-strict canonicalization (``extra="forbid"`` schemas, frozen
invariants) is the same class but a separate detector, deliberately not built here.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
from typing import NamedTuple

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_RULE_ID = "CANON_PILL_001"

_MD_EXTS = frozenset({".md", ".mdx"})
# Dependency / build / cache output — never canonical authority.
_EXCLUDE_DIRS = frozenset({
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "site-packages", ".eggs", ".idea", ".vscode",
})

# ── register ────────────────────────────────────────────────────────────────
# Case-SENSITIVE: the shouted form is the canonical register. Lowercase "never"
# in ordinary prose ("we never got around to it") deliberately does not match.
_PROHIBITION = re.compile(
    r"(?<![A-Za-z])("
    r"MUST NOT|SHALL NOT|MAY NOT|may NOT|MUST NEVER"
    r"|NEVER|LOCKED|AUTHORITATIVE|PROHIBITED|FORBIDDEN"
    r")(?![A-Za-z])"
)

# Opposing tokens — the tertiary "inadvertent" signal.
_PERMISSION = re.compile(
    r"(?<![A-Za-z])(EVOLUTIONARY|ALLOWED|PERMITTED|OPTIONAL|MAY)(?![A-Za-z])"
)

# Headings under which a declarative statement is read as law (order-specified set).
_PRESCRIPTIVE_HEADING = re.compile(
    r"role|authority|governance|rules|position|non-?goals?|constraints", re.IGNORECASE
)

# Doc-level "this document is canonical" marker, looked for in the preamble only.
_GOVERNANCE_MARKER = re.compile(
    r"(?:^|\W)(?:Status|Type|Class)\W{0,4}\s*"
    r"(ACTIVE GOVERNANCE|CANONICAL|AUTHORITATIVE|GOVERNANCE|LOCKED|PROTECTED|FROZEN)"
    r"(?![A-Za-z])"
)
_PREAMBLE_LINES = 15

# ── citation ────────────────────────────────────────────────────────────────
# A citation is a source you could go check. A prose rationale is not one.
_CITATIONS = (
    re.compile(r"https?://|www\."),                              # URL
    re.compile(r"§"),                                       # section symbol
    re.compile(r"\bsee\s+(?:§|\[|`|https?://|[A-Z]|\w+/)", re.IGNORECASE),
    re.compile(r"[±]\s*\d|\+/-\s*\d"),                      # tolerance
    re.compile(r"\b(?:RFC|ISO|IEEE|ASTM|ANSI|DIN|IEC|NIST|EN)[\s-]?\d+"),
    re.compile(r"\bv?\d+\.\d+(?:\.\d+)?\b"),                     # version pin
    re.compile(r"\bet\s+al\.", re.IGNORECASE),                   # paper
    re.compile("\"[^\"]{6,}\"|“[^”]{6,}”"),       # quoted title
    re.compile(r"\b[A-Z]\.\s*[A-Z][a-z]+"),                      # R. Mottola
    re.compile(r"\b(?:pp?\.|Table|Figure|Section|Appendix|Chapter)\s*\d+",
               re.IGNORECASE),
    re.compile(r"\breferences?\s*:", re.IGNORECASE),
    re.compile(r"#\d{1,4}(?![\w-])"),                            # issue / journal no.
    # Pinned commit SHA — the strongest version pin there is. Requires both a
    # digit and a hex letter so plain numbers and words like "deadbeef" miss.
    re.compile(r"(?<![\w-])(?=[0-9a-f]{7,40}(?![\w-]))"
               r"(?=[0-9a-f]*[0-9])(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}(?![\w-])"),
)

# ── declaratives ────────────────────────────────────────────────────────────
# Absence / negation asserted in the present indicative — a description of today
# sitting where a rule is read.
_ABSENCE = re.compile(
    r"(?<![\w'])(?:"
    r"[Nn]o\s+[A-Za-z][\w\- ]{1,40}?\s+(?:exists?|is\s+present|are\s+present|remains?)"
    r"|(?:does|do)\s+not\s+\w+"
    r"|ha(?:s|ve)\s+no\s+\w+"
    r"|(?:is|are)\s+not\s+(?:an?|the)?\s*\w+"
    r"|,\s*not\s+(?:an?|the)\s+\w+"
    r")"
)

# Footer restatement: "*IBG role definition. No learning systems. No image processing.*"
_NO_NOUN = re.compile(r"(?<![\w'])No\s+[A-Za-z][\w\-]*(?:\s+[a-z][\w\-]*){0,3}\s*[.;]")
_EMPHASISED_LINE = re.compile(r"^\s*(?:\*{1,3}|_{1,3})[^*_].*(?:\*{1,3}|_{1,3})\s*$")
_CLOSING_TAIL = 3  # the document's last N prose lines also count as closing

_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(?:```|~~~)")
_MAX_SNIPPET = 200
_MAX_CONTRADICTION_REFS = 8


class _Section:
    """A heading and every line until the next heading of equal-or-higher level."""

    __slots__ = ("level", "heading", "start", "end", "prescriptive", "cited")

    def __init__(self, level: int, heading: str, start: int) -> None:
        self.level = level
        self.heading = heading
        self.start = start          # 1-based line of the heading (0 = preamble)
        self.end = start
        self.prescriptive = bool(_PRESCRIPTIVE_HEADING.search(heading))
        self.cited = False


def _any_citation(lines: list[str], mask: list[bool], start: int, end: int) -> bool:
    """True if any prose line in [start, end] carries a checkable source."""
    for idx in range(max(start - 1, 0), min(end, len(lines))):
        if mask[idx]:
            continue
        if any(p.search(lines[idx]) for p in _CITATIONS):
            return True
    return False


def _code_mask(lines: list[str]) -> list[bool]:
    """Mark fenced-code lines so diagrams and samples never trip a tell."""
    mask: list[bool] = []
    in_fence = False
    for raw in lines:
        if _FENCE.match(raw):
            in_fence = not in_fence
            mask.append(True)
            continue
        mask.append(in_fence)
    return mask


def _split_sections(lines: list[str], mask: list[bool]) -> list[_Section]:
    """Section spans, each ending at the next heading of equal-or-higher level."""
    sections = [_Section(0, "", 0)]
    open_stack: list[_Section] = [sections[0]]
    for i, raw in enumerate(lines, start=1):
        if mask[i - 1]:
            continue
        m = _HEADING.match(raw)
        if not m:
            continue
        level = len(m.group(1))
        while len(open_stack) > 1 and open_stack[-1].level >= level:
            open_stack.pop().end = i - 1
        section = _Section(level, m.group(2), i)
        sections.append(section)
        open_stack.append(section)
    for section in open_stack:
        section.end = len(lines)
    return sections


def _section_index(sections: list[_Section], total: int) -> list[_Section]:
    """Map each 1-based line to its innermost enclosing section."""
    index = [sections[0]] * (total + 1)
    for section in sections:
        for line in range(max(section.start, 1), min(section.end, total) + 1):
            if section.level >= index[line].level:
                index[line] = section
    return index


def _has_governance_marker(lines: list[str]) -> bool:
    """True if the preamble declares the document canonical."""
    seen = 0
    for raw in lines:
        if not raw.strip():
            continue
        if _GOVERNANCE_MARKER.search(raw):
            return True
        seen += 1
        if seen >= _PREAMBLE_LINES:
            return False
    return False


def _permission_hits(rel: str, lines: list[str], mask: list[bool]) -> list[str]:
    """`rel:line` refs for opposing permission tokens (`MAY NOT` is a prohibition)."""
    hits: list[str] = []
    for i, raw in enumerate(lines, start=1):
        if mask[i - 1]:
            continue
        for m in _PERMISSION.finditer(raw):
            if raw[m.end():m.end() + 4].upper().startswith(" NOT"):
                continue
            hits.append(f"{rel}:{i}")
            break
    return hits


def _closing_lines(lines: list[str], mask: list[bool]) -> set[int]:
    """Emphasised whole-line summaries plus the document's last few prose lines."""
    prose = [i for i, raw in enumerate(lines, start=1)
             if raw.strip() and not mask[i - 1]]
    out: set[int] = set(prose[-_CLOSING_TAIL:])
    out.update(i for i in prose if _EMPHASISED_LINE.match(lines[i - 1]))
    return out


def _iter_md_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDE_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in _MD_EXTS:
                found.append(Path(dirpath) / name)
    return sorted(found)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return path.name


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


class _Candidate(NamedTuple):
    """Everything one surfaced line needs to become a Finding."""

    rel: str
    line: int
    snippet: str
    tell: str
    token: str
    strength: str
    section: str
    contradictions: list[str]


def _classify(raw: str, section: _Section, governed: bool, closing: bool):
    """Return ``(tell, token, strength)`` for the strongest tell on this line."""
    prohibition = _PROHIBITION.search(raw)
    if prohibition and (governed or section.prescriptive) and not section.cited:
        if _ABSENCE.search(raw):
            return ("unsourced imperative + present-indicative",
                    prohibition.group(1), "HIGH")
        return "unsourced imperative", prohibition.group(1), "MEDIUM"
    if prohibition:
        return None
    absence = _ABSENCE.search(raw) if section.prescriptive else None
    if absence:
        return "present-indicative-as-law", absence.group(0).strip(), "MEDIUM"
    footer = _NO_NOUN.search(raw) if (closing and governed) else None
    if footer:
        return "closing restatement", footer.group(0).strip(), "MEDIUM"
    return None


class CanonicalPillAnalyzer:
    """Surface unsourced imperative prohibitions in canonical governance prose."""

    id: str = "canonical_pill"
    version: str = "1.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        # `files` is the runner's Python-only discovery set — Markdown never appears
        # there, so this analyzer collects its own inputs (cross_copy_drift precedent).
        parsed: dict[str, tuple[list[str], list[bool]]] = {}
        by_dir: dict[str, list[str]] = {}
        for path in _iter_md_files(root):
            text = _read(path)
            if text is None:
                continue
            rel = _relative(path, root)
            lines = text.splitlines()
            mask = _code_mask(lines)
            parsed[rel] = (lines, mask)
            by_dir.setdefault(os.path.dirname(rel), []).extend(
                _permission_hits(rel, lines, mask)
            )

        findings: list[Finding] = []
        for rel, (lines, mask) in parsed.items():
            findings.extend(
                self._scan(rel, lines, mask, by_dir.get(os.path.dirname(rel), []))
            )
        findings.sort(key=lambda f: (f.location.path, f.location.line_start))
        return findings

    def _scan(self, rel: str, lines: list[str], mask: list[bool],
              contradictions: list[str]) -> list[Finding]:
        sections = _split_sections(lines, mask)
        for section in sections:
            section.cited = _any_citation(lines, mask, section.start, section.end)
        index = _section_index(sections, len(lines))
        governed = _has_governance_marker(lines)
        closing = _closing_lines(lines, mask)

        out: list[Finding] = []
        for i, raw in enumerate(lines, start=1):
            if mask[i - 1] or not raw.strip():
                continue
            tell = _classify(raw, index[i], governed, i in closing)
            if tell is None:
                continue
            kind, token, strength = tell
            out.append(self._finding(_Candidate(
                rel=rel, line=i, snippet=raw.strip()[:_MAX_SNIPPET], tell=kind,
                token=token, strength=strength, section=index[i].heading,
                contradictions=contradictions,
            )))
        return out

    def _finding(self, cand: _Candidate) -> Finding:
        rel, line, snippet, token = cand.rel, cand.line, cand.snippet, cand.token
        fingerprint = make_fingerprint(_RULE_ID, rel, token, snippet)
        message = (
            f"'{rel}':{line} carries a canonical prohibition ('{token}') with no "
            f"citation anywhere in its section ('{cand.section or 'preamble'}') — "
            f"unsourced canonical prohibition; confirm whether this is a real rule "
            f"or a frozen observation. A rationale is not a source: a rule backed by "
            f"a reference, standard, tolerance or version pin carries authority, "
            f"while a rule backed only by a description of today's behavior can "
            f"permanently lock out a still-developmental capability. Fix: cite the "
            f"authority, or restate it as a dated observation rather than a rule."
        )
        return Finding(
            finding_id=fingerprint,
            type=AnalyzerType.CANONICAL_PILL,
            # Advisory: a candidate lead must never fail a build. The MEDIUM/HIGH
            # ladder is carried by `confidence` and `candidate_strength` instead.
            severity=Severity.LOW,
            confidence=0.7 if cand.strength == "HIGH" else 0.5,
            message=message,
            location=Location(path=rel, line_start=line, line_end=line),
            fingerprint=fingerprint,
            snippet=snippet,
            metadata={
                "rule_id": _RULE_ID,
                "tell": cand.tell,
                "token": token,
                "section": cand.section,
                "candidate_strength": cand.strength,
                "candidate": True,
                "context_confirmed": False,
                "contradiction_refs": cand.contradictions[:_MAX_CONTRADICTION_REFS],
            },
        )
