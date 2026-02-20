"""Vue coupling analyzer — detects composable extraction opportunities and component coupling issues.

Combines two analysis strategies:
1. **Composable Extraction**: Identifies script logic that should be extracted to composables
2. **Component Coupling**: Detects tightly coupled components via props/emits/imports

Rules
-----
VUE-COMPOSE-001 (MEDIUM)
    Component has many refs/reactives that form a cohesive group — extract to composable.
VUE-COMPOSE-002 (MEDIUM)
    Component has repeated state pattern seen in other components — shared composable opportunity.
VUE-COMPOSE-003 (LOW)
    Component mixes multiple concerns (data fetching + UI state + form handling).

VUE-COUPLE-001 (MEDIUM)
    Component has excessive props (>8) — suggests over-coupling with parent.
VUE-COUPLE-002 (MEDIUM)
    Component has excessive emits (>6) — suggests leaky abstraction.
VUE-COUPLE-003 (HIGH)
    Component imports many siblings (>5) — high coupling, consider restructuring.
VUE-COUPLE-004 (MEDIUM)
    Prop drilling detected — component passes props through without using them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint


# ══════════════════════════════════════════════════════════════════════════════
# Thresholds
# ══════════════════════════════════════════════════════════════════════════════

# Composable extraction thresholds
_MIN_REFS_FOR_COMPOSABLE = 4       # Group of 4+ refs = composable candidate
_MIN_FUNCTIONS_FOR_COMPOSABLE = 3  # 3+ related functions = composable candidate
_CONCERN_MIX_THRESHOLD = 2         # 2+ distinct concerns = multi-concern smell

# Coupling thresholds
_PROPS_HIGH = 8                    # >8 props = over-coupled
_PROPS_CRITICAL = 12               # >12 props = definitely too many
_EMITS_HIGH = 6                    # >6 emits = leaky abstraction
_EMITS_CRITICAL = 10               # >10 emits = needs redesign
_IMPORTS_HIGH = 5                  # >5 sibling imports = high coupling
_IMPORTS_CRITICAL = 8              # >8 = spaghetti


# ══════════════════════════════════════════════════════════════════════════════
# Data Structures
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class StateGroup:
    """A group of related reactive state that could become a composable."""
    name: str                      # Suggested composable name
    refs: tuple[str, ...]          # ref() variable names
    reactives: tuple[str, ...]     # reactive() variable names
    computeds: tuple[str, ...]     # computed() variable names
    functions: tuple[str, ...]     # Related function names
    concern: str                   # Detected concern type
    line_start: int
    line_end: int

    @property
    def total_items(self) -> int:
        return len(self.refs) + len(self.reactives) + len(self.computeds) + len(self.functions)


@dataclass(slots=True)
class VueCouplingMetrics:
    """Parsed coupling metrics for a Vue SFC."""

    # Basic counts
    total_lines: int = 0
    script_lines: int = 0

    # Composable extraction signals
    refs: list[str] = field(default_factory=list)
    reactives: list[str] = field(default_factory=list)
    computeds: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    watches: list[str] = field(default_factory=list)

    # Coupling signals
    props: list[str] = field(default_factory=list)
    emits: list[str] = field(default_factory=list)
    component_imports: list[str] = field(default_factory=list)
    composable_imports: list[str] = field(default_factory=list)

    # Detected concerns
    concerns: list[str] = field(default_factory=list)

    # Prop drilling signals
    props_passed_through: list[str] = field(default_factory=list)

    # State groups (composable candidates)
    state_groups: list[StateGroup] = field(default_factory=list)

    @property
    def has_excessive_props(self) -> bool:
        return len(self.props) > _PROPS_HIGH

    @property
    def has_excessive_emits(self) -> bool:
        return len(self.emits) > _EMITS_HIGH

    @property
    def has_high_coupling(self) -> bool:
        return len(self.component_imports) > _IMPORTS_HIGH

    @property
    def needs_composable_extraction(self) -> bool:
        return (
            len(self.refs) + len(self.reactives) >= _MIN_REFS_FOR_COMPOSABLE
            or len(self.functions) >= _MIN_FUNCTIONS_FOR_COMPOSABLE + 2
        )

    @property
    def has_mixed_concerns(self) -> bool:
        return len(self.concerns) >= _CONCERN_MIX_THRESHOLD


# ══════════════════════════════════════════════════════════════════════════════
# Concern Detection
# ══════════════════════════════════════════════════════════════════════════════

# Patterns that indicate specific concerns
_CONCERN_PATTERNS = {
    "data_fetching": [
        r"\bfetch\s*\(",
        r"\baxios\.",
        r"\buseFetch\b",
        r"\buseAsyncData\b",
        r"\bawait\s+\w+\s*\.\s*get\(",
        r"\bawait\s+\w+\s*\.\s*post\(",
        r"api\.\w+\(",
    ],
    "form_handling": [
        r"\bv-model\b",
        r"\bhandleSubmit\b",
        r"\bvalidate\w*\(",
        r"\bformData\b",
        r"\buseForm\b",
        r"\berrors\s*[=:]\s*ref",
        r"\bisValid\b",
    ],
    "ui_state": [
        r"\bisOpen\b",
        r"\bisLoading\b",
        r"\bisVisible\b",
        r"\bshowModal\b",
        r"\bactiveTab\b",
        r"\bselected\w*\s*=\s*ref",
        r"\bexpanded\b",
    ],
    "pagination": [
        r"\bpage\s*=\s*ref",
        r"\bpageSize\b",
        r"\btotalPages\b",
        r"\bnextPage\b",
        r"\bprevPage\b",
        r"\boffset\b",
        r"\blimit\b",
    ],
    "sorting_filtering": [
        r"\bsortBy\b",
        r"\bsortOrder\b",
        r"\bfilter\w*\s*=\s*ref",
        r"\bsearchQuery\b",
        r"\bsearchTerm\b",
    ],
    "selection": [
        r"\bselectedIds\b",
        r"\bselectedItems\b",
        r"\bisSelected\b",
        r"\btoggleSelection\b",
        r"\bselectAll\b",
        r"\bclearSelection\b",
    ],
    "undo_redo": [
        r"\bundoStack\b",
        r"\bredoStack\b",
        r"\bcanUndo\b",
        r"\bcanRedo\b",
        r"\bundo\(\)",
        r"\bredo\(\)",
    ],
}


def _detect_concerns(content: str) -> list[str]:
    """Detect which concerns are present in the component."""
    detected = []
    for concern, patterns in _CONCERN_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(concern)
                break
    return detected


# ══════════════════════════════════════════════════════════════════════════════
# State Group Detection (Composable Candidates)
# ══════════════════════════════════════════════════════════════════════════════

def _detect_state_groups(content: str, metrics: VueCouplingMetrics) -> list[StateGroup]:
    """Identify groups of related state that could become composables."""
    groups = []

    # Group by naming prefix (e.g., form*, user*, item*)
    prefix_groups: dict[str, dict] = {}

    all_names = metrics.refs + metrics.reactives + metrics.computeds + metrics.functions

    for name in all_names:
        # Extract prefix (first word in camelCase or first part before underscore)
        prefix_match = re.match(r"^([a-z]+)", name)
        if not prefix_match:
            continue
        prefix = prefix_match.group(1)

        if len(prefix) < 3:  # Skip very short prefixes
            continue

        if prefix not in prefix_groups:
            prefix_groups[prefix] = {
                "refs": [], "reactives": [], "computeds": [], "functions": []
            }

        if name in metrics.refs:
            prefix_groups[prefix]["refs"].append(name)
        elif name in metrics.reactives:
            prefix_groups[prefix]["reactives"].append(name)
        elif name in metrics.computeds:
            prefix_groups[prefix]["computeds"].append(name)
        elif name in metrics.functions:
            prefix_groups[prefix]["functions"].append(name)

    # Convert significant groups to StateGroup objects
    for prefix, items in prefix_groups.items():
        total = sum(len(v) for v in items.values())
        if total >= _MIN_REFS_FOR_COMPOSABLE:
            # Determine the concern
            concern = "unknown"
            for c in metrics.concerns:
                if prefix in c or c in prefix:
                    concern = c
                    break

            groups.append(StateGroup(
                name=f"use{prefix.capitalize()}",
                refs=tuple(items["refs"]),
                reactives=tuple(items["reactives"]),
                computeds=tuple(items["computeds"]),
                functions=tuple(items["functions"]),
                concern=concern,
                line_start=1,
                line_end=metrics.script_lines,
            ))

    # Also detect concern-based groups using simpler keyword matching
    concern_keywords = {
        "data_fetching": ["fetch", "load", "api", "data", "response"],
        "pagination": ["page", "offset", "limit", "total"],
        "selection": ["selected", "selection", "toggle", "select"],
        "undo_redo": ["undo", "redo", "history", "stack"],
    }

    for concern in metrics.concerns:
        if concern in concern_keywords:
            # These are strong composable candidates
            concern_refs = []
            keywords = concern_keywords[concern]

            for ref in metrics.refs + metrics.reactives:
                ref_lower = ref.lower()
                if any(kw in ref_lower for kw in keywords):
                    concern_refs.append(ref)

            if len(concern_refs) >= 2:
                composable_name = f"use{concern.replace('_', ' ').title().replace(' ', '')}"
                # Avoid duplicates
                if not any(g.name == composable_name for g in groups):
                    groups.append(StateGroup(
                        name=composable_name,
                        refs=tuple(concern_refs),
                        reactives=(),
                        computeds=(),
                        functions=(),
                        concern=concern,
                        line_start=1,
                        line_end=metrics.script_lines,
                    ))

    return groups


# ══════════════════════════════════════════════════════════════════════════════
# Parsing
# ══════════════════════════════════════════════════════════════════════════════

def _parse_coupling_metrics(content: str) -> VueCouplingMetrics:
    """Extract coupling and composable metrics from Vue SFC content."""
    metrics = VueCouplingMetrics()
    lines = content.splitlines()
    metrics.total_lines = len(lines)

    # Find script section
    script_start = script_end = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("<script"):
            script_start = i
        elif line.strip() == "</script>":
            script_end = i
            break

    metrics.script_lines = max(0, script_end - script_start - 1) if script_start >= 0 else 0

    # Extract reactive state
    metrics.refs = re.findall(r"const\s+(\w+)\s*=\s*ref\s*[<(]", content)
    metrics.reactives = re.findall(r"const\s+(\w+)\s*=\s*reactive\s*[<(]", content)
    metrics.computeds = re.findall(r"const\s+(\w+)\s*=\s*computed\s*\(", content)
    metrics.watches = re.findall(r"watch\s*\(\s*(\w+)", content)

    # Extract functions (excluding lifecycle hooks and built-ins)
    all_funcs = re.findall(r"(?:const\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|function\s+(\w+)\s*\()", content)
    excluded = {"onMounted", "onUnmounted", "onBeforeMount", "onBeforeUnmount",
                "watch", "watchEffect", "computed", "ref", "reactive", "defineProps", "defineEmits"}
    metrics.functions = [
        f[0] or f[1] for f in all_funcs
        if (f[0] or f[1]) not in excluded and not (f[0] or f[1]).startswith("_")
    ]

    # Extract props
    prop_match = re.search(r"defineProps<\{([^}]*)\}>", content, re.DOTALL)
    if prop_match:
        metrics.props = re.findall(r"(\w+)\s*[?:]", prop_match.group(1))

    # Also check for withDefaults pattern
    defaults_match = re.search(r"withDefaults\s*\(\s*defineProps<\{([^}]*)\}>", content, re.DOTALL)
    if defaults_match and not metrics.props:
        metrics.props = re.findall(r"(\w+)\s*[?:]", defaults_match.group(1))

    # Extract emits
    emit_match = re.search(r"defineEmits<\{([^}]*)\}>", content, re.DOTALL)
    if emit_match:
        metrics.emits = re.findall(r"\(\s*e:\s*['\"](\w+)['\"]", emit_match.group(1))

    # Also check array syntax: defineEmits(['event1', 'event2'])
    emit_array_match = re.search(r"defineEmits\s*\(\s*\[([^\]]*)\]", content)
    if emit_array_match and not metrics.emits:
        metrics.emits = re.findall(r"['\"](\w+)['\"]", emit_array_match.group(1))

    # Extract component imports
    metrics.component_imports = re.findall(
        r"import\s+(\w+)\s+from\s+['\"](?:@/components/|\.\.?/|~/components/).*\.vue['\"]",
        content
    )

    # Extract composable imports
    metrics.composable_imports = re.findall(
        r"import\s+\{\s*([^}]*use\w+[^}]*)\s*\}",
        content
    )

    # Detect concerns
    metrics.concerns = _detect_concerns(content)

    # Detect prop drilling (props that are passed to children without local use)
    for prop in metrics.props:
        # Check if prop is used in template bindings to child components
        prop_pass_pattern = rf":{prop}=['\"]?{prop}['\"]?"
        prop_use_pattern = rf"\b{prop}\b"

        # Count uses in script (excluding the prop definition)
        script_section = content[script_start:script_end] if script_start >= 0 else ""
        script_uses = len(re.findall(prop_use_pattern, script_section))

        # If prop is only passed through (1 script use = prop definition), it's drilling
        if script_uses <= 1 and re.search(prop_pass_pattern, content):
            metrics.props_passed_through.append(prop)

    # Detect state groups (composable candidates)
    metrics.state_groups = _detect_state_groups(content, metrics)

    return metrics


# ══════════════════════════════════════════════════════════════════════════════
# Analyzer
# ══════════════════════════════════════════════════════════════════════════════

class VueCouplingAnalyzer:
    """Detects composable extraction opportunities and component coupling issues.

    Analyzes:
    - Reactive state that should be grouped into composables
    - Mixed concerns that should be separated
    - Excessive props/emits indicating tight coupling
    - High component import count indicating spaghetti
    - Prop drilling patterns

    Rule IDs:
    - VUE-COMPOSE-001: State group should be composable
    - VUE-COMPOSE-002: Mixed concerns detected
    - VUE-COUPLE-001: Excessive props
    - VUE-COUPLE-002: Excessive emits
    - VUE-COUPLE-003: High component coupling
    - VUE-COUPLE-004: Prop drilling detected
    """

    id: str = "vue_coupling"
    version: str = "1.0.0"

    def __init__(
        self,
        props_threshold: int = _PROPS_HIGH,
        emits_threshold: int = _EMITS_HIGH,
        imports_threshold: int = _IMPORTS_HIGH,
    ):
        self.props_threshold = props_threshold
        self.emits_threshold = emits_threshold
        self.imports_threshold = imports_threshold

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []

        for path in files:
            if path.suffix != ".vue":
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, IOError):
                continue

            metrics = _parse_coupling_metrics(content)
            rel = path.relative_to(root).as_posix()
            component_name = path.stem

            # ── Composable extraction findings ────────────────────────────

            # VUE-COMPOSE-001: State groups that should be composables
            for group in metrics.state_groups:
                if group.total_items >= _MIN_REFS_FOR_COMPOSABLE:
                    rule_id = "VUE-COMPOSE-001"
                    items_list = ", ".join(group.refs[:3] + group.functions[:2])
                    if group.total_items > 5:
                        items_list += f" (+{group.total_items - 5} more)"

                    snippet = f"{group.name}(): {items_list}"

                    findings.append(Finding(
                        finding_id="",
                        type=AnalyzerType.COMPLEXITY,
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                        message=f"State group '{group.name}' ({group.total_items} items) should be extracted to composable",
                        location=Location(path=rel, line_start=1, line_end=metrics.script_lines or 1),
                        fingerprint=make_fingerprint(rule_id, rel, group.name, snippet),
                        snippet=snippet,
                        metadata={
                            "rule_id": rule_id,
                            "component_name": component_name,
                            "suggested_composable": group.name,
                            "refs": list(group.refs),
                            "reactives": list(group.reactives),
                            "computeds": list(group.computeds),
                            "functions": list(group.functions),
                            "concern": group.concern,
                            "total_items": group.total_items,
                        },
                    ))

            # VUE-COMPOSE-002: Mixed concerns
            if metrics.has_mixed_concerns:
                rule_id = "VUE-COMPOSE-002"
                concerns_str = ", ".join(metrics.concerns)
                snippet = f"Concerns: {concerns_str}"

                findings.append(Finding(
                    finding_id="",
                    type=AnalyzerType.COMPLEXITY,
                    severity=Severity.LOW,
                    confidence=0.7,
                    message=f"Component '{component_name}' mixes {len(metrics.concerns)} concerns — consider separating into composables",
                    location=Location(path=rel, line_start=1, line_end=metrics.total_lines),
                    fingerprint=make_fingerprint(rule_id, rel, component_name, snippet),
                    snippet=snippet,
                    metadata={
                        "rule_id": rule_id,
                        "component_name": component_name,
                        "concerns": metrics.concerns,
                        "suggested_composables": [
                            f"use{c.replace('_', ' ').title().replace(' ', '')}"
                            for c in metrics.concerns
                        ],
                    },
                ))

            # ── Coupling findings ─────────────────────────────────────────

            # VUE-COUPLE-001: Excessive props
            if len(metrics.props) > self.props_threshold:
                rule_id = "VUE-COUPLE-001"
                severity = Severity.HIGH if len(metrics.props) > _PROPS_CRITICAL else Severity.MEDIUM
                snippet = f"Props: {len(metrics.props)} ({', '.join(metrics.props[:5])}...)"

                findings.append(Finding(
                    finding_id="",
                    type=AnalyzerType.COMPLEXITY,
                    severity=severity,
                    confidence=0.9,
                    message=f"Component '{component_name}' has {len(metrics.props)} props — over-coupled with parent",
                    location=Location(path=rel, line_start=1, line_end=metrics.total_lines),
                    fingerprint=make_fingerprint(rule_id, rel, component_name, snippet),
                    snippet=snippet,
                    metadata={
                        "rule_id": rule_id,
                        "component_name": component_name,
                        "prop_count": len(metrics.props),
                        "props": metrics.props,
                        "threshold": self.props_threshold,
                    },
                ))

            # VUE-COUPLE-002: Excessive emits
            if len(metrics.emits) > self.emits_threshold:
                rule_id = "VUE-COUPLE-002"
                severity = Severity.HIGH if len(metrics.emits) > _EMITS_CRITICAL else Severity.MEDIUM
                snippet = f"Emits: {len(metrics.emits)} ({', '.join(metrics.emits[:5])}...)"

                findings.append(Finding(
                    finding_id="",
                    type=AnalyzerType.COMPLEXITY,
                    severity=severity,
                    confidence=0.9,
                    message=f"Component '{component_name}' has {len(metrics.emits)} emits — leaky abstraction",
                    location=Location(path=rel, line_start=1, line_end=metrics.total_lines),
                    fingerprint=make_fingerprint(rule_id, rel, component_name, snippet),
                    snippet=snippet,
                    metadata={
                        "rule_id": rule_id,
                        "component_name": component_name,
                        "emit_count": len(metrics.emits),
                        "emits": metrics.emits,
                        "threshold": self.emits_threshold,
                    },
                ))

            # VUE-COUPLE-003: High component coupling
            if len(metrics.component_imports) > self.imports_threshold:
                rule_id = "VUE-COUPLE-003"
                severity = Severity.HIGH if len(metrics.component_imports) > _IMPORTS_CRITICAL else Severity.MEDIUM
                snippet = f"Imports: {len(metrics.component_imports)} components"

                findings.append(Finding(
                    finding_id="",
                    type=AnalyzerType.COMPLEXITY,
                    severity=severity,
                    confidence=0.85,
                    message=f"Component '{component_name}' imports {len(metrics.component_imports)} sibling components — high coupling",
                    location=Location(path=rel, line_start=1, line_end=metrics.total_lines),
                    fingerprint=make_fingerprint(rule_id, rel, component_name, snippet),
                    snippet=snippet,
                    metadata={
                        "rule_id": rule_id,
                        "component_name": component_name,
                        "import_count": len(metrics.component_imports),
                        "imports": metrics.component_imports,
                        "threshold": self.imports_threshold,
                    },
                ))

            # VUE-COUPLE-004: Prop drilling
            if len(metrics.props_passed_through) >= 2:
                rule_id = "VUE-COUPLE-004"
                snippet = f"Drilled props: {', '.join(metrics.props_passed_through)}"

                findings.append(Finding(
                    finding_id="",
                    type=AnalyzerType.COMPLEXITY,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    message=f"Component '{component_name}' drills {len(metrics.props_passed_through)} props — consider provide/inject or composable",
                    location=Location(path=rel, line_start=1, line_end=metrics.total_lines),
                    fingerprint=make_fingerprint(rule_id, rel, component_name, snippet),
                    snippet=snippet,
                    metadata={
                        "rule_id": rule_id,
                        "component_name": component_name,
                        "drilled_props": metrics.props_passed_through,
                        "total_props": len(metrics.props),
                    },
                ))

        # Assign stable finding IDs
        for i, f in enumerate(findings):
            prefix = "vc" if "COMPOSE" in f.metadata.get("rule_id", "") else "vcp"
            object.__setattr__(f, "finding_id", f"{prefix}_{f.fingerprint[7:15]}_{i:04d}")

        return findings


# ══════════════════════════════════════════════════════════════════════════════
# Standalone utilities
# ══════════════════════════════════════════════════════════════════════════════

def suggest_composables(content: str) -> list[dict]:
    """Analyze Vue component and suggest composables to extract.

    Returns list of suggestions with:
    - name: Suggested composable name (e.g., "useSelection")
    - refs: List of refs to include
    - functions: List of functions to include
    - rationale: Why this should be a composable
    """
    metrics = _parse_coupling_metrics(content)
    suggestions = []

    for group in metrics.state_groups:
        suggestions.append({
            "name": group.name,
            "refs": list(group.refs),
            "reactives": list(group.reactives),
            "computeds": list(group.computeds),
            "functions": list(group.functions),
            "concern": group.concern,
            "rationale": f"Group of {group.total_items} related items with '{group.concern}' concern",
        })

    return suggestions


def analyze_coupling(content: str) -> dict:
    """Analyze Vue component coupling metrics.

    Returns dict with:
    - props_count, emits_count, imports_count
    - issues: List of coupling issues detected
    - score: 0-100 coupling health score (lower = more coupled)
    """
    metrics = _parse_coupling_metrics(content)

    issues = []
    score = 100

    if metrics.has_excessive_props:
        issues.append(f"Excessive props ({len(metrics.props)})")
        score -= min(30, (len(metrics.props) - _PROPS_HIGH) * 5)

    if metrics.has_excessive_emits:
        issues.append(f"Excessive emits ({len(metrics.emits)})")
        score -= min(20, (len(metrics.emits) - _EMITS_HIGH) * 4)

    if metrics.has_high_coupling:
        issues.append(f"High component coupling ({len(metrics.component_imports)} imports)")
        score -= min(25, (len(metrics.component_imports) - _IMPORTS_HIGH) * 5)

    if metrics.props_passed_through:
        issues.append(f"Prop drilling ({len(metrics.props_passed_through)} props)")
        score -= min(15, len(metrics.props_passed_through) * 3)

    if metrics.has_mixed_concerns:
        issues.append(f"Mixed concerns ({', '.join(metrics.concerns)})")
        score -= min(10, len(metrics.concerns) * 3)

    return {
        "props_count": len(metrics.props),
        "emits_count": len(metrics.emits),
        "imports_count": len(metrics.component_imports),
        "composable_imports": len(metrics.composable_imports),
        "concerns": metrics.concerns,
        "issues": issues,
        "score": max(0, score),
    }
