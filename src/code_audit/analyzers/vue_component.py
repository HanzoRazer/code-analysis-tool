"""Vue component analyzer — detects god object components needing decomposition."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# Thresholds
_LOC_THRESHOLD = 500      # Start flagging
_LOC_HIGH = 800           # High severity
_LOC_CRITICAL = 1500      # Critical - definitely needs decomposition

# Template/script ratio thresholds
_TEMPLATE_RATIO_HIGH = 0.7  # >70% template is a smell (inline logic)
_SCRIPT_RATIO_HIGH = 0.8    # >80% script suggests extract to composable


@dataclass(frozen=True, slots=True)
class VueComponentMetrics:
    """Parsed metrics for a Vue SFC."""

    total_lines: int
    template_lines: int
    script_lines: int
    style_lines: int
    template_ratio: float
    script_ratio: float
    has_setup: bool
    component_count: int  # Child component imports
    composable_count: int  # use* imports
    emit_count: int  # defineEmits count
    prop_count: int  # defineProps fields

    @property
    def is_god_object(self) -> bool:
        return self.total_lines >= _LOC_HIGH

    @property
    def needs_composable_extraction(self) -> bool:
        return self.script_ratio >= _SCRIPT_RATIO_HIGH and self.script_lines > 400

    @property
    def needs_component_extraction(self) -> bool:
        return self.template_ratio >= _TEMPLATE_RATIO_HIGH and self.template_lines > 300


def _parse_vue_metrics(content: str) -> VueComponentMetrics:
    """Extract structural metrics from Vue SFC content."""
    lines = content.splitlines()
    total = len(lines)

    # Find section boundaries
    template_start = template_end = -1
    script_start = script_end = -1
    style_start = style_end = -1

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("<template"):
            template_start = i
        elif stripped == "</template>":
            template_end = i
        elif stripped.startswith("<script"):
            script_start = i
        elif stripped == "</script>":
            script_end = i
        elif stripped.startswith("<style"):
            style_start = i
        elif stripped == "</style>":
            style_end = i

    template_lines = max(0, template_end - template_start - 1) if template_start >= 0 else 0
    script_lines = max(0, script_end - script_start - 1) if script_start >= 0 else 0
    style_lines = max(0, style_end - style_start - 1) if style_start >= 0 else 0

    code_lines = template_lines + script_lines  # Exclude style from ratio calc
    template_ratio = template_lines / code_lines if code_lines > 0 else 0
    script_ratio = script_lines / code_lines if code_lines > 0 else 0

    # Detect patterns
    has_setup = bool(re.search(r"<script\s+setup", content))

    # Count imports
    component_imports = len(re.findall(r"import\s+\w+\s+from\s+['\"].*\.vue['\"]", content))
    composable_imports = len(re.findall(r"import\s+\{[^}]*use\w+", content))

    # Count defineEmits/defineProps
    emit_match = re.search(r"defineEmits<\{([^}]*)\}>", content, re.DOTALL)
    emit_count = len(re.findall(r"(\w+):", emit_match.group(1))) if emit_match else 0

    prop_match = re.search(r"defineProps<\{([^}]*)\}>", content, re.DOTALL)
    prop_count = len(re.findall(r"(\w+)\??:", prop_match.group(1))) if prop_match else 0

    return VueComponentMetrics(
        total_lines=total,
        template_lines=template_lines,
        script_lines=script_lines,
        style_lines=style_lines,
        template_ratio=template_ratio,
        script_ratio=script_ratio,
        has_setup=has_setup,
        component_count=component_imports,
        composable_count=composable_imports,
        emit_count=emit_count,
        prop_count=prop_count,
    )


def _identify_extraction_candidates(content: str, metrics: VueComponentMetrics) -> list[dict]:
    """Identify template sections that could be extracted as child components."""
    candidates = []
    lines = content.splitlines()

    # Find template section
    template_start = -1
    template_end = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("<template"):
            template_start = i
        elif line.strip() == "</template>":
            template_end = i
            break

    if template_start < 0 or template_end < 0:
        return candidates

    # Look for extractable patterns:
    # 1. Divs/sections with comments like "<!-- M.3: Energy -->"
    # 2. Large repeated structures
    # 3. Divs with many children (>50 lines)

    current_section = None
    section_start = -1
    depth = 0

    for i in range(template_start + 1, template_end):
        line = lines[i]
        stripped = line.strip()

        # Track section comments
        comment_match = re.match(r"<!--\s*(.+?)\s*-->", stripped)
        if comment_match and depth == 0:
            if current_section and i - section_start > 30:
                candidates.append({
                    "name": current_section,
                    "line_start": section_start,
                    "line_end": i - 1,
                    "line_count": i - section_start,
                })
            current_section = comment_match.group(1).strip()
            section_start = i

        # Track div depth for large blocks
        depth += stripped.count("<div") + stripped.count("<section")
        depth -= stripped.count("</div>") + stripped.count("</section>")

    # Close last section
    if current_section and template_end - section_start > 30:
        candidates.append({
            "name": current_section,
            "line_start": section_start,
            "line_end": template_end - 1,
            "line_count": template_end - section_start,
        })

    return candidates


class VueComponentAnalyzer:
    """Detects Vue SFC components needing decomposition.

    Analyzes:
    - Total line count (god object detection)
    - Template/script ratio (identifies extraction needs)
    - Extractable sections (based on comments/structure)
    - Composable opportunities (script-heavy components)

    Rule IDs:
    - VUE-GOD-001: Component exceeds LOC threshold (MEDIUM)
    - VUE-GOD-002: Component is a god object (HIGH)
    - VUE-GOD-003: Component critically oversized (CRITICAL)
    - VUE-EXTRACT-001: Template section extractable as component
    - VUE-COMPOSABLE-001: Script-heavy, needs composable extraction
    """

    id: str = "vue_component"
    version: str = "1.0.0"

    def __init__(
        self,
        threshold: int = _LOC_THRESHOLD,
        high_threshold: int = _LOC_HIGH,
        critical_threshold: int = _LOC_CRITICAL,
    ):
        self.threshold = threshold
        self.high_threshold = high_threshold
        self.critical_threshold = critical_threshold

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []

        for path in files:
            if path.suffix != ".vue":
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, IOError):
                continue

            metrics = _parse_vue_metrics(content)
            rel = path.relative_to(root).as_posix()
            component_name = path.stem

            # Check LOC thresholds
            if metrics.total_lines >= self.threshold:
                if metrics.total_lines >= self.critical_threshold:
                    severity = Severity.CRITICAL
                    rule_id = "VUE-GOD-003"
                    message = f"Component '{component_name}' has {metrics.total_lines} lines — critical decomposition needed"
                elif metrics.total_lines >= self.high_threshold:
                    severity = Severity.HIGH
                    rule_id = "VUE-GOD-002"
                    message = f"Component '{component_name}' has {metrics.total_lines} lines — god object detected"
                else:
                    severity = Severity.MEDIUM
                    rule_id = "VUE-GOD-001"
                    message = f"Component '{component_name}' has {metrics.total_lines} lines — consider decomposition"

                snippet = f"{component_name}: {metrics.total_lines} LOC (template:{metrics.template_lines}, script:{metrics.script_lines})"

                findings.append(
                    Finding(
                        finding_id="",
                        type=AnalyzerType.COMPLEXITY,
                        severity=severity,
                        confidence=1.0,
                        message=message,
                        location=Location(path=rel, line_start=1, line_end=metrics.total_lines),
                        fingerprint=make_fingerprint(rule_id, rel, component_name, snippet),
                        snippet=snippet,
                        metadata={
                            "rule_id": rule_id,
                            "component_name": component_name,
                            "total_lines": metrics.total_lines,
                            "template_lines": metrics.template_lines,
                            "script_lines": metrics.script_lines,
                            "style_lines": metrics.style_lines,
                            "template_ratio": round(metrics.template_ratio, 2),
                            "script_ratio": round(metrics.script_ratio, 2),
                            "has_setup": metrics.has_setup,
                            "child_components": metrics.component_count,
                            "composables": metrics.composable_count,
                            "threshold": self.threshold,
                        },
                    )
                )

            # Check for extraction candidates (only for large components)
            if metrics.total_lines >= self.threshold:
                candidates = _identify_extraction_candidates(content, metrics)
                for candidate in candidates:
                    rule_id = "VUE-EXTRACT-001"
                    snippet = f"Section '{candidate['name']}' ({candidate['line_count']} lines)"

                    findings.append(
                        Finding(
                            finding_id="",
                            type=AnalyzerType.COMPLEXITY,
                            severity=Severity.LOW,
                            confidence=0.7,  # Heuristic-based
                            message=f"Template section '{candidate['name']}' could be extracted as child component",
                            location=Location(
                                path=rel,
                                line_start=candidate["line_start"],
                                line_end=candidate["line_end"],
                            ),
                            fingerprint=make_fingerprint(
                                rule_id, rel, candidate["name"], snippet
                            ),
                            snippet=snippet,
                            metadata={
                                "rule_id": rule_id,
                                "section_name": candidate["name"],
                                "line_count": candidate["line_count"],
                                "suggested_component_name": _to_component_name(candidate["name"]),
                            },
                        )
                    )

            # Check for composable extraction opportunity
            if metrics.needs_composable_extraction:
                rule_id = "VUE-COMPOSABLE-001"
                snippet = f"Script section: {metrics.script_lines} lines ({metrics.script_ratio:.0%} of code)"

                findings.append(
                    Finding(
                        finding_id="",
                        type=AnalyzerType.COMPLEXITY,
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        message=f"Component '{component_name}' is script-heavy — consider extracting to composable",
                        location=Location(path=rel, line_start=1, line_end=metrics.total_lines),
                        fingerprint=make_fingerprint(rule_id, rel, component_name, snippet),
                        snippet=snippet,
                        metadata={
                            "rule_id": rule_id,
                            "script_lines": metrics.script_lines,
                            "script_ratio": round(metrics.script_ratio, 2),
                            "suggested_composable": f"use{component_name}",
                        },
                    )
                )

        # Assign stable finding IDs
        for i, f in enumerate(findings):
            object.__setattr__(f, "finding_id", f"vue_{f.fingerprint[7:15]}_{i:04d}")

        return findings


def _to_component_name(section_name: str) -> str:
    """Convert section comment to PascalCase component name."""
    # Remove common prefixes like "M.3:" or "L.2:"
    cleaned = re.sub(r"^[A-Z]\.\d+[:\s]*", "", section_name)
    # Convert to PascalCase
    words = re.split(r"[\s_-]+", cleaned)
    return "".join(w.capitalize() for w in words if w) + "Panel"
