"""Tests for vue_coupling analyzer."""

from pathlib import Path

import pytest

from code_audit.analyzers.vue_coupling import (
    VueCouplingAnalyzer,
    VueCouplingMetrics,
    _parse_coupling_metrics,
    _detect_concerns,
    suggest_composables,
    analyze_coupling,
)
from code_audit.model import AnalyzerType, Severity


# ══════════════════════════════════════════════════════════════════════════════
# Sample Components
# ══════════════════════════════════════════════════════════════════════════════

SIMPLE_COMPONENT = """<script setup lang="ts">
const count = ref(0)
</script>

<template>
  <div>{{ count }}</div>
</template>
"""

EXCESSIVE_PROPS_COMPONENT = """<script setup lang="ts">
defineProps<{
  id: string;
  name: string;
  email: string;
  phone: string;
  address: string;
  city: string;
  state: string;
  zip: string;
  country: string;
  avatar: string;
  role: string;
  status: string;
}>()
</script>

<template>
  <div>User</div>
</template>
"""

EXCESSIVE_EMITS_COMPONENT = """<script setup lang="ts">
defineEmits<{
  (e: 'update'): void;
  (e: 'delete'): void;
  (e: 'save'): void;
  (e: 'cancel'): void;
  (e: 'edit'): void;
  (e: 'copy'): void;
  (e: 'move'): void;
  (e: 'archive'): void;
}>()
</script>

<template>
  <div>Actions</div>
</template>
"""

HIGH_COUPLING_COMPONENT = """<script setup lang="ts">
import HeaderPanel from "@/components/HeaderPanel.vue";
import SidebarPanel from "@/components/SidebarPanel.vue";
import ContentPanel from "@/components/ContentPanel.vue";
import FooterPanel from "@/components/FooterPanel.vue";
import NavigationPanel from "@/components/NavigationPanel.vue";
import ToolbarPanel from "@/components/ToolbarPanel.vue";
import StatusBar from "@/components/StatusBar.vue";
</script>

<template>
  <div>Layout</div>
</template>
"""

COMPOSABLE_CANDIDATE_COMPONENT = """<script setup lang="ts">
import { ref, computed } from 'vue'

// Selection state - should be useSelection()
const selectedIds = ref<Set<string>>(new Set())
const selectedItems = computed(() => items.value.filter(i => selectedIds.value.has(i.id)))
const selectionCount = computed(() => selectedIds.value.size)

function toggleSelection(id: string) {
  if (selectedIds.value.has(id)) {
    selectedIds.value.delete(id)
  } else {
    selectedIds.value.add(id)
  }
}

function selectAll() {
  items.value.forEach(i => selectedIds.value.add(i.id))
}

function clearSelection() {
  selectedIds.value.clear()
}

// Pagination state - should be usePagination()
const page = ref(1)
const pageSize = ref(10)
const totalPages = computed(() => Math.ceil(items.value.length / pageSize.value))

function nextPage() {
  if (page.value < totalPages.value) page.value++
}

function prevPage() {
  if (page.value > 1) page.value--
}

// Items
const items = ref([])
</script>

<template>
  <div>List</div>
</template>
"""

MIXED_CONCERNS_COMPONENT = """<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'

// Data fetching concern
const data = ref(null)
const loading = ref(false)

async function fetchData() {
  loading.value = true
  const response = await fetch('/api/data')
  data.value = await response.json()
  loading.value = false
}

// Form handling concern
const formData = ref({})
const errors = ref({})

function validateForm() {
  errors.value = {}
  if (!formData.value.name) {
    errors.value.name = 'Name is required'
  }
}

function handleSubmit() {
  validateForm()
  if (Object.keys(errors.value).length === 0) {
    // submit
  }
}

// UI state concern
const isModalOpen = ref(false)
const activeTab = ref('details')

onMounted(() => {
  fetchData()
})
</script>

<template>
  <div>Form</div>
</template>
"""

PROP_DRILLING_COMPONENT = """<script setup lang="ts">
import ChildComponent from './ChildComponent.vue'

const props = defineProps<{
  userId: string;
  userName: string;
  userRole: string;
  theme: string;
  locale: string;
}>()

// Only uses theme locally
const themeClass = computed(() => `theme-${props.theme}`)
</script>

<template>
  <div :class="themeClass">
    <ChildComponent
      :userId="userId"
      :userName="userName"
      :userRole="userRole"
      :locale="locale"
    />
  </div>
</template>
"""


# ══════════════════════════════════════════════════════════════════════════════
# Tests: Parsing
# ══════════════════════════════════════════════════════════════════════════════

class TestParseCouplingMetrics:
    """Tests for _parse_coupling_metrics function."""

    def test_parses_simple_component(self):
        metrics = _parse_coupling_metrics(SIMPLE_COMPONENT)

        assert metrics.total_lines > 0
        assert len(metrics.refs) == 1
        assert "count" in metrics.refs

    def test_parses_props(self):
        metrics = _parse_coupling_metrics(EXCESSIVE_PROPS_COMPONENT)

        assert len(metrics.props) == 12
        assert "id" in metrics.props
        assert "name" in metrics.props

    def test_parses_emits(self):
        metrics = _parse_coupling_metrics(EXCESSIVE_EMITS_COMPONENT)

        assert len(metrics.emits) == 8
        assert "update" in metrics.emits
        assert "delete" in metrics.emits

    def test_parses_component_imports(self):
        metrics = _parse_coupling_metrics(HIGH_COUPLING_COMPONENT)

        assert len(metrics.component_imports) == 7
        assert "HeaderPanel" in metrics.component_imports

    def test_parses_refs_and_functions(self):
        metrics = _parse_coupling_metrics(COMPOSABLE_CANDIDATE_COMPONENT)

        assert "selectedIds" in metrics.refs
        assert "page" in metrics.refs
        assert "toggleSelection" in metrics.functions or "selectAll" in metrics.functions


class TestDetectConcerns:
    """Tests for concern detection."""

    def test_detects_data_fetching(self):
        content = "await fetch('/api/data')"
        concerns = _detect_concerns(content)
        assert "data_fetching" in concerns

    def test_detects_form_handling(self):
        content = "const errors = ref({})\nfunction validateForm() {}"
        concerns = _detect_concerns(content)
        assert "form_handling" in concerns

    def test_detects_pagination(self):
        content = "const page = ref(1)\nconst pageSize = ref(10)"
        concerns = _detect_concerns(content)
        assert "pagination" in concerns

    def test_detects_selection(self):
        content = "const selectedIds = ref(new Set())\nfunction toggleSelection() {}"
        concerns = _detect_concerns(content)
        assert "selection" in concerns

    def test_detects_multiple_concerns(self):
        metrics = _parse_coupling_metrics(MIXED_CONCERNS_COMPONENT)
        assert len(metrics.concerns) >= 2


class TestCouplingMetricsProperties:
    """Tests for VueCouplingMetrics computed properties."""

    def test_has_excessive_props(self):
        metrics = _parse_coupling_metrics(EXCESSIVE_PROPS_COMPONENT)
        assert metrics.has_excessive_props is True

    def test_has_excessive_emits(self):
        metrics = _parse_coupling_metrics(EXCESSIVE_EMITS_COMPONENT)
        assert metrics.has_excessive_emits is True

    def test_has_high_coupling(self):
        metrics = _parse_coupling_metrics(HIGH_COUPLING_COMPONENT)
        assert metrics.has_high_coupling is True

    def test_simple_component_no_issues(self):
        metrics = _parse_coupling_metrics(SIMPLE_COMPONENT)
        assert metrics.has_excessive_props is False
        assert metrics.has_excessive_emits is False
        assert metrics.has_high_coupling is False


# ══════════════════════════════════════════════════════════════════════════════
# Tests: Analyzer
# ══════════════════════════════════════════════════════════════════════════════

class TestVueCouplingAnalyzer:
    """Tests for VueCouplingAnalyzer class."""

    def test_analyzer_protocol(self):
        analyzer = VueCouplingAnalyzer()
        assert analyzer.id == "vue_coupling"
        assert analyzer.version == "1.0.0"
        assert callable(analyzer.run)

    def test_simple_component_no_findings(self, tmp_path: Path):
        vue_file = tmp_path / "Simple.vue"
        vue_file.write_text(SIMPLE_COMPONENT)

        analyzer = VueCouplingAnalyzer()
        findings = analyzer.run(tmp_path, [vue_file])

        # Simple component should have no coupling issues
        coupling_findings = [f for f in findings if "COUPLE" in f.metadata.get("rule_id", "")]
        assert len(coupling_findings) == 0

    def test_excessive_props_finding(self, tmp_path: Path):
        vue_file = tmp_path / "ExcessiveProps.vue"
        vue_file.write_text(EXCESSIVE_PROPS_COMPONENT)

        analyzer = VueCouplingAnalyzer()
        findings = analyzer.run(tmp_path, [vue_file])

        prop_findings = [f for f in findings if f.metadata.get("rule_id") == "VUE-COUPLE-001"]
        assert len(prop_findings) == 1
        assert prop_findings[0].metadata["prop_count"] == 12

    def test_excessive_emits_finding(self, tmp_path: Path):
        vue_file = tmp_path / "ExcessiveEmits.vue"
        vue_file.write_text(EXCESSIVE_EMITS_COMPONENT)

        analyzer = VueCouplingAnalyzer()
        findings = analyzer.run(tmp_path, [vue_file])

        emit_findings = [f for f in findings if f.metadata.get("rule_id") == "VUE-COUPLE-002"]
        assert len(emit_findings) == 1
        assert emit_findings[0].metadata["emit_count"] == 8

    def test_high_coupling_finding(self, tmp_path: Path):
        vue_file = tmp_path / "HighCoupling.vue"
        vue_file.write_text(HIGH_COUPLING_COMPONENT)

        analyzer = VueCouplingAnalyzer()
        findings = analyzer.run(tmp_path, [vue_file])

        coupling_findings = [f for f in findings if f.metadata.get("rule_id") == "VUE-COUPLE-003"]
        assert len(coupling_findings) == 1
        assert coupling_findings[0].metadata["import_count"] == 7

    def test_composable_candidate_finding(self, tmp_path: Path):
        vue_file = tmp_path / "ComposableCandidate.vue"
        vue_file.write_text(COMPOSABLE_CANDIDATE_COMPONENT)

        analyzer = VueCouplingAnalyzer()
        findings = analyzer.run(tmp_path, [vue_file])

        compose_findings = [f for f in findings if "COMPOSE" in f.metadata.get("rule_id", "")]
        # Should detect selection and/or pagination groups
        assert len(compose_findings) >= 1

    def test_mixed_concerns_finding(self, tmp_path: Path):
        vue_file = tmp_path / "MixedConcerns.vue"
        vue_file.write_text(MIXED_CONCERNS_COMPONENT)

        analyzer = VueCouplingAnalyzer()
        findings = analyzer.run(tmp_path, [vue_file])

        concern_findings = [f for f in findings if f.metadata.get("rule_id") == "VUE-COMPOSE-002"]
        assert len(concern_findings) == 1
        assert len(concern_findings[0].metadata["concerns"]) >= 2

    def test_finding_has_fingerprint(self, tmp_path: Path):
        vue_file = tmp_path / "Props.vue"
        vue_file.write_text(EXCESSIVE_PROPS_COMPONENT)

        analyzer = VueCouplingAnalyzer()
        findings = analyzer.run(tmp_path, [vue_file])

        assert len(findings) >= 1
        assert findings[0].fingerprint.startswith("sha256:")

    def test_non_vue_files_ignored(self, tmp_path: Path):
        py_file = tmp_path / "component.py"
        py_file.write_text("x = 1")

        analyzer = VueCouplingAnalyzer()
        findings = analyzer.run(tmp_path, [py_file])

        assert findings == []


# ══════════════════════════════════════════════════════════════════════════════
# Tests: Utility Functions
# ══════════════════════════════════════════════════════════════════════════════

class TestSuggestComposables:
    """Tests for suggest_composables utility."""

    def test_suggests_composables_for_state_groups(self):
        suggestions = suggest_composables(COMPOSABLE_CANDIDATE_COMPONENT)

        # Should suggest at least one composable
        assert len(suggestions) >= 1

        # Check structure
        for s in suggestions:
            assert "name" in s
            assert "refs" in s
            assert "rationale" in s
            assert s["name"].startswith("use")


class TestAnalyzeCoupling:
    """Tests for analyze_coupling utility."""

    def test_returns_coupling_metrics(self):
        result = analyze_coupling(EXCESSIVE_PROPS_COMPONENT)

        assert "props_count" in result
        assert "emits_count" in result
        assert "imports_count" in result
        assert "score" in result
        assert "issues" in result

        assert result["props_count"] == 12
        assert result["score"] < 100  # Should have deductions

    def test_simple_component_high_score(self):
        result = analyze_coupling(SIMPLE_COMPONENT)

        assert result["score"] >= 90  # Simple = healthy

    def test_complex_component_low_score(self):
        result = analyze_coupling(EXCESSIVE_PROPS_COMPONENT)

        assert result["score"] <= 80  # Excessive props = unhealthy
        assert len(result["issues"]) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# Tests: Severity Levels
# ══════════════════════════════════════════════════════════════════════════════

class TestSeverityLevels:
    """Tests for correct severity assignment."""

    def test_excessive_props_medium_severity(self, tmp_path: Path):
        # 12 props = > 8 threshold but < 12 critical
        vue_file = tmp_path / "Props.vue"
        vue_file.write_text(EXCESSIVE_PROPS_COMPONENT)

        analyzer = VueCouplingAnalyzer()
        findings = analyzer.run(tmp_path, [vue_file])

        prop_findings = [f for f in findings if f.metadata.get("rule_id") == "VUE-COUPLE-001"]
        # 12 props = critical threshold, so HIGH severity
        assert prop_findings[0].severity in [Severity.MEDIUM, Severity.HIGH]

    def test_composable_suggestion_medium_severity(self, tmp_path: Path):
        vue_file = tmp_path / "Composable.vue"
        vue_file.write_text(COMPOSABLE_CANDIDATE_COMPONENT)

        analyzer = VueCouplingAnalyzer()
        findings = analyzer.run(tmp_path, [vue_file])

        compose_findings = [f for f in findings if f.metadata.get("rule_id") == "VUE-COMPOSE-001"]
        if compose_findings:
            assert compose_findings[0].severity == Severity.MEDIUM

    def test_mixed_concerns_low_severity(self, tmp_path: Path):
        vue_file = tmp_path / "Mixed.vue"
        vue_file.write_text(MIXED_CONCERNS_COMPONENT)

        analyzer = VueCouplingAnalyzer()
        findings = analyzer.run(tmp_path, [vue_file])

        concern_findings = [f for f in findings if f.metadata.get("rule_id") == "VUE-COMPOSE-002"]
        if concern_findings:
            assert concern_findings[0].severity == Severity.LOW
