# Vue Component Decomposition Pattern

> Extract logic from large Vue components into composables for better maintainability.

## Problem

Large Vue SFC components (>500 LOC) become difficult to maintain:
- Mixed concerns (state, UI, business logic)
- Hard to test individual features
- Cognitive load increases with file size

## Solution

Extract reusable logic into **composables** (Vue 3 Composition API pattern):

1. **Identify extraction candidates** - Look for:
   - State + related methods (e.g., undo stack, form state)
   - Side effects (localStorage, API calls)
   - UI state (drawer open/close, modals)
   - Code generators/builders (snippet builders)

2. **Create composable files** in `composables/` directory adjacent to component

3. **Export state + actions** from composable, import into parent component

## Example: DesignFirstWorkflowPanel.vue

### Before (1,548 LOC)
```
DesignFirstWorkflowPanel.vue
├── Template (~350 lines)
├── Script (~980 lines)
│   ├── Override state + localStorage (200 lines)
│   ├── Log drawer state (80 lines)
│   └── Export snippet builders (500 lines)
└── Style (~218 lines)
```

### After (770 LOC + 4 composables)
```
DesignFirstWorkflowPanel.vue (770 LOC)
composables/
├── useLogDrawer.ts (107 LOC)
│   - isOpen, pinnedRunId, drawerTitle
│   - openDrawer(), closeDrawer(), togglePin()
│
├── useWorkflowOverrides.ts (179 LOC)
│   - toolId, materialId, machineProfileId...
│   - TOOL_OPTIONS, MATERIAL_OPTIONS...
│   - hydrateOverrides(), clearOverrides()
│   - Auto-save to localStorage on change
│
├── useExportSnippets.ts (403 LOC)
│   - psEscape(), pyEscape(), jsEscape()
│   - buildExportPowerShellIwr()
│   - buildExportPythonRequests()
│   - buildExportNodeFetch()
│   - buildExportGitHubActionsStep/Job/Workflow()
│
└── useClipboardExport.ts (275 LOC)
    - exportUrlPreview, buildPromotionIntentExportUrl
    - copyIntent(), copySessionId(), copyIntentCurl()
    - copyExportUrl(), copyExportPowerShell/Python/Node()
    - copyExportGitHubActionsStep/Job/Workflow()
    - downloadIntent()
```

## Composable Template

```typescript
// composables/useFeatureName.ts
import { ref, computed, watch, onMounted } from 'vue'

export interface FeatureState {
  // Refs
  value: Ref<string>
  // Computed
  derived: ComputedRef<boolean>
  // Actions
  doSomething: () => void
}

export function useFeatureName(
  // Dependency injection via callbacks
  getDependency: () => string,
  onEvent?: (data: any) => void
): FeatureState {
  const value = ref('')

  const derived = computed(() => !!value.value)

  function doSomething() {
    // Implementation
    onEvent?.({ done: true })
  }

  // Watchers for side effects
  watch(value, (newVal) => {
    // e.g., save to localStorage
  })

  return {
    value,
    derived,
    doSomething,
  }
}
```

## Usage in Component

```vue
<script setup lang="ts">
import { useFeatureName } from './composables/useFeatureName'
import { useStore } from '@/stores/myStore'

const store = useStore()

// Initialize composable with dependency injection
const feature = useFeatureName(
  () => store.someValue,
  (data) => toast.success('Done!')
)

// Use in template via feature.value, feature.doSomething()
</script>

<template>
  <button @click="feature.doSomething">
    {{ feature.derived ? 'Active' : 'Inactive' }}
  </button>
</template>
```

## Benefits

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Main component LOC | 1,548 | 770 | -50% |
| Testable units | 1 | 5 | +400% |
| Reusable modules | 0 | 4 | +4 |

## Example 2: PresetHubView.vue

### Before (1,429 LOC)
```
PresetHubView.vue
├── Template (~472 lines)
├── Script (~355 lines)
│   ├── Filter state + localStorage persistence (100 lines)
│   ├── Form state + CRUD operations (150 lines)
│   └── Job tooltip state + formatters (100 lines)
└── Style (~602 lines)
```

### After (1,225 LOC + 3 composables)
```
PresetHubView.vue (1,225 LOC)
views/composables/
├── usePresetFilters.ts (~160 LOC)
│   - activeTab, searchQuery, selectedTag
│   - TAB_CONFIG constant
│   - filteredPresets computed
│   - localStorage persistence
│
├── usePresetForm.ts (~155 LOC)
│   - formData, tagsInput, exportTemplate
│   - showCreateModal, editingPreset, saving
│   - savePreset(), closeModal(), editPreset(), clonePreset()
│
└── useJobTooltip.ts (~160 LOC)
    - hoveredPresetId, tooltipPosition, jobDetailsCache
    - currentJobDetails computed
    - showJobTooltip(), hideJobTooltip()
    - formatTime(), formatEnergy(), formatDate()
```

### Key Pattern: Convenience Aliases

When composables return many values used in templates, create aliases for template compatibility:

```typescript
// Composables Setup
const filters = usePresetFilters(() => presets.value)
const form = usePresetForm(async () => await refreshPresets())
const tooltip = useJobTooltip(() => presets.value)

// Convenience Aliases (for template compatibility)
const activeTab = filters.activeTab
const searchQuery = filters.searchQuery
const showCreateModal = form.showCreateModal
const formatTime = tooltip.formatTime
// ... etc
```

This avoids changing `{{ activeTab }}` to `{{ filters.activeTab }}` throughout the template.

## When to Apply

- Component exceeds 500 LOC
- Multiple unrelated concerns in script section
- Same logic needed in multiple components
- Logic requires isolated testing

## Files

### Example 1: DesignFirstWorkflowPanel
- **Pattern source**: `luthiers-toolbox/packages/client/src/components/rosette/`
- **Main component**: `DesignFirstWorkflowPanel.vue`
- **Composables**: `composables/useLogDrawer.ts`, `useWorkflowOverrides.ts`, `useExportSnippets.ts`, `useClipboardExport.ts`

### Example 2: PresetHubView
- **Pattern source**: `luthiers-toolbox/packages/client/src/views/`
- **Main component**: `PresetHubView.vue`
- **Composables**: `composables/usePresetFilters.ts`, `usePresetForm.ts`, `useJobTooltip.ts`

### Example 3: AdaptivePocketLab
- **Pattern source**: `luthiers-toolbox/packages/client/src/components/adaptive/`
- **Main component**: `AdaptivePocketLab.vue`
- **Composables**: `composables/usePocketSettings.ts`, `useAdaptiveFeedPresets.ts`, `useToolpathRenderer.ts`, `useToolpathExport.ts`, `useEnergyMetrics.ts`, `useLiveLearning.ts`
