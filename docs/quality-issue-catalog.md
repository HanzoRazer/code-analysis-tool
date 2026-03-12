# Code Quality Issue Catalog

> **Generated:** 2026-02-24 15:45 UTC  
> **Target:** `docs/patterns/examples/vue-composables/`  
> **Suite:** Code Quality Analyzer v2.0 (28 checkers)  
> **Total remaining:** 95 issues (0 critical, 17 warning, 78 info)

---

## Summary by checker

| Checker | Severity | Count | Disposition |
|---------|----------|------:|-------------|
| DeadCodeDetector | info | 72 | Likely false-positive — composable exports consumed by parent `.vue` files outside this directory |
| TestCoverageIndicator | info | 6 | Expected — example/pattern files, not production source |
| DuplicateCodeDetector | warning | 14 | Structural similarity inherent to the Vue composable pattern |
| ConsoleLogDetector | warning | 3 | **False-positive** — `console.*` calls are inside string templates (generated Node.js snippet output) |

---

## 1. Warnings (17)

### 1.1 ConsoleLogDetector — false positives in generated snippet strings (3)

These `console.log`/`console.warn` calls appear inside **string literals** that build a Node.js code snippet for the user to copy. They are _output template content_, not actual runtime calls.

| # | File | Line | Message | Recommendation |
|---|------|-----:|---------|----------------|
| W-1 | `useExportSnippets.ts` | 167 | `console.log()` left in source | **No action** — inside `buildExportNodeFetch()` template string |
| W-2 | `useExportSnippets.ts` | 169 | `console.warn()` left in source | **No action** — same template string |
| W-3 | `useExportSnippets.ts` | 172 | `console.log()` left in source | **No action** — same template string |

> **Tooling improvement:** The `ConsoleLogDetector` checker should learn to skip `console.*` calls that appear inside string delimiters (quotes, backticks, template-literal array elements).

---

### 1.2 DuplicateCodeDetector — intra-file duplication (3)

Structural repetition within a single file.

| # | File | Line | Similar to | Context | Recommendation |
|---|------|-----:|------------|---------|----------------|
| W-4 | `useExportSnippets.ts` | 130 | line 173 | GitHub Actions YAML step/job builders share `run: \|` + `curl` + `upload-artifact` scaffolding | Consider a shared `buildYamlCurlStep()` helper |
| W-5 | `useExportSnippets.ts` | 173 | line 240 | Job builder and Workflow builder repeat identical `steps:` YAML block | Extract common step array into a function |
| W-6 | `usePresetFilters.ts` | 94 | line 104 | `loadPersistedState()` and `savePersistedState()` both iterate the same 3 `STORAGE_KEYS` | Consider a data-driven loop over the key→ref mapping |

---

### 1.3 DuplicateCodeDetector — cross-file structural similarity (11)

These are inherent to the Vue Composition API composable pattern: each composable independently imports from `vue`, declares refs/computed, returns a state object. Merging them would break the deliberate per-concern extraction.

| # | File | Line | Similar to | What's duplicated |
|---|------|-----:|------------|-------------------|
| W-7 | `useJobTooltip.ts` | 8 | `usePresetFilters.ts` | `import { ref, computed, … } from 'vue'` |
| W-8 | `useJobTooltip.ts` | 15 | `usePresetFilters.ts` | Interface declaration block scaffold |
| W-9 | `useJobTooltip.ts` | 60 | `usePresetFilters.ts` | `export function use…(` composable signature |
| W-10 | `useJobTooltip.ts` | 72 | `usePresetFilters.ts` | `const … = computed(() => {` pattern |
| W-11 | `useJobTooltip.ts` | 82 | `usePresetFilters.ts` | `async function … {` / `try { … } catch` |
| W-12 | `useJobTooltip.ts` | 83 | `usePresetFilters.ts` | Return statement `return { … }` |
| W-13 | `usePresetFilters.ts` | 6 | `usePresetForm.ts` | `import { ref, … } from 'vue'` + `import type { Preset }` |
| W-14 | `usePresetFilters.ts` | 49 | `usePresetForm.ts` | Interface field declarations |
| W-15 | `usePresetFilters.ts` | 50 | `usePresetForm.ts` | Interface field declarations (continued) |
| W-16 | `usePresetFilters.ts` | 68 | `usePresetForm.ts` | `export function use…(` composable signature |
| W-17 | `usePresetFilters.ts` | 150 | `usePresetForm.ts` | `return { … }` composable return object |

> **Disposition:** These are _by-design_ — the composable extraction pattern intentionally makes each file self-contained. No code change recommended. Consider adding these patterns to the suite's baseline or suppression list.

---

## 2. Info — Missing test files (6)

Each composable is an extracted example/pattern file, not production source code. Creating test files is optional but recommended if these composables are promoted to production.

| # | File | Recommendation |
|---|------|----------------|
| I-1 | `useExportSnippets.ts` | Create `useExportSnippets.test.ts` — pure functions, easy to unit test |
| I-2 | `useJobTooltip.ts` | Create `useJobTooltip.test.ts` — needs API mock for `fetchJobDetails` |
| I-3 | `useLogDrawer.ts` | Create `useLogDrawer.test.ts` — needs `window.location` stub |
| I-4 | `usePresetFilters.ts` | Create `usePresetFilters.test.ts` — needs `localStorage` mock |
| I-5 | `usePresetForm.ts` | Create `usePresetForm.test.ts` — needs `fetch` mock |
| I-6 | `useWorkflowOverrides.ts` | Create `useWorkflowOverrides.test.ts` — needs `localStorage` mock |

---

## 3. Info — Potentially unused declarations (72)

The `DeadCodeDetector` reports declarations that are not referenced in any _other_ file in the scanned directory. Because these composables are consumed by `.vue` files living outside the `vue-composables/` directory, every export appears "unused" within the scanned scope.

**Disposition:** All 72 are **expected false-positives** for this directory structure. To suppress, either:
- Widen the scan scope to include the consuming `.vue` files, or
- Add a `.codequalityrc.json` suppression entry, or
- Use `--exclude-checks DeadCodeDetector` for example directories.

### 3.1 `useExportSnippets.ts` (12 symbols)

| # | Symbol | Kind | Likely consumer |
|---|--------|------|-----------------|
| I-7 | `prepareYamlExportArgs` | helper function | Internal — used by `buildExportGitHubActions*` in same file |
| I-8 | `BACKTICK_CHARCODE` | constant | Internal — used by `jsEscape()` in same file |
| I-9 | `MAX_SESSION_ID_LENGTH` | constant | Internal — used by `safeFilenameFromSession()` in same file |
| I-10 | `cleaned` | local variable | False positive — scoped to `safeFilenameFromSession()` |
| I-11 | `viteRepo` | local variable | False positive — scoped to `detectRepoNameForHeader()` |
| I-12 | `parts` | local variable | False positive — scoped to `detectRepoNameForHeader()` |
| I-13 | `out` | local variable | False positive — scoped to `buildExportPowerShellIwr()` |
| I-14 | `out` | local variable | False positive — scoped to `buildExportPythonRequests()` |
| I-15 | `out` | local variable | False positive — scoped to `buildExportNodeFetch()` |
| I-16 | `rawOut` | destructured field | Internal — from `prepareYamlExportArgs()` |
| I-17 | `repoName` | local variable | False positive — scoped to `buildRepoReadyWorkflowBundle()` |
| I-18 | _(3× `out` duplicates)_ | — | Same symbol in multiple functions |

> **Tooling improvement:** `DeadCodeDetector` should skip local/scoped variables and only flag module-level or exported symbols.

### 3.2 `useJobTooltip.ts` (12 symbols)

| # | Symbol | Kind | Likely consumer |
|---|--------|------|-----------------|
| I-19 | `fetchJobDetails` | async function | Internal composable method |
| I-20 | `showJobTooltip` | function | Returned to consuming `.vue` — used in template `@mouseenter` |
| I-21 | `hideJobTooltip` | function | Returned to consuming `.vue` — used in template `@mouseleave` |
| I-22 | `viewJobInHistory` | function | Returned to consuming `.vue` — used in template `@click` |
| I-23 | `formatTime` | function | Returned — used in tooltip template |
| I-24 | `formatEnergy` | function | Returned — used in tooltip template |
| I-25 | `formatDate` | function | Returned — used in tooltip template |
| I-26 | `TOOLTIP_CURSOR_OFFSET` | constant | Internal — used in `showJobTooltip()` |
| I-27 | `hoveredPresetId` | ref | Returned — used in template `v-if` |
| I-28 | `tooltipPosition` | ref | Returned — used in template `:style` |
| I-29 | `jobDetailsCache` | ref | Returned — exposed for parent inspection |
| I-30 | `currentJobDetails` | computed | Returned — used in tooltip template |

### 3.3 `useLogDrawer.ts` (10 symbols)

| # | Symbol | Kind | Likely consumer |
|---|--------|------|-----------------|
| I-31 | `buildLogViewerUrl` | function | Internal — used by `logsUrl` computed |
| I-32 | `openDrawer` | function | Returned — used in template `@click` |
| I-33 | `closeDrawer` | function | Returned — used in template `@click` |
| I-34 | `togglePin` | function | Returned — used in template `@click` |
| I-35 | `openLogsNewTab` | function | Returned — used in template `@click` |
| I-36 | `isOpen` | ref | Returned — used in template `v-if` |
| I-37 | `pinnedRunId` | ref | Returned — used in template display |
| I-38 | `effectiveRunId` | computed | Returned — used for iframe URL |
| I-39 | `logsUrl` | computed | Returned — used in template `:src` |
| I-40 | `isPinned` | computed | Returned — used in template conditional |
| I-41 | `drawerTitle` | computed | Returned — used in template header |

### 3.4 `usePresetFilters.ts` (11 symbols)

| # | Symbol | Kind | Likely consumer |
|---|--------|------|-----------------|
| I-42 | `loadPersistedState` | function | Returned — called in `onMounted()` by parent |
| I-43 | `savePersistedState` | function | Returned — called by watcher in composable |
| I-44 | `getTabCount` | function | Returned — used in tab badge `{{ getTabCount('cam') }}` |
| I-45 | `STORAGE_KEYS` | const object | Internal — used by persistence functions |
| I-46 | `activeTab` | ref | Returned — used in template `v-model` |
| I-47 | `searchQuery` | ref | Returned — used in template `v-model` |
| I-48 | `selectedTag` | ref | Returned — used in template `v-model` |
| I-49 | `availableTags` | computed | Returned — used in template `v-for` |
| I-50 | `tagSet` | local variable | False positive — scoped to `availableTags` computed |
| I-51 | `filteredPresets` | computed | Returned — used in template `v-for` |
| I-52 | `filtered` | local variable | False positive — scoped to `filteredPresets` computed |

### 3.5 `usePresetForm.ts` (12 symbols)

| # | Symbol | Kind | Likely consumer |
|---|--------|------|-----------------|
| I-53 | `populateFormFromPreset` | function | Internal — used by `editPreset()` and `clonePreset()` |
| I-54 | `resetForm` | function | Internal — called by `closeModal()` |
| I-55 | `closeModal` | function | Returned — used in template `@click` |
| I-56 | `editPreset` | function | Returned — used in template `@click` |
| I-57 | `clonePreset` | function | Returned — used in template `@click` |
| I-58 | `savePreset` | async function | Returned — used in template `@submit` |
| I-59 | `DEFAULT_EXPORT_TEMPLATE` | constant | Internal — default value for `exportTemplate` |
| I-60 | `showCreateModal` | ref | Returned — used in template `v-if` |
| I-61 | `editingPreset` | ref | Returned — used in template conditional |
| I-62 | `saving` | ref | Returned — used in template `:disabled` |
| I-63 | `tagsInput` | ref | Returned — used in template `v-model` |
| I-64 | `exportTemplate` | ref | Returned — used in template `v-model` |

### 3.6 `useWorkflowOverrides.ts` (15 symbols)

| # | Symbol | Kind | Likely consumer |
|---|--------|------|-----------------|
| I-65 | `getStorageKey` | function | Internal — used by `storageKey` computed |
| I-66 | `readFromStorage` | function | Internal — used by `hydrateOverrides()` and watcher |
| I-67 | `writeToStorage` | function | Internal — used by auto-save watcher |
| I-68 | `clearStorage` | function | Internal — used by `clearOverrides()` |
| I-69 | `applyOverrides` | function | Internal — used by `hydrateOverrides()` and watcher |
| I-70 | `hydrateOverrides` | function | Returned — called in `onMounted()` by parent |
| I-71 | `clearOverrides` | function | Returned — used in template `@click` |
| I-72 | `OVERRIDES_LS_KEY_PREFIX` | constant | Internal — used by `getStorageKey()` |
| I-73 | `toolId` | ref | Returned — used in template `v-model` |
| I-74 | `materialId` | ref | Returned — used in template `v-model` |
| I-75 | `machineProfileId` | ref | Returned — used in template `v-model` |
| I-76 | `camProfileId` | ref | Returned — used in template `v-model` |
| I-77 | `riskTolerance` | ref | Returned — used in template `v-model` |
| I-78 | `storageKey` | computed | Internal — used by persistence watcher |
| I-79 | `currentOverrides` | computed | Returned — used by export panel |

---

## 4. Recommended tooling improvements

Based on this analysis, the following improvements to the Code Quality Analyzer suite would reduce false positives:

| ID | Checker | Improvement | Impact |
|----|---------|-------------|--------|
| T-1 | `ConsoleLogDetector` | Skip `console.*` inside string delimiters (array of string elements in `.join()`) | Eliminates 3 false-positive warnings |
| T-2 | `DeadCodeDetector` | Only flag module-level / exported symbols, not local variables or function-scoped `const`/`let` | Eliminates ~15 false-positive infos |
| T-3 | `DeadCodeDetector` | Recognize that `export function` / `export const` symbols are API surface and skip them when no consuming files are in scan scope | Eliminates ~50 false-positive infos |
| T-4 | `DuplicateCodeDetector` | Add configurable minimum semantic weight — skip blocks that are mostly imports/type declarations | Reduces ~8 cross-file structural warnings |
| T-5 | `TestCoverageIndicator` | Add configurable `exclude_paths` for example/pattern directories | Eliminates 6 infos for non-production code |

---

## 5. Recommended suppressions

To baseline these known issues, add to `.codequalityrc.json`:

```json
{
  "exclude_checks": [],
  "suppressions": [
    {
      "check": "ConsoleLogDetector",
      "file": "useExportSnippets.ts",
      "message": "console.*() left in source"
    },
    {
      "check": "DeadCodeDetector",
      "file": "docs/patterns/examples/"
    },
    {
      "check": "TestCoverageIndicator",
      "file": "docs/patterns/examples/"
    }
  ]
}
```
