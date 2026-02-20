# Vue CSS Module Extraction Pattern

> Extract bloated scoped styles from Vue SFCs into CSS Modules for better maintainability.

## Problem

Large Vue components often have disproportionate CSS (>40% of LOC):
- Scoped styles create large, hard-to-scan files
- CSS mixed with component logic increases cognitive load
- Styles can't be shared between components
- No CSS-level code splitting

## When to Apply

| Style % | Recommendation |
|---------|----------------|
| <30% | Keep scoped styles |
| 30-40% | Consider extraction |
| >40% | **Extract to CSS module** |
| >50% | Critical - extract immediately |

## Solution

Extract scoped styles to **CSS Modules** (`.module.css` files):

1. **Audit** - Calculate style percentage
2. **Create** - Create `.module.css` file
3. **Migrate** - Move styles, convert selectors
4. **Import** - Use `$style` object in template
5. **Verify** - Type-check and visual test

## Step-by-Step Procedure

### Step 1: Audit Component

```bash
# Count lines in each section
wc -l ComponentName.vue

# Or use this script:
awk '
  /<script/,/<\/script>/ { script++ }
  /<template/,/<\/template>/ { template++ }
  /<style/,/<\/style>/ { style++ }
  END {
    total = script + template + style
    printf "Script: %d (%d%%)\n", script, script*100/total
    printf "Template: %d (%d%%)\n", template, template*100/total
    printf "Style: %d (%d%%)\n", style, style*100/total
  }
' ComponentName.vue
```

### Step 2: Create CSS Module

Create `ComponentName.module.css` alongside the component:

```
components/
├── ComponentName.vue
└── ComponentName.module.css   # NEW
```

### Step 3: Migrate Styles

#### Before (scoped styles in SFC)
```vue
<style scoped>
.widget-container {
  display: flex;
  gap: 16px;
}

.widget-container .header {
  font-weight: 700;
}

.btn {
  padding: 8px 16px;
}

.btn.primary {
  background: #3b82f6;
}

.btn:hover:not(:disabled) {
  opacity: 0.9;
}
</style>
```

#### After (CSS Module)
```css
/* ComponentName.module.css */

.widgetContainer {
  display: flex;
  gap: 16px;
}

.header {
  font-weight: 700;
}

.btn {
  padding: 8px 16px;
}

.btnPrimary {
  composes: btn;
  background: #3b82f6;
}

.btnPrimary:hover:not(:disabled) {
  opacity: 0.9;
}
```

#### Conversion Rules

| Scoped CSS | CSS Module |
|------------|------------|
| `.kebab-case` | `.camelCase` |
| `.parent .child` | Flatten or use `composes` |
| `.class.modifier` | `.classModifier` or `composes` |
| `:deep(.class)` | Keep in SFC (rare cases) |

### Step 4: Import and Apply

```vue
<script setup lang="ts">
import styles from './ComponentName.module.css'
</script>

<template>
  <!-- Static class -->
  <div :class="styles.widgetContainer">
    <h1 :class="styles.header">Title</h1>

    <!-- Multiple classes -->
    <button :class="[styles.btn, styles.btnPrimary]">
      Primary
    </button>

    <!-- Conditional classes -->
    <button :class="[styles.btn, isActive && styles.active]">
      Toggle
    </button>

    <!-- Object syntax -->
    <div :class="{ [styles.card]: true, [styles.cardSelected]: isSelected }">
      Card
    </div>
  </div>
</template>

<!-- Keep minimal scoped styles for edge cases -->
<style scoped>
/* Only for :deep() or third-party overrides */
</style>
```

### Step 5: TypeScript Declaration (Optional)

For better type safety, add a declaration file:

```typescript
// src/types/css-modules.d.ts
declare module '*.module.css' {
  const classes: { [key: string]: string }
  export default classes
}
```

### Step 6: Verify

```bash
# Type check
npm run type-check

# Build
npm run build

# Visual test - manually verify styling
npm run dev
```

## Example: DxfToGcodeView.vue

### Before (651 LOC)
```
DxfToGcodeView.vue
├── Script: 56 LOC (9%)
├── Template: 213 LOC (33%)
└── Style: 371 LOC (57%)  ← CRITICAL
```

### After (280 LOC + 371 LOC CSS Module)
```
DxfToGcodeView.vue (280 LOC)
├── Script: 56 LOC
├── Template: 213 LOC (with :class bindings)
└── Style: 11 LOC (minimal, only :deep overrides)

DxfToGcodeView.module.css (371 LOC)
└── All styles, properly scoped via CSS Modules
```

## Common Patterns

### Pattern 1: State-Based Styling

```vue
<!-- Before -->
<div class="card" :class="{ selected: isSelected, disabled: isDisabled }">

<!-- After -->
<div :class="[
  styles.card,
  isSelected && styles.cardSelected,
  isDisabled && styles.cardDisabled
]">
```

### Pattern 2: Prop-Based Variants

```vue
<script setup>
const props = defineProps<{ size: 'sm' | 'md' | 'lg' }>()

const sizeClass = computed(() => ({
  sm: styles.btnSm,
  md: styles.btnMd,
  lg: styles.btnLg,
}[props.size]))
</script>

<template>
  <button :class="[styles.btn, sizeClass]">
    <slot />
  </button>
</template>
```

### Pattern 3: Composable for Complex Styling

```typescript
// useComponentStyles.ts
import { computed } from 'vue'
import styles from './Component.module.css'

export function useComponentStyles(props: { variant: string; disabled: boolean }) {
  const rootClass = computed(() => [
    styles.root,
    styles[`variant${capitalize(props.variant)}`],
    props.disabled && styles.disabled,
  ].filter(Boolean))

  return { styles, rootClass }
}
```

## Checklist

- [ ] Calculate style percentage (target: >40%)
- [ ] Create `.module.css` file
- [ ] Convert kebab-case to camelCase
- [ ] Flatten nested selectors
- [ ] Replace `.class.modifier` with composed classes
- [ ] Update template class bindings
- [ ] Keep `:deep()` styles in SFC if needed
- [ ] Run type-check
- [ ] Visual verification
- [ ] Commit with clear message

## Benefits

| Metric | Before | After |
|--------|--------|-------|
| SFC LOC | 651 | 280 |
| Style separation | Mixed | Isolated |
| Reusability | None | Import anywhere |
| Build optimization | None | CSS code splitting |

## Edge Cases

### When to Keep Scoped Styles

1. **`:deep()` overrides** for third-party components
2. **Keyframe animations** (can stay in SFC)
3. **Global resets** (use `:global()` or separate file)

### Hybrid Approach

```vue
<script setup>
import styles from './Component.module.css'
</script>

<template>
  <div :class="styles.container">
    <ThirdPartyComponent class="override-target" />
  </div>
</template>

<style scoped>
/* Only for third-party overrides */
.override-target :deep(.internal-class) {
  color: red;
}
</style>
```

## Files

- **Pattern source**: `luthiers-toolbox/packages/client/src/views/`
- **Example 1**: `DxfToGcodeView.vue` → `DxfToGcodeView.module.css`
- **Example 2**: `RmosRunViewerView.vue` → `RmosRunViewerView.module.css`
- **Example 3**: `InstrumentGeometryPanel.vue` → `InstrumentGeometryPanel.module.css`

## Related Patterns

- [Vue Component Decomposition](./vue-component-decomposition.md) - For script extraction
- Tailwind CSS migration - Alternative approach using utility classes
