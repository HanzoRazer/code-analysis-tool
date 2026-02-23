#!/usr/bin/env python3
"""
vue_composable_generator.py - Generate composable templates from Vue component analysis

This tool generates starter composable files based on patterns detected in a Vue component.
Use after vue_decomposition_analyzer.py identifies candidates.

Usage:
    python scripts/vue_composable_generator.py <vue_file> --output-dir <composables_dir>

Example:
    python scripts/vue_composable_generator.py ./src/components/MyComponent.vue --output-dir ./src/components/composables

Patterns Detected -> Composable Templates Generated:
    - heavy_state      -> use{Component}State.ts     (refs, reactive state)
    - api_calls        -> use{Component}Api.ts       (fetch, async operations)
    - export_functions -> use{Component}Export.ts    (download, blob, clipboard)
    - form_validation  -> use{Component}Validation.ts (validate, errors)
    - filtering_sorting-> use{Component}Filters.ts   (filter, sort, paginate)
    - many_handlers    -> use{Component}Actions.ts   (event handlers)
"""

import argparse
import re
import sys
from pathlib import Path
from textwrap import dedent


def extract_script_content(vue_file: Path) -> str:
    """Extract script content from Vue file."""
    content = vue_file.read_text(encoding='utf-8', errors='replace')
    match = re.search(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
    return match.group(1) if match else ''


def detect_patterns(script: str) -> dict[str, bool]:
    """Detect patterns in script content."""
    return {
        'heavy_state': script.count('ref') > 5 or script.count('reactive') > 2,
        'api_calls': bool(re.search(r'(fetch|axios|api\(|\.get\(|\.post\()', script, re.I)),
        'export_functions': bool(re.search(r'(download|export|blob|createObjectURL|clipboard)', script, re.I)),
        'form_validation': bool(re.search(r'(validate|validation|errors|isValid)', script, re.I)),
        'filtering_sorting': bool(re.search(r'(filter|sort|search|paginate)', script, re.I)),
        'many_handlers': len(re.findall(r'function\s+\w+|const\s+\w+\s*=\s*(?:async\s*)?\(', script)) > 5,
        'computed_heavy': script.count('computed(') > 3,
        'watchers': script.count('watch(') > 2,
    }


def generate_state_composable(component_name: str) -> str:
    """Generate a state management composable template."""
    return dedent(f'''
        /**
         * use{component_name}State - State management for {component_name}
         */
        import {{ ref, reactive, computed }} from "vue";

        export interface {component_name}State {{
          // TODO: Define state interface
          isLoading: boolean;
          error: string | null;
        }}

        export function use{component_name}State() {{
          // Reactive state
          const state = reactive<{component_name}State>({{
            isLoading: false,
            error: null,
          }});

          // Refs for simple values
          const selectedId = ref<string | null>(null);

          // Computed properties
          const hasError = computed(() => state.error !== null);

          // State mutations
          function setLoading(loading: boolean) {{
            state.isLoading = loading;
          }}

          function setError(error: string | null) {{
            state.error = error;
          }}

          function reset() {{
            state.isLoading = false;
            state.error = null;
            selectedId.value = null;
          }}

          return {{
            state,
            selectedId,
            hasError,
            setLoading,
            setError,
            reset,
          }};
        }}
    ''').strip()


def generate_api_composable(component_name: str) -> str:
    """Generate an API composable template."""
    return dedent(f'''
        /**
         * use{component_name}Api - API operations for {component_name}
         */
        import {{ ref }} from "vue";

        export interface ApiResponse<T> {{
          data: T | null;
          error: string | null;
          loading: boolean;
        }}

        export function use{component_name}Api() {{
          const loading = ref(false);
          const error = ref<string | null>(null);

          async function fetchData<T>(url: string): Promise<T | null> {{
            loading.value = true;
            error.value = null;

            try {{
              const response = await fetch(url);
              if (!response.ok) {{
                throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
              }}
              return await response.json();
            }} catch (err) {{
              error.value = err instanceof Error ? err.message : String(err);
              return null;
            }} finally {{
              loading.value = false;
            }}
          }}

          async function postData<T, R>(url: string, data: T): Promise<R | null> {{
            loading.value = true;
            error.value = null;

            try {{
              const response = await fetch(url, {{
                method: "POST",
                headers: {{ "Content-Type": "application/json" }},
                body: JSON.stringify(data),
              }});
              if (!response.ok) {{
                throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
              }}
              return await response.json();
            }} catch (err) {{
              error.value = err instanceof Error ? err.message : String(err);
              return null;
            }} finally {{
              loading.value = false;
            }}
          }}

          return {{
            loading,
            error,
            fetchData,
            postData,
          }};
        }}
    ''').strip()


def generate_export_composable(component_name: str) -> str:
    """Generate an export/download composable template."""
    return dedent(f'''
        /**
         * use{component_name}Export - Export and download functions for {component_name}
         */

        export function use{component_name}Export() {{
          /**
           * Download data as JSON file
           */
          function downloadJson(data: unknown, filename: string) {{
            const json = JSON.stringify(data, null, 2);
            const blob = new Blob([json], {{ type: "application/json" }});
            downloadBlob(blob, `${{filename}}.json`);
          }}

          /**
           * Download data as CSV file
           */
          function downloadCsv(rows: string[][], filename: string) {{
            const csv = rows.map(row => row.join(",")).join("\\n");
            const blob = new Blob([csv], {{ type: "text/csv" }});
            downloadBlob(blob, `${{filename}}.csv`);
          }}

          /**
           * Download SVG element as file
           */
          function downloadSvg(svgElement: SVGElement, filename: string) {{
            const svgClone = svgElement.cloneNode(true) as SVGElement;
            svgClone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
            const svgData = new XMLSerializer().serializeToString(svgClone);
            const blob = new Blob([svgData], {{ type: "image/svg+xml" }});
            downloadBlob(blob, `${{filename}}.svg`);
          }}

          /**
           * Copy text to clipboard
           */
          async function copyToClipboard(text: string): Promise<boolean> {{
            try {{
              await navigator.clipboard.writeText(text);
              return true;
            }} catch {{
              return false;
            }}
          }}

          /**
           * Helper to trigger blob download
           */
          function downloadBlob(blob: Blob, filename: string) {{
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
          }}

          return {{
            downloadJson,
            downloadCsv,
            downloadSvg,
            copyToClipboard,
          }};
        }}
    ''').strip()


def generate_validation_composable(component_name: str) -> str:
    """Generate a validation composable template."""
    return dedent(f'''
        /**
         * use{component_name}Validation - Form validation for {component_name}
         */
        import {{ ref, computed }} from "vue";

        export interface ValidationRule<T> {{
          validate: (value: T) => boolean;
          message: string;
        }}

        export interface FieldErrors {{
          [field: string]: string[];
        }}

        export function use{component_name}Validation() {{
          const errors = ref<FieldErrors>({{}});
          const touched = ref<Set<string>>(new Set());

          const isValid = computed(() => {{
            return Object.values(errors.value).every(errs => errs.length === 0);
          }});

          const hasErrors = computed(() => !isValid.value);

          function validateField<T>(field: string, value: T, rules: ValidationRule<T>[]) {{
            const fieldErrors: string[] = [];

            for (const rule of rules) {{
              if (!rule.validate(value)) {{
                fieldErrors.push(rule.message);
              }}
            }}

            errors.value[field] = fieldErrors;
            return fieldErrors.length === 0;
          }}

          function touchField(field: string) {{
            touched.value.add(field);
          }}

          function getFieldErrors(field: string): string[] {{
            return errors.value[field] || [];
          }}

          function clearErrors() {{
            errors.value = {{}};
            touched.value.clear();
          }}

          // Common validation rules
          const rules = {{
            required: <T>(msg = "This field is required"): ValidationRule<T> => ({{
              validate: (v) => v !== null && v !== undefined && v !== "",
              message: msg,
            }}),
            minLength: (min: number, msg?: string): ValidationRule<string> => ({{
              validate: (v) => v.length >= min,
              message: msg || `Minimum ${{min}} characters required`,
            }}),
            maxLength: (max: number, msg?: string): ValidationRule<string> => ({{
              validate: (v) => v.length <= max,
              message: msg || `Maximum ${{max}} characters allowed`,
            }}),
            pattern: (regex: RegExp, msg: string): ValidationRule<string> => ({{
              validate: (v) => regex.test(v),
              message: msg,
            }}),
          }};

          return {{
            errors,
            touched,
            isValid,
            hasErrors,
            validateField,
            touchField,
            getFieldErrors,
            clearErrors,
            rules,
          }};
        }}
    ''').strip()


def generate_filters_composable(component_name: str) -> str:
    """Generate a filtering/sorting composable template."""
    return dedent(f'''
        /**
         * use{component_name}Filters - Filtering and sorting for {component_name}
         */
        import {{ ref, computed, type Ref }} from "vue";

        export type SortDirection = "asc" | "desc";

        export interface SortConfig<T> {{
          key: keyof T;
          direction: SortDirection;
        }}

        export function use{component_name}Filters<T extends Record<string, unknown>>(
          items: Ref<T[]>
        ) {{
          const searchQuery = ref("");
          const sortConfig = ref<SortConfig<T> | null>(null);
          const activeFilters = ref<Record<string, unknown>>({{}});

          // Pagination
          const page = ref(1);
          const pageSize = ref(20);

          const filtered = computed(() => {{
            let result = [...items.value];

            // Apply search
            if (searchQuery.value) {{
              const query = searchQuery.value.toLowerCase();
              result = result.filter(item =>
                Object.values(item).some(v =>
                  String(v).toLowerCase().includes(query)
                )
              );
            }}

            // Apply filters
            for (const [key, value] of Object.entries(activeFilters.value)) {{
              if (value !== null && value !== undefined) {{
                result = result.filter(item => item[key] === value);
              }}
            }}

            return result;
          }});

          const sorted = computed(() => {{
            if (!sortConfig.value) return filtered.value;

            const {{ key, direction }} = sortConfig.value;
            return [...filtered.value].sort((a, b) => {{
              const aVal = a[key];
              const bVal = b[key];
              const cmp = aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
              return direction === "asc" ? cmp : -cmp;
            }});
          }});

          const paginated = computed(() => {{
            const start = (page.value - 1) * pageSize.value;
            return sorted.value.slice(start, start + pageSize.value);
          }});

          const totalPages = computed(() =>
            Math.ceil(sorted.value.length / pageSize.value)
          );

          function setSearch(query: string) {{
            searchQuery.value = query;
            page.value = 1; // Reset to first page
          }}

          function setSort(key: keyof T, direction?: SortDirection) {{
            if (sortConfig.value?.key === key && !direction) {{
              // Toggle direction
              sortConfig.value.direction =
                sortConfig.value.direction === "asc" ? "desc" : "asc";
            }} else {{
              sortConfig.value = {{ key, direction: direction || "asc" }};
            }}
          }}

          function setFilter(key: string, value: unknown) {{
            activeFilters.value[key] = value;
            page.value = 1;
          }}

          function clearFilters() {{
            searchQuery.value = "";
            activeFilters.value = {{}};
            sortConfig.value = null;
            page.value = 1;
          }}

          return {{
            searchQuery,
            sortConfig,
            activeFilters,
            page,
            pageSize,
            filtered,
            sorted,
            paginated,
            totalPages,
            setSearch,
            setSort,
            setFilter,
            clearFilters,
          }};
        }}
    ''').strip()


def generate_actions_composable(component_name: str) -> str:
    """Generate an actions/handlers composable template."""
    return dedent(f'''
        /**
         * use{component_name}Actions - Event handlers and actions for {component_name}
         */
        import {{ ref }} from "vue";

        export function use{component_name}Actions() {{
          const isProcessing = ref(false);
          const lastAction = ref<string | null>(null);

          /**
           * Wrap an async action with loading state
           */
          async function withLoading<T>(
            action: () => Promise<T>,
            actionName?: string
          ): Promise<T | null> {{
            if (isProcessing.value) return null;

            isProcessing.value = true;
            lastAction.value = actionName || null;

            try {{
              return await action();
            }} finally {{
              isProcessing.value = false;
            }}
          }}

          /**
           * Debounce a function
           */
          function debounce<T extends (...args: unknown[]) => void>(
            fn: T,
            delay: number
          ): T {{
            let timeoutId: ReturnType<typeof setTimeout>;
            return ((...args: unknown[]) => {{
              clearTimeout(timeoutId);
              timeoutId = setTimeout(() => fn(...args), delay);
            }}) as T;
          }}

          /**
           * Throttle a function
           */
          function throttle<T extends (...args: unknown[]) => void>(
            fn: T,
            limit: number
          ): T {{
            let inThrottle = false;
            return ((...args: unknown[]) => {{
              if (!inThrottle) {{
                fn(...args);
                inThrottle = true;
                setTimeout(() => (inThrottle = false), limit);
              }}
            }}) as T;
          }}

          return {{
            isProcessing,
            lastAction,
            withLoading,
            debounce,
            throttle,
          }};
        }}
    ''').strip()


def generate_index_file(composable_names: list[str]) -> str:
    """Generate barrel export index.ts."""
    exports = '\n'.join(f'export * from "./{name}";' for name in sorted(composable_names))
    return dedent(f'''
        /**
         * Composables barrel export
         */
        {exports}
    ''').strip()


GENERATORS = {
    'heavy_state': ('State', generate_state_composable),
    'api_calls': ('Api', generate_api_composable),
    'export_functions': ('Export', generate_export_composable),
    'form_validation': ('Validation', generate_validation_composable),
    'filtering_sorting': ('Filters', generate_filters_composable),
    'many_handlers': ('Actions', generate_actions_composable),
}


def main():
    parser = argparse.ArgumentParser(
        description="Generate composable templates from Vue component",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("vue_file", type=Path, help="Path to Vue component file")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Output directory for composables")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be generated without writing files")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite existing files")

    args = parser.parse_args()

    if not args.vue_file.exists():
        print(f"Error: File {args.vue_file} does not exist", file=sys.stderr)
        sys.exit(1)

    # Extract component name
    component_name = args.vue_file.stem  # e.g., "MyComponent" from "MyComponent.vue"

    # Analyze patterns
    script = extract_script_content(args.vue_file)
    patterns = detect_patterns(script)

    detected = [p for p, found in patterns.items() if found]
    if not detected:
        print(f"No decomposition patterns detected in {args.vue_file}")
        sys.exit(0)

    print(f"Detected patterns: {', '.join(detected)}")
    print()

    # Generate composables
    generated_names = []
    for pattern in detected:
        if pattern not in GENERATORS:
            continue

        suffix, generator = GENERATORS[pattern]
        composable_name = f"use{component_name}{suffix}"
        filename = f"{composable_name}.ts"
        filepath = args.output_dir / filename

        content = generator(component_name)

        if args.dry_run:
            print(f"Would create: {filepath}")
            print("-" * 40)
            print(content[:500] + "..." if len(content) > 500 else content)
            print()
        else:
            if filepath.exists() and not args.force:
                print(f"Skipping {filepath} (already exists, use --force to overwrite)")
                continue

            args.output_dir.mkdir(parents=True, exist_ok=True)
            filepath.write_text(content, encoding='utf-8')
            print(f"Created: {filepath}")
            generated_names.append(composable_name)

    # Generate index.ts
    if generated_names and not args.dry_run:
        index_path = args.output_dir / "index.ts"
        if index_path.exists():
            # Append to existing
            existing = index_path.read_text(encoding='utf-8')
            for name in generated_names:
                export_line = f'export * from "./{name}";'
                if export_line not in existing:
                    existing += f'\n{export_line}'
            index_path.write_text(existing.strip() + '\n', encoding='utf-8')
            print(f"Updated: {index_path}")
        else:
            index_path.write_text(generate_index_file(generated_names) + '\n', encoding='utf-8')
            print(f"Created: {index_path}")


if __name__ == "__main__":
    main()
