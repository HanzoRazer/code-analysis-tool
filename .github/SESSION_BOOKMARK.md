# Session Bookmark — 2026-02-11

> **Purpose:** snapshot of project state for session continuity after system reset.

---

## Commit lineage

| Commit | Description |
|--------|-------------|
| `80e8ccb` | Initial build: governance, schemas, i18n, copy linters, CI, 26 tests |
| *(this commit)* | Scan CLI pipeline + functional pipeline + three-rule exceptions + evidence ordering |

## What exists (35 tests, all green)

### Engine (`src/code_audit/`)

| Module | Role |
|--------|------|
| `model/` | `AnalyzerType`, `Severity`, `RiskLevel`, `Finding`, `RunResult` dataclass |
| `analyzers/complexity.py` | Cyclomatic complexity (class-based) |
| `analyzers/exceptions.py` | Broad/bare/swallowed exceptions (class-based + functional `analyze_exceptions()`) |
| `core/discover.py` | `*.py` file discovery with exclusion patterns |
| `core/runner.py` | Class-based pipeline: `run_scan()` → `RunResult` |
| `insights/confidence.py` | Class-based confidence scorer |
| `insights/translator.py` | Class-based finding → signal translator |
| `run_result.py` | **Functional pipeline**: `build_run_result()` — monolithic, dict-based |
| `__main__.py` | CLI: `python -m code_audit <path>` + `scan` subcommand |

### Three exception rules (functional pipeline)

| Rule ID | Trigger | Severity |
|---------|---------|----------|
| `EXC_SWALLOW_001` | Broad catch + no raise + no logging | critical/high |
| `EXC_BROAD_LOGGED_001` | Broad catch + logging + no raise | medium/low |
| `EXC_BROAD_001` | Broad catch (generic/other) | high/medium |

### Schemas

- `run_result.schema.json` — draft 2020-12, `evidence.summary` with `swallowed_count`/`logged_count`
- `signals_latest.schema.json` — exists but **nothing emits it yet**
- `user_event.schema.json` — exists, no consumer

### CI

- `.github/workflows/pytest.yml` — runs on push to main + PRs
- `.github/workflows/copy-lint.yml` — runs on i18n/copy changes

### Exit codes

- `0` = green (score ≥ 75)
- `1` = yellow (score 55–74)
- `2` = red (score < 55)

---

## Two pipelines (divergent — convergence needed)

| Feature | Functional (`build_run_result`) | Class-based (`run_scan → RunResult`) |
|---------|--------------------------------|--------------------------------------|
| Rule-aware confidence | ✅ Three-tier penalties | ❌ Flat severity-based |
| Evidence ordering | ✅ Swallowed-first | ❌ Insertion order |
| Evidence summary | ✅ `swallowed_count`/`logged_count` | ✅ Added (but no rule awareness) |
| Signal builder | Self-contained `_build_signals_snapshot` | Delegates to `translator.py` |

---

## Open decisions (need developer input)

### Already recommended — awaiting confirmation

1. **`signals_latest.json` in v1?** → Recommend: yes, behind `--emit-signals` flag
2. **v1 signal set** → Recommend: `complexity` + `exceptions` only (other 4 declared-but-disabled)
3. **Compounds** → Recommend: skip in v1
4. **Canonical pipeline** → Recommend: functional; `RunResult` becomes a thin wrapper
5. **Version bump policy** → Recommend: signal_logic bumps when fixture outputs change; engine bumps on implementation changes

### Blocking work

6. **Fixtures needed** — only 1 exists (`sample_repo_exceptions/`). Need 3–5 covering all exit codes + both analyzers. Can be built synthetically.
7. **Ruff config** — dev dep exists, no `[tool.ruff]` config, CI doesn't run it. Recommend `E,F,I,UP,B`.

---

## Immediate next steps (post-reset)

1. **Get developer answers** to items 1–5 above (or accept defaults)
2. **Converge pipelines** — make `run_scan()` delegate to `build_run_result()`
3. **Build synthetic fixtures** — `clean_project/`, `complexity_hot/`, `mixed_severity/`
4. **Add ruff config** to pyproject.toml + CI
5. **Add `--emit-signals` flag** to scan subcommand

---

## Runtime

- Python `>=3.11` (CI tests on 3.11)
- **Stdlib-only at runtime** — no external dependencies
- Dev deps: `pytest>=7.0`, `jsonschema>=4.0`, `ruff>=0.4.0`
- Venv: `C:/Users/thepr/Downloads/code-analysis-tool/.venv/`

## Test command

```powershell
$env:PYTHONPATH = "C:\Users\thepr\Downloads\code-analysis-tool\repo\src"
C:\Users\thepr\Downloads\code-analysis-tool\.venv\Scripts\python.exe -m pytest . -v
```
