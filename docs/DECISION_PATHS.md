# Decision Paths — code-analysis-tool

> Architectural decision record documenting available paths and chosen direction.
> Last updated: 2026-02-13

---

## Executive Summary

**Chosen Path**: Feature Depth → Dead Code Analyzer → Then Performance

```
                    ┌─────────────────────────────────────┐
                    │         code-analysis-tool          │
                    │    "Confidence Engine for Vibe      │
                    │           Coders"                   │
                    └──────────────┬──────────────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
   ┌─────────┐              ┌─────────────┐            ┌──────────┐
   │ PATH A  │              │   PATH B    │            │  PATH C  │
   │Parallel │              │Feature Depth│            │   SaaS   │
   │  Perf   │              │  (CHOSEN)   │            │  Scale   │
   └─────────┘              └─────────────┘            └──────────┘
```

---

## Decision Point 1: Next Priority After MVP

### Context
- Level 1 MVP complete (4 endpoints working)
- 6 analyzers implemented
- 2 analyzer types pre-wired but not implemented
- No parallelism or caching

### Options Evaluated

| Path | Description | Effort | User Value | Risk |
|------|-------------|--------|------------|------|
| **A. Parallel + Incremental** | ProcessPool scanning, mtime caching | 2-3 days | Performance (4-100x) | Low |
| **B. Feature Depth** | Dead code analyzer, security analyzer | 1-2 days | New capabilities | Low |
| **C. SaaS Scale** | Level 2 scaffold (auth, DB, services) | 3-5 days | Multi-user | Medium |

### Decision: **PATH B — Feature Depth**

**Rationale:**
1. Dead code detection is the #1 "rescue" question: "What can I delete?"
2. Infrastructure already pre-wired (enum, signal, translator)
3. Performance optimization is premature — feature set not complete
4. SaaS scale not needed until user validation

---

## Decision Point 2: Which Feature First

### Options Evaluated

| Feature | Pre-wired | Complexity | Rescue Value |
|---------|-----------|------------|--------------|
| **Dead Code Analyzer** | ✓ Full | Medium | HIGH — deletable code |
| **Security Analyzer** | ✓ Partial | High | Medium — vulnerabilities |
| **Dependency Analyzer** | ✗ None | Medium | Medium — outdated deps |

### Decision: **Dead Code Analyzer**

**Rationale:**
1. Fully pre-wired: `AnalyzerType.DEAD_CODE`, signal mapping, translator ready
2. Aligns with rescue tier philosophy: find things to remove
3. Lower complexity than security (no taint analysis needed)
4. Clear, actionable output for beginners

---

## Path Taken: Implementation Sequence

```
PHASE 1: MVP Foundation (COMPLETE)
──────────────────────────────────
✓ Core API (scan_project, governance_audit, detect_debt_patterns)
✓ Web API Level 1 (FastAPI scaffold)
✓ 4 Endpoints (/health, /scan, /scan/governance, /scan/debt)
✓ 6 Analyzers (complexity, duplication, exceptions, file_sizes, global_state, routers)
✓ Rescue Tier Tests (smell detection, extraction plans)
✓ Template Tier Tests (scaffold validation, migration tracking)
✓ Web API Tests (22 endpoint tests)

PHASE 2: Feature Depth (CURRENT)
────────────────────────────────
◯ Dead Code Analyzer (DC-UNUSED-IMPORT, DC-UNUSED-FUNC, etc.)
◯ Dead Code Tests + Golden Fixtures
◯ Wire into _DEFAULT_ANALYZERS
◯ Translator signal aggregation

PHASE 3: Risk Detection Depth (NEXT)
────────────────────────────────────
◯ Security Analyzer (SQL injection, command injection, etc.)
◯ Enhanced severity scoring
◯ Risk correlation across findings

PHASE 4: Performance (LATER)
────────────────────────────
◯ Parallel file processing (ProcessPoolExecutor)
◯ Incremental scanning (mtime + content hash)
◯ Result caching (SQLite fingerprint store)
◯ Batch API endpoint

PHASE 5: SaaS Scale (FUTURE)
────────────────────────────
◯ Level 2: Auth + DB + Services
◯ Level 3: Celery + Redis + Docker
◯ Multi-tenant support
```

---

## Paths NOT Taken (and why)

### Path A: Parallel + Incremental First

**What it would have delivered:**
- 4-100x speedup on large repos
- Incremental rescans in <1s

**Why deferred:**
- Optimization before feature completeness
- Users need capabilities before speed
- Can be added non-disruptively later

### Path C: SaaS Scale First

**What it would have delivered:**
- Multi-user auth (JWT)
- Persistent scan history (PostgreSQL)
- Background job processing (Celery)

**Why deferred:**
- No user validation yet
- Adds operational complexity
- MVP sufficient for single-user/CI use

### Security Analyzer Before Dead Code

**What it would have delivered:**
- SQL injection detection
- Command injection detection
- Hardcoded secrets detection

**Why deferred:**
- Higher implementation complexity (taint analysis)
- Dead code is more universally applicable
- Security can build on dead code analysis (unused imports = attack surface)

---

## Analyzer Implementation Status

```
┌─────────────────────────────────────────────────────────────────┐
│                    ANALYZER COVERAGE MAP                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  IMPLEMENTED (6)                 PRE-WIRED (2)                  │
│  ══════════════                  ════════════                   │
│                                                                 │
│  ┌─────────────┐                 ┌─────────────┐                │
│  │ complexity  │ CC scoring      │ dead_code   │ ← NEXT         │
│  └─────────────┘                 └─────────────┘                │
│  ┌─────────────┐                 ┌─────────────┐                │
│  │ duplication │ Clone detect    │ security    │ ← PHASE 3      │
│  └─────────────┘                 └─────────────┘                │
│  ┌─────────────┐                                                │
│  │ exceptions  │ Bare except                                    │
│  └─────────────┘                                                │
│  ┌─────────────┐                                                │
│  │ file_sizes  │ Large files                                    │
│  └─────────────┘                                                │
│  ┌─────────────┐                                                │
│  │global_state │ Mutable state   (CAT-0021 COMPLETE)            │
│  └─────────────┘                                                │
│  ┌─────────────┐                                                │
│  │  routers    │ FastAPI routes                                 │
│  └─────────────┘                                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Dead Code Analyzer Specification

### Scope (when implemented)

| Rule ID | Detection | Severity | Confidence |
|---------|-----------|----------|------------|
| DC-UNUSED-IMPORT-001 | Imported symbol never referenced | LOW | 0.95 |
| DC-UNUSED-FUNC-001 | Function defined but never called | MEDIUM | 0.80 |
| DC-UNUSED-CLASS-001 | Class defined but never instantiated | MEDIUM | 0.75 |
| DC-UNUSED-VAR-001 | Variable assigned but never read | LOW | 0.85 |
| DC-UNREACHABLE-001 | Code after return/raise/break/continue | HIGH | 0.98 |

### Limitations (known)

1. **Cross-module calls**: Won't detect calls from other packages
2. **Dynamic usage**: `getattr()`, `__import__()` can hide references
3. **Test coverage**: Test files may reference "unused" code
4. **Framework magic**: Django/Flask decorators may register routes

### Signal Aggregation

```python
{
    "signal_id": "signal.dead_code",
    "evidence": {
        "summary": {
            "unused_import_count": 12,
            "unused_function_count": 3,
            "unused_class_count": 1,
            "unused_variable_count": 8,
            "unreachable_code_count": 2
        },
        "top_items": [...]
    }
}
```

---

## Risk Assessment

### Current Risk Level: LOW

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Dead code false positives | Medium | Low | Document limitations, confidence scoring |
| Feature creep | Low | Medium | Strict scope, defer enhancements |
| Performance regression | Low | Low | Benchmark before/after |

---

## Success Criteria for Phase 2

1. **Dead Code Analyzer functional**
   - All 5 rule types detecting correctly
   - Wired into `_DEFAULT_ANALYZERS`
   - Signal aggregation working

2. **Test coverage**
   - Unit tests for each rule type
   - Golden fixture repos (dead_code_hot, dead_code_clean)
   - Integration with scan_project()

3. **Documentation**
   - Rule descriptions in code
   - Limitations documented
   - Example output in README

---

## Appendix: Decision Log

| Date | Decision | Alternatives Considered | Outcome |
|------|----------|------------------------|---------|
| 2026-02-13 | Prioritize feature depth over performance | Parallel scanning, SaaS scale | Dead code analyzer chosen |
| 2026-02-13 | Dead code before security | Security analyzer | Lower complexity, higher rescue value |
| 2026-02-13 | Document paths before implementation | Jump straight to code | Created DECISION_PATHS.md |

---

*This document will be updated as decisions are made and paths are taken.*
