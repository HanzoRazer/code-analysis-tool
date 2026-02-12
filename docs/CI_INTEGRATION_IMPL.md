# CI Integration Implementation Guide

**Status:** Ready for implementation
**Based on:** Corrected Integration Packet (Contract-Aligned)

---

## Required Changes

### 1. CLI Args Update (`__main__.py` lines 452-494)

**debt snapshot** — add `--out` and `--ci`:
```python
debt_snap_p.add_argument(
    "--name",
    required=False,  # Changed from True
    default=None,
    help="Snapshot name. Required unless --out is used.",
)
debt_snap_p.add_argument(
    "--out",
    dest="snapshot_out",
    type=Path,
    default=None,
    help="Write snapshot to FILE (CI-friendly, bypasses registry).",
)
debt_snap_p.add_argument(
    "--ci",
    dest="ci_mode",
    action="store_true",
    default=False,
    help="Deterministic mode: fixed timestamps, sorted output.",
)
```

**debt compare** — add `--current` and `--ci`:
```python
debt_cmp_p.add_argument(
    "--baseline",
    required=True,
    help="Baseline: snapshot name or path to JSON file.",  # Updated help
)
debt_cmp_p.add_argument(
    "--current",
    dest="current_file",
    type=Path,
    default=None,
    help="Current snapshot file. If omitted, scans debt_path live.",
)
debt_cmp_p.add_argument(
    "--ci",
    dest="ci_mode",
    action="store_true",
    default=False,
    help="Deterministic mode: stable output ordering.",
)
```

---

### 2. Handler Update: `_handle_debt` snapshot section (~line 1241)

Replace:
```python
if args.debt_command == "snapshot":
    from code_audit.strangler.debt_registry import DebtRegistry

    debt_items = detector.detect(target, files)
    reg_dir = args.registry_dir or (target / ".debt_snapshots")
    registry = DebtRegistry(reg_dir)
    path = registry.save_snapshot(args.name, debt_items)
    print(f"Snapshot '{args.name}' saved ({len(debt_items)} items) → {path}", file=sys.stderr)
    return 0
```

With:
```python
if args.debt_command == "snapshot":
    from code_audit.strangler.debt_registry import DebtRegistry
    from datetime import datetime, timezone

    # Validate: need either --name or --out
    if not args.name and not getattr(args, "snapshot_out", None):
        print("error: --name or --out required for snapshot", file=sys.stderr)
        return 2

    debt_items = detector.detect(target, files)
    # Sort for determinism
    debt_items = sorted(debt_items, key=lambda d: (d.path, d.line_start, d.symbol))

    # --out mode: write directly to file (CI-friendly)
    if getattr(args, "snapshot_out", None):
        out_path: Path = args.snapshot_out
        out_path.parent.mkdir(parents=True, exist_ok=True)
        ts = "2000-01-01T00:00:00+00:00" if getattr(args, "ci_mode", False) else datetime.now(timezone.utc).isoformat()
        data = {
            "schema_version": "debt_snapshot_v1",
            "created_at": ts,
            "debt_count": len(debt_items),
            "items": [d.to_dict() for d in debt_items],
        }
        out_path.write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")
        print(f"Snapshot written ({len(debt_items)} items) → {out_path}", file=sys.stderr)
        return 0

    # Registry mode (original behavior)
    reg_dir = args.registry_dir or (target / ".debt_snapshots")
    registry = DebtRegistry(reg_dir)
    path = registry.save_snapshot(args.name, debt_items)
    print(f"Snapshot '{args.name}' saved ({len(debt_items)} items) → {path}", file=sys.stderr)
    return 0
```

---

### 3. Handler Update: `_handle_debt` compare section (~line 1254)

Add file-based loading before registry fallback:
```python
if args.debt_command == "compare":
    from code_audit.strangler.debt_registry import DebtRegistry
    from code_audit.model.debt_instance import DebtInstance, DebtType, make_debt_fingerprint

    # Load baseline (file path or registry name)
    baseline_path = Path(args.baseline)
    if baseline_path.exists() and baseline_path.is_file():
        # Load from file directly
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
        baseline_items = [
            DebtInstance(
                debt_type=DebtType(raw["debt_type"]),
                path=raw["path"],
                symbol=raw["symbol"],
                line_start=raw["line_start"],
                line_end=raw["line_end"],
                metrics=raw.get("metrics", {}),
                strategy=raw.get("strategy", ""),
                fingerprint=raw.get("fingerprint", make_debt_fingerprint(raw["debt_type"], raw["path"], raw["symbol"])),
            )
            for raw in data.get("items", [])
        ]
    else:
        # Load from registry
        reg_dir = args.registry_dir or (target / ".debt_snapshots")
        registry = DebtRegistry(reg_dir)
        try:
            baseline_items = registry.load_snapshot(args.baseline)
        except FileNotFoundError:
            print(f"error: baseline snapshot '{args.baseline}' not found", file=sys.stderr)
            return 2

    # Load current (file or live scan)
    if getattr(args, "current_file", None):
        data = json.loads(args.current_file.read_text(encoding="utf-8"))
        debt_items = [
            DebtInstance(
                debt_type=DebtType(raw["debt_type"]),
                path=raw["path"],
                symbol=raw["symbol"],
                line_start=raw["line_start"],
                line_end=raw["line_end"],
                metrics=raw.get("metrics", {}),
                strategy=raw.get("strategy", ""),
                fingerprint=raw.get("fingerprint", make_debt_fingerprint(raw["debt_type"], raw["path"], raw["symbol"])),
            )
            for raw in data.get("items", [])
        ]
    else:
        debt_items = detector.detect(target, files)

    diff = DebtRegistry.compare(baseline_items, debt_items)
    # ... rest unchanged
```

---

## CI Workflow (After Implementation)

```yaml
jobs:
  debt-ratchet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Create deterministic snapshot
        run: |
          mkdir -p artifacts
          code-audit debt snapshot . --ci --out artifacts/current.json

      - name: Compare against baseline
        run: |
          code-audit debt compare . \
            --baseline baselines/main.json \
            --current artifacts/current.json \
            --ci
```

---

## Exit Code Contract

| Code | Meaning |
|------|---------|
| 0 | Success (no new debt) |
| 1 | New debt introduced (ratchet violation) |
| 2 | Usage/runtime error |

---

## Determinism Guarantees (--ci mode)

- Timestamps: Fixed to `2000-01-01T00:00:00+00:00`
- Paths: Sorted, repo-relative, POSIX normalized
- Items: Sorted by (path, line_start, symbol)
- No random IDs or environment-dependent values

---

## Test Cases Required

1. `debt snapshot --out FILE` writes to FILE
2. `debt snapshot --ci --out FILE` has fixed timestamp
3. `debt compare --baseline FILE --current FILE` compares two files
4. `debt compare --baseline name` falls back to registry
5. Same repo → two --ci runs → identical JSON
