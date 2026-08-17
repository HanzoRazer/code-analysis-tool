# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each release section **must** include the following contract-axis declarations:

```
Schema: yes|no
Signals: yes|no
Rule registry: yes|no
Exit codes: yes|no
Confidence: yes|no
Web API: yes|no
Breaking: yes|no
```

When `Breaking: yes`, the release **must** bump the MAJOR version and at least
one contract axis must also be `yes`.

## [Unreleased]

Schema: no
Signals: no
Rule registry: no
Exit codes: no
Confidence: no
Web API: no
Breaking: no

- `context_pinned_hash` **1.1.0**: add `float_repr` axis (`CTX_PINNED_HASH_FLOAT_001`) for hashes over unquantized float serialisation (POS-007 / `json.dumps` + geometry floats); mitigation `floats_quantized` when `round` / precision format-specs are visible. The axis is scoped to the hashed payload, not the function: it fires only where a value reaches a hash (constructor, module-local wrapper, or `.update()`), through a call whose receiver resolves via this module's imports to a known text serialiser (`json`/`orjson`/`yaml`/… — never an opaque `serializer.dumps` or a binary `pickle`/`marshal`/`msgpack`), carrying float evidence in its own argument (division, float literal, `float`/`round`/`math.*`, or a `float` annotation) resolved one hop through local assignments. `Decimal` is not float evidence — it is the cure for this defect, not an instance of it — though it remains a mitigation signal. Serialisation that only reaches a log line, `json.dumps({"name": "x"})`, and an unrelated `round()` all stay silent
- `context_pinned_hash` **1.2.0**: two scope-precision fixes across all three axes. (a) `_is_lf_normalize` checked only the *searched* string, so `.replace(b'\r\n', b'')` — which deletes the line break rather than normalising it, leaving the hash just as context-pinned — was credited as `input_lf_normalized` and downgraded a live finding to LOW; both arguments are now checked, must agree in type, and a non-constant replacement is no longer credited. (b) Function scopes walked into nested `def` bodies while `_scan_module` also visits those bodies as scopes of their own, so a hash inside a nested function was reported twice under two different function names; scope walks now stop at `def` boundaries, leaving the two traversals exactly complementary. Lambdas and class bodies are deliberately not pruned — they are not scopes of their own here, so pruning would drop them from analysis rather than reattribute them. (c) Found while dogfooding (a) and (b) on this repo: local-name resolution was unbounded despite both docstrings claiming "one hop" — the `seen` set guaranteed termination but not relevance, so a four-name chain (`ids` → `reg` → `p` → `ROOT / meta["path"]`) reached a *pathlib* `/` and read it as float division, emitting a false `float_repr` on `tests/test_contracts_bundle_is_fresh.py`. Resolution is now capped at two bindings on each side (`_MAX_SERIALISER_HOPS`, `_MAX_EVIDENCE_HOPS`), which keeps the shapes that actually occur and drops the false positive. Self-scan on this repo: 38 → 37 findings, fixtures unchanged at 0

## [0.1.0] - 2025-01-01

Schema: no
Signals: no
Rule registry: no
Exit codes: no
Confidence: no
Web API: no
Breaking: no

- Initial release scaffold
- Engine v1, signals v2, confidence v1
- Core analyzers: copy-paste detection, dead code, complexity
- Contract test infrastructure with golden fixtures, translator policy, and logic manifests
- Schema governance: run_result, debt_snapshot, drift_budget_signal, signals_latest, user_event
- CI workflows: pytest, copy-lint, ratchet, rule-registry-sync
