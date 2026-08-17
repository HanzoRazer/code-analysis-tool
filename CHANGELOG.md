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
Confidence: yes
Web API: no
Breaking: no

- `namespace_authority_drift` **0.1.0** (advisory): vendor Git-independent namespace-authority engine from `luthiers-toolbox@14c15afca6c1e9c029a221ef97d2c46613dfb717` (#273) plus suite adapter. Observes declared authority only (`INSUFFICIENT_EVIDENCE` when unbound; never invents namespace→domain bindings). Silent without review context; suite severity capped at LOW. Activation via `NamespaceAuthorityDriftAnalyzer(review_context=...)` or `scan_project(namespace_authority_context=...)`. Confidence golden/policy manifests refreshed for the new `AnalyzerType` enum member (closure-only; scoring weights unchanged).
- `context_pinned_hash` **1.1.0**: add `float_repr` axis (`CTX_PINNED_HASH_FLOAT_001`) for hashes over unquantized float serialisation (POS-007 / `json.dumps` + geometry floats); mitigation `floats_quantized` when `round` / precision format-specs are visible. The axis is scoped to the hashed payload, not the function: it fires only where a value reaches a hash (constructor, module-local wrapper, or `.update()`), through a call whose receiver resolves via this module's imports to a known text serialiser (`json`/`orjson`/`yaml`/… — never an opaque `serializer.dumps` or a binary `pickle`/`marshal`/`msgpack`), carrying float evidence in its own argument (division, float literal, `float`/`round`/`math.*`, or a `float` annotation) resolved one hop through local assignments. `Decimal` is not float evidence — it is the cure for this defect, not an instance of it — though it remains a mitigation signal. Serialisation that only reaches a log line, `json.dumps({"name": "x"})`, and an unrelated `round()` all stay silent

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
