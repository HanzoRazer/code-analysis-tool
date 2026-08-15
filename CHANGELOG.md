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

- `context_pinned_hash` **1.1.0**: add `float_repr` axis (`CTX_PINNED_HASH_FLOAT_001`) for hashes over unquantized float serialisation (POS-007 / `json.dumps` + geometry floats); mitigation `floats_quantized` when `round` / precision format-specs are visible. The axis is payload-scoped: a serialiser only fires when its own argument carries float evidence (division, float literal, `float`/`round`/`Decimal`/`math.*`, or a `float` annotation) resolved one hop through local assignments, so `json.dumps({"name": "x"})` and binary `pickle.dumps` stay silent and an unrelated `round()` cannot downgrade a finding

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
