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
