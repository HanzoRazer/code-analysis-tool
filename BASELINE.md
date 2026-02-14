# Baseline and Ratchet

This repo uses a **ratchet** CI gate to prevent introducing new *structural* debt.

## What is the baseline?

`baselines/main.json` is the committed baseline artifact.

It is produced by:

```bash
code-audit debt snapshot . --ci --out baselines/main.json
```

The baseline is validated in CI against `schemas/debt_snapshot.schema.json`.

## What does the ratchet do?

CI creates a deterministic snapshot for the PR and compares it against the baseline:

```bash
code-audit debt snapshot . --ci --out artifacts/current.json
code-audit debt compare . --baseline baselines/main.json --current artifacts/current.json --ci
```

- Exit **0**: no new debt introduced
- Exit **1**: new debt introduced (PR blocked)
- Exit **2**: usage/runtime error

## Refreshing the baseline

Baseline updates are a deliberate PR action.

Use the helper script:

```bash
python scripts/refresh_baseline.py
```

Then commit the updated `baselines/main.json` with an explanation of why the baseline moved.
