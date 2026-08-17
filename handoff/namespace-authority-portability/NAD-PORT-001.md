# NAD-PORT-001 — durable closure

```text
NAD-PORT-001
STATUS: COMPLETE / VERIFIED ON main

Canonical suite pin:
14c15afca6c1e9c029a221ef97d2c46613dfb717

Source:
PR #273 squash merge (luthiers-toolbox)

Includes:
- portability parameterization
- #272 adapter hardening

Do not use:
d796cf95
e25c7390
a368652f
```

## Downstream (code-analysis-tool)

Authorized extraction is in draft PR **#26** (`cursor/namespace-authority-drift-adapter-6227`):

- Git-independent detector core
- `DetectorConfig` / portable configuration boundary
- topology / finding models required by the engine
- existing adjudication semantics and evidence behavior

Not vendored: Luthiers CLI, git/ref wrapper, repository-specific authority declarations, namespace bindings, or blocking policy.

Constitutional invariant preserved:

`missing namespace→domain binding → INSUFFICIENT_EVIDENCE`

Integration posture: **advisory only**.

No further Luthiers mutation is required for this thread.
