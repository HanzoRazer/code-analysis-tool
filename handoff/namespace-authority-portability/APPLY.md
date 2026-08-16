# Apply portability follow-up onto luthiers-toolbox `main`

## Status change (read first)

PR **#271 MERGED** to `main` at `114cef1ac25007d4a7d1a062576c2fff574a0b0b` **without** the portability commit.

- `a368652f…` was never pushed and is **obsolete** as a freeze pin (it was based on pre-merge branch tip `e25c7390`).
- This handoff replaces it with a **portability-only** patch that applies cleanly onto current `main`.

| | Value |
|---|---|
| Required base HEAD | `114cef1ac25007d4a7d1a062576c2fff574a0b0b` (`main` after #271) |
| Patch file | `0ce251fb-portability-on-main.patch` |
| Patch SHA256 | `a1aa3765a7317b50bb82a86e71e6c6664e6b39c1c99d6378af7f32e272c957fc` |
| Expected after apply | `DetectorConfig` + `analyze_namespace_authority_drift` present; **38** governance tests green; parent of new commit is `114cef1a…` |
| Luthiers PR | Open a **new** draft PR for this follow-up (do not reopen #271). Hold / do not merge until triage. |

## Preferred fetch (immutable release asset)

After this update is published, prefer:

`https://github.com/HanzoRazer/code-analysis-tool/releases/download/handoff-ns-auth-portability-on-main/0ce251fb-portability-on-main.patch`

(Branch raw URL is fallback only.)

## Operator sequence

```bash
cd /path/to/luthiers-toolbox
git fetch origin
git checkout main
git pull --ff-only origin main
test "$(git rev-parse HEAD)" = "114cef1ac25007d4a7d1a062576c2fff574a0b0b"

curl -fsSL -o /tmp/portability-on-main.patch \
  https://github.com/HanzoRazer/code-analysis-tool/releases/download/handoff-ns-auth-portability-on-main/0ce251fb-portability-on-main.patch
curl -fsSL -o /tmp/SHA256SUMS \
  https://github.com/HanzoRazer/code-analysis-tool/releases/download/handoff-ns-auth-portability-on-main/SHA256SUMS

cd /tmp && sha256sum -c SHA256SUMS

cd /path/to/luthiers-toolbox
git checkout -b feat/namespace-authority-drift-portability
git am /tmp/portability-on-main.patch
test "$(git rev-parse HEAD^)" = "114cef1ac25007d4a7d1a062576c2fff574a0b0b"
rg -n 'class DetectorConfig|def analyze_namespace_authority_drift' scripts/governance/check_namespace_authority_drift.py
python3 -m pytest tests/governance/test_namespace_authority_drift.py -q

git push -u origin feat/namespace-authority-drift-portability
# open DRAFT PR into main; report the pushed HEAD SHA — that becomes the suite freeze pin
```

## Cleanup sequence

Delete this handoff branch/PR (#24) and related releases **only after**:

1. A Luthiers commit containing this portability change is **visible on GitHub** (API 200 for that SHA).
2. That commit’s parent is `114cef1a…` (or a later main that still contains #271).
3. The suite agent acknowledges the new freeze SHA.

Then close/delete #24, delete `cursor/ns-auth-portability-patch-handoff-6227`, and delete obsolete releases:
- `handoff-ns-auth-portability-a368652f` (superseded)
- `handoff-ns-auth-portability-on-main` (after Luthiers has the commit)

Do **not** pin the suite to `a368652f`.
