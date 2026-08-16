# Apply portability freeze onto luthiers-toolbox

**Do not integrate from `d796cf95`.** The suite freeze pin becomes authoritative only after commit `a368652f…` is visible on the Luthiers remote branch.

| | Value |
|---|---|
| Target branch | `feat/namespace-authority-drift-detector` |
| Required base HEAD | `e25c73905e64440f4f92cee694ad7c6fb388df8a` |
| Expected HEAD after `git am` | `a368652fb0fb0b6fe41117834c61c2bc2c9757e8` |
| Patch file | `a368652f-portability-on-e25c7390.patch` |
| Patch SHA256 | `7148a5828c49fed4e5d167e9a94776f2d849d9601419c2584675366a2b8cf07d` |
| Luthiers PR | [#271](https://github.com/HanzoRazer/luthiers-toolbox/pull/271) — stays **DRAFT / HOLD / DO NOT MERGE** |

## Preferred fetch (immutable release asset)

Prefer the GitHub Release asset — it survives handoff-branch cleanup:

https://github.com/HanzoRazer/code-analysis-tool/releases/download/handoff-ns-auth-portability-a368652f/a368652f-portability-on-e25c7390.patch

Release page: https://github.com/HanzoRazer/code-analysis-tool/releases/tag/handoff-ns-auth-portability-a368652f

Branch-hosted raw URL (fallback only; invalidated when this handoff branch is deleted):

https://raw.githubusercontent.com/HanzoRazer/code-analysis-tool/cursor/ns-auth-portability-patch-handoff-6227/handoff/namespace-authority-portability/a368652f-portability-on-e25c7390.patch

## Operator sequence

```bash
cd /path/to/luthiers-toolbox
git fetch origin
git checkout feat/namespace-authority-drift-detector
git pull --ff-only origin feat/namespace-authority-drift-detector
test "$(git rev-parse HEAD)" = "e25c73905e64440f4f92cee694ad7c6fb388df8a"

curl -fsSL -o /tmp/a368652f.portability.patch \
  https://github.com/HanzoRazer/code-analysis-tool/releases/download/handoff-ns-auth-portability-a368652f/a368652f-portability-on-e25c7390.patch

# Verify you fetched the intended artifact (required)
echo "7148a5828c49fed4e5d167e9a94776f2d849d9601419c2584675366a2b8cf07d  /tmp/a368652f.portability.patch" \
  | sha256sum -c -

git am /tmp/a368652f.portability.patch
test "$(git rev-parse HEAD)" = "a368652fb0fb0b6fe41117834c61c2bc2c9757e8"

git push origin feat/namespace-authority-drift-detector

# Confirm GitHub has the object (authoritative for suite pin)
gh api repos/HanzoRazer/luthiers-toolbox/commits/a368652fb0fb0b6fe41117834c61c2bc2c9757e8 --jq .sha
```

## Cleanup sequence (do this only after success)

Delete this handoff branch / PR **only after** all of the following are true:

1. GitHub returns commit `a368652fb0fb0b6fe41117834c61c2bc2c9757e8` (not 422).
2. `feat/namespace-authority-drift-detector` tip equals that SHA (PR #271 `headRefOid` matches).
3. The suite agent (or operator) has acknowledged the freeze pin is now authoritative.

Then:

1. Close / delete draft handoff PR [#24](https://github.com/HanzoRazer/code-analysis-tool/pull/24).
2. Delete branch `cursor/ns-auth-portability-patch-handoff-6227`.
3. Delete prerelease tag/release `handoff-ns-auth-portability-a368652f` (optional once Luthiers history holds the commit; keep longer if you want the checksummed artifact retained).

Do **not** delete the handoff branch or release while operators may still need to re-fetch the patch, and do **not** treat `a368652f` as the suite freeze pin until it is visible on the Luthiers remote.
