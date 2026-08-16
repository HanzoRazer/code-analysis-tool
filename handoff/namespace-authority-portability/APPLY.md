# Apply portability freeze onto luthiers-toolbox

**Do not integrate from `d796cf95`.** Suite pin becomes authoritative only after this lands on the remote branch.

Expected base HEAD: `e25c73905e64440f4f92cee694ad7c6fb388df8a`
Expected after am:  `a368652fb0fb0b6fe41117834c61c2bc2c9757e8`

```bash
cd /path/to/luthiers-toolbox
git fetch origin
git checkout feat/namespace-authority-drift-detector
git pull --ff-only origin feat/namespace-authority-drift-detector
git rev-parse HEAD   # must be e25c7390…

curl -fsSL -o /tmp/a368652f.portability.patch \
  https://raw.githubusercontent.com/HanzoRazer/code-analysis-tool/cursor/ns-auth-portability-patch-handoff-6227/handoff/namespace-authority-portability/a368652f-portability-on-e25c7390.patch

git am /tmp/a368652f.portability.patch
git rev-parse HEAD   # expect a368652f…
git push origin feat/namespace-authority-drift-detector
```

PR #271 stays DRAFT / HOLD / DO NOT MERGE.
Delete this handoff branch/folder after the freeze SHA is visible on luthiers remote.
