# Namespace-authority detector portability freeze (rebased)

| | Value |
|---|---|
| Luthiers branch | `feat/namespace-authority-drift-detector` |
| Required base (remote tip before apply) | `e25c73905e64440f4f92cee694ad7c6fb388df8a` |
| **Freeze SHA after apply** | `a368652fb0fb0b6fe41117834c61c2bc2c9757e8` |
| Supersedes (unpushed) | `cf72ee4d` (rebase onto anti-inference + CBSP21 fixes) |
| Patch file | `a368652f-portability-on-e25c7390.patch` |
| **Patch SHA256** | `7148a5828c49fed4e5d167e9a94776f2d849d9601419c2584675366a2b8cf07d` |

## Contained

- `DetectorConfig` portability + `analyze_namespace_authority_drift`
- Preserves anti-inference guard + `NAMESPACE_BINDING_GAP.md` from `8024c371` / `e25c7390`
- 38 tests passed; retopo dogfood OK; CBSP21 PASS

## Artifact locations

1. **Preferred (immutable release asset):**  
   https://github.com/HanzoRazer/code-analysis-tool/releases/download/handoff-ns-auth-portability-a368652f/a368652f-portability-on-e25c7390.patch
2. Fallback (branch-hosted; invalidated by handoff cleanup): see `APPLY.md`

Verify after download:

```bash
echo "7148a5828c49fed4e5d167e9a94776f2d849d9601419c2584675366a2b8cf07d  /path/to/a368652f-portability-on-e25c7390.patch" \
  | sha256sum -c -
```

## Apply / cleanup

Follow `APPLY.md` end-to-end. Summary:

- Apply only onto `e25c7390`; expect `a368652f` after `git am` + push.
- Suite pin is **not** authoritative until GitHub returns that SHA on the Luthiers branch.
- **Delete this handoff branch/PR only after** the target branch visibly contains commit `a368652fb0fb0b6fe41117834c61c2bc2c9757e8` on GitHub.
