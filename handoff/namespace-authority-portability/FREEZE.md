# Portability freeze (rebased onto main after #271)

| | Value |
|---|---|
| Luthiers base | `main` @ `114cef1ac25007d4a7d1a062576c2fff574a0b0b` (#271 merged) |
| Patch | `0ce251fb-portability-on-main.patch` |
| **Patch SHA256** | `a1aa3765a7317b50bb82a86e71e6c6664e6b39c1c99d6378af7f32e272c957fc` |
| Obsolete pin | `a368652f` — never pushed; do not use |

## Contained

- `DetectorConfig` + `analyze_namespace_authority_drift`
- Preserves #271 anti-inference guard / binding-gap semantics
- 38 tests; CBSP21 portability manifest

## Authoritative suite pin

**Not yet.** Suite pin = the SHA that appears on GitHub after a Luthiers-writable agent applies this patch and pushes. Report that SHA back.

Verify download:

```bash
echo "a1aa3765a7317b50bb82a86e71e6c6664e6b39c1c99d6378af7f32e272c957fc  0ce251fb-portability-on-main.patch" | sha256sum -c -
```
