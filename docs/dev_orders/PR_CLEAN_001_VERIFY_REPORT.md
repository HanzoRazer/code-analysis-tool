# PR-CLEAN-001 — Verify and Report Only

## Status

Experimental scaffold. **No repair execution. No merge decision.**

## Purpose

Given a pull request and an external assessment (for example, Copilot review
findings), independently test the assessment against the repository's existing
code-analysis suite and distinguish:

1. findings reproduced on the PR head but not the base (`pr_introduced`),
2. findings reproduced on both base and head (`pre_existing`),
3. claims not reproduced by the suite (`unsupported_by_tool`), and
4. claims that cannot be safely adjudicated mechanically (`needs_human_decision`).

The assessment is evidence, not authority.

## Non-goals / frozen boundary

PR-CLEAN-001 MUST NOT:

- edit source files,
- generate or apply repair patches,
- push commits,
- comment/review on the target PR,
- resolve review threads,
- approve or merge a PR,
- weaken tests, contracts, or gates,
- infer that green tests make an architectural approach correct,
- turn an unsupported external claim into a confirmed defect by textual guess.

`merge_worthy` is therefore explicitly `null` in the report.

## Assessment input

JSON contract (scaffold form):

```json
{
  "schema_version": "pr_clean_assessment_v1",
  "source": "copilot",
  "claims": [
    {
      "claim_id": "C01",
      "summary": "Unsafe fallback can silently succeed",
      "rule_id": "EXAMPLE_RULE_001",
      "path": "src/example.py",
      "line": 117,
      "severity": "high",
      "evidence": "Optional source-review text"
    }
  ]
}
```

Only `claim_id`, `summary`, and the envelope fields are required. A `rule_id`
is required for automatic tool verification. A claim without a rule ID is sent
to human adjudication; PR-CLEAN-001 does not invent a mapping from prose to a
rule.

## Invocation

```bash
python -m code_audit.pr_clean 296 \
  --repo-root . \
  --assessment copilot_assessment.json \
  --json
```

Optional existing PR-scope enforcement:

```bash
python -m code_audit.pr_clean 296 \
  --repo-root . \
  --assessment copilot_assessment.json \
  --pr-scope-manifest path/inside/pr/to/patch_input_v2.json \
  --json
```

## Verification semantics

The tool scans the exact PR head and exact recorded base SHA independently.
For claims with a suite `rule_id`, rule/path matches are compared between the
two scans. Fingerprint identity is used when available.

The algorithm is intentionally conservative. If the same rule/path appears on
base but finding identity changes, the claim is routed to human adjudication
instead of being called PR-introduced.

Claims without an independently checkable rule ID are also routed to human
adjudication. This is intentional: review prose is not executable authority.

## Repair plan semantics

`repair_plan` is a list of *human repair candidates*. Every entry contains
`automatic_apply: false`. It is a plan/report, not a patch queue.

## Exit posture

Successful report generation exits zero regardless of findings. This increment
introduces no blocking policy.

## Deferred work

PR-CLEAN-002 through PR-CLEAN-004 are explicitly deferred. They would cover
transactional mechanical repair, whole-PR qualification, and GitHub workflow
integration respectively. They require a separate authorization after
PR-CLEAN-001 has demonstrated value and failure modes on real PRs.
