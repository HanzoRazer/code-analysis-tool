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

## Acquisition and cleanup contract

PR-CLEAN-001 reuses the PR-SCAN v1 acquisition contract (`code_audit.pr_scan`):

- the assessment is validated **before** any Git activity;
- the exact PR head and the exact captured base commit are fetched into
  private per-run refs (`refs/code-audit/run/<token>/…`) and their SHAs
  verified; the caller's branches, remote-tracking refs and `FETCH_HEAD`
  are never touched;
- head and base are scanned in temporary detached worktrees;
- both worktree registrations and all private refs are removed and the
  removal is **verified**. An unverified cleanup fails the run (exit 2)
  instead of producing a report, and a primary failure carries any cleanup
  failure as an exception note rather than hiding it;
- `--pr-scope-manifest` must resolve (symlinks included) inside the PR head;
- `--timeout` must be finite and > 0.

The report's `execution` block states this explicitly
(`source_files_modified: false`, `caller_checkout_mutated: false`,
`git_admin_metadata.temporarily_modified: true`, `cleanup.verified: true`)
in place of a single `mutations_performed` flag.

### Open question: base commit vs. merge-base

`base_sha` is GitHub's `baseRefOid`, i.e. the base branch tip when the PR
was resolved. If the base branch advanced after the PR branched, comparing
head against that tip (rather than against the merge-base) can mislabel a
finding as `pr_introduced` when the base merely fixed it later, and
`changed_files` can include base-side changes. Whether to compare against
the merge-base is a semantic decision deferred to review; the current
behaviour is the documented "exact recorded base SHA".

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
