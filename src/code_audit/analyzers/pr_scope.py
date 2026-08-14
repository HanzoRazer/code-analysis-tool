"""Review-time analyzer for PR scope contamination and merge-base drift.

This analyzer is intentionally silent in the ordinary source sweep. A caller
must provide a CBSP21 ``patch_input_v2`` manifest; the analyzer then compares
the committed Git diff against the declared scope and verifies the immutable
base commit the manifest pins.

Two activation styles, both supported:

* ``PrScopeAnalyzer(manifest=...)`` — the review gate, used by
  ``code_audit.api.check_pr_scope`` and the ``pr-scope`` CLI subcommand.
* ``PrScopeAnalyzer(review_context=ReviewContext(...))`` — the same check run
  inside an ordinary scan via ``scan_project(pr_scope_manifest=...)``.

Every failure mode is a *finding*, never an exception: an exception escaping
``run()`` aborts the scan, which is exactly the silent pass this detector
exists to prevent. States where the check cannot be performed at all are
CRITICAL; genuine scope violations are HIGH/MEDIUM.

Acceptance contract: ``cbsp21/pr_scope_acceptance.json``.
"""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import json
from pathlib import Path
import re
import subprocess
from typing import Any

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_SCHEMA_VERSION = "cbsp21_patch_manifest_v2"

# Acceptance-contract floor (cbsp21/pr_scope_acceptance.json →
# "coverage_below_95"). scope.min_coverage_percent may raise this bar but never
# lower it — see _effective_threshold().
_CONTRACT_FLOOR = 0.95

# git diff --name-status records that carry two paths (source + destination).
_TWO_PATH_STATUS = frozenset({"R", "C"})


@dataclass(frozen=True, slots=True)
class ReviewContext:
    """Activates pr_scope enforcement inside an ordinary scan.

    Deliberately carries no changed-files / merge-base injection hooks: the
    detector's whole value is that it reads the real Git surface, and a caller
    able to hand it a synthetic diff could manufacture a clean pass.
    """

    manifest_path: str | Path
    base_ref: str | None = None
    head_ref: str | None = None


@dataclass(frozen=True, slots=True)
class _GitResult:
    returncode: int
    stdout: str
    stderr: str
    failure_rule: str = ""


@dataclass(frozen=True, slots=True)
class _ResolvedRefs:
    base: str
    head: str
    pinned_base: str
    merge_base: str


def _git(root: Path, timeout: float, *args: str) -> _GitResult:
    """Run Git without a shell and turn process failures into data."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return _GitResult(127, "", "git executable was not found", "pr_scope.git_unavailable")
    except subprocess.TimeoutExpired:
        return _GitResult(
            124,
            "",
            f"git command timed out after {timeout:g}s",
            "pr_scope.git_timeout",
        )
    except OSError as exc:
        return _GitResult(126, "", str(exc), "pr_scope.git_failed")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    # Paths and SHAs must decode cleanly. Replacing invalid bytes would
    # manufacture a different path and silently contaminate (or pass) the gate.
    try:
        stdout = proc.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        return _GitResult(
            proc.returncode,
            "",
            f"git output is not valid UTF-8: {exc}",
            "pr_scope.git_failed",
        )
    return _GitResult(proc.returncode, stdout, stderr)


def _normalized_path(value: str) -> str | None:
    """Return a safe repository-relative POSIX path or pattern."""
    path = value.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if not path or path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        return None
    if any(part == ".." for part in path.split("/")):
        return None
    return path


def _unique_normalized_paths(
    values: Any, *, field: str, array_of_paths: bool = False
) -> tuple[list[str], str | None]:
    """Normalize a string array; reject non-strings, unsafe paths, and duplicates.

    Uniqueness is checked *after* normalization so ``a.py`` and ``./a.py``
    cannot collapse into one authorized/observed entry.
    """
    if not isinstance(values, list):
        return [], f"{field} must be an array."
    if array_of_paths and any(not isinstance(item, str) for item in values):
        return [], f"{field} must be an array of paths."
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if not isinstance(raw, str) or (path := _normalized_path(raw)) is None:
            return [], f"Unsafe or invalid declared path: {raw!r}." if not array_of_paths else (
                f"{field} contains an unsafe path."
            )
        if path in seen:
            return [], f"{field} contains duplicate path {path!r}."
        seen.add(path)
        normalized.append(path)
    return normalized, None


def _parse_name_status(stdout: str) -> tuple[list[str], str | None]:
    """Parse ``git diff --name-status -z`` into destination paths.

    Rename/copy records are ``R100\\0old\\0new\\0`` (or ``C…``). Only the
    destination is treated as the changed path so a manifest that correctly
    authorizes the post-rename name is not contaminated by the old name.
    Any path that cannot be normalized fails the parse rather than vanishing.
    """
    tokens = stdout.split("\0")
    if tokens and tokens[-1] == "":
        tokens.pop()
    paths: list[str] = []
    index = 0
    while index < len(tokens):
        status = tokens[index]
        index += 1
        if not status:
            return [], "Git name-status output contained an empty status field."
        two_path = status[0] in _TWO_PATH_STATUS
        needed = 2 if two_path else 1
        if index + needed > len(tokens):
            return [], f"Git name-status record {status!r} is truncated."
        if two_path:
            raw = tokens[index + 1]
            index += 2
        else:
            raw = tokens[index]
            index += 1
        path = _normalized_path(raw)
        if path is None:
            return [], f"Git reported an unsafe changed path: {raw!r}."
        paths.append(path)
    return paths, None


def _manifest_location(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _effective_threshold(ctor_threshold: float, manifest_percent: float | None) -> float:
    """Combine the operator's threshold with the manifest's declared minimum.

    ``scope.min_coverage_percent`` may only *tighten*. Taking the minimum here
    would let a manifest declare ``50`` and opt itself out of the acceptance
    criterion, while silently clamping an intentionally strict ``100`` back
    down. The constructor value is an operator decision (an explicit CLI flag)
    and is honoured as-is; the manifest can only raise it.
    """
    if manifest_percent is None:
        return ctor_threshold
    return max(ctor_threshold, manifest_percent / 100.0)


def _is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


class PrScopeAnalyzer:
    """Compare a branch diff with a CBSP21-declared file scope."""

    id: str = "pr_scope"
    version: str = "2.1.0"

    def __init__(
        self,
        review_context: ReviewContext | dict[str, Any] | None = None,
        *,
        manifest: str | Path | None = None,
        base: str | None = None,
        head: str | None = None,
        coverage_threshold: float = _CONTRACT_FLOOR,
        git_timeout: float = 30.0,
    ) -> None:
        if not 0.0 <= coverage_threshold <= 1.0:
            raise ValueError("coverage_threshold must be between 0 and 1")
        if git_timeout <= 0:
            raise ValueError("git_timeout must be greater than zero")

        if review_context is not None:
            if manifest is not None:
                raise ValueError("pass either review_context or manifest, not both")
            ctx = (
                review_context
                if isinstance(review_context, ReviewContext)
                else ReviewContext(
                    manifest_path=review_context["manifest_path"],
                    base_ref=review_context.get("base_ref"),
                    head_ref=review_context.get("head_ref"),
                )
            )
            manifest = ctx.manifest_path
            base = base or ctx.base_ref
            head = head or ctx.head_ref

        self.manifest = Path(manifest) if manifest is not None else None
        self.base = base
        self.head = head
        self.coverage_threshold = coverage_threshold
        self.git_timeout = git_timeout

    def run(self, root: Path, files: list[Path] | None = None) -> list[Finding]:
        del files
        # Ordinary scans: no manifest → silent.
        if self.manifest is None:
            return []

        loaded = self._load_manifest(root)
        if isinstance(loaded, Finding):
            return [loaded]
        manifest, manifest_label = loaded

        parsed = self._validate_manifest_shape(manifest, manifest_label)
        if isinstance(parsed, Finding):
            return [parsed]
        diff_range, scope, min_coverage_percent, declared_context_coverage = parsed
        threshold = _effective_threshold(self.coverage_threshold, min_coverage_percent)

        refs = self._resolve_refs(root, diff_range, manifest, manifest_label)
        if isinstance(refs, Finding):
            return [refs]
        resolved, findings = refs

        findings.extend(self._drift_findings(root, diff_range, resolved, manifest_label))

        changed = self._changed_paths(root, resolved)
        if isinstance(changed, Finding):
            return findings + [changed]

        raw_declared = scope.get("files_expected_to_change")
        if raw_declared is None:
            declared, invalid = [], None
        else:
            declared, invalid = _unique_normalized_paths(
                raw_declared, field="scope.files_expected_to_change",
            )
        if invalid is not None:
            return findings + [self._uncheckable(
                invalid, manifest_label, symbol="scope.files_expected_to_change",
                rule="pr_scope.manifest_invalid",
            )]
        raw_prefixes = scope.get("paths_in_scope")
        if raw_prefixes is None:
            prefixes, invalid = [], None
        else:
            prefixes, invalid = _unique_normalized_paths(
                raw_prefixes, field="scope.paths_in_scope",
            )
        if invalid is not None:
            return findings + [self._uncheckable(
                invalid, manifest_label, symbol="scope.paths_in_scope",
                rule="pr_scope.manifest_invalid",
            )]
        if not declared and not prefixes:
            return findings + [self._uncheckable(
                "Manifest declares no expected files or in-scope paths; the "
                "authorized scope is empty.",
                manifest_label,
                symbol="scope.files_expected_to_change",
                rule="pr_scope.no_declared_files",
            )]

        observed = self._reconcile_observed(manifest, changed, manifest_label)
        if isinstance(observed, Finding):
            return findings + [observed]
        findings.extend(observed)

        findings.extend(
            self._scope_and_coverage_findings(
                changed, declared, prefixes, declared_context_coverage, threshold,
            )
        )
        return findings

    # ── manifest loading / validation ───────────────────────────────

    def _load_manifest(self, root: Path) -> tuple[dict[str, Any], str] | Finding:
        manifest_path = self.manifest
        assert manifest_path is not None
        if not manifest_path.is_absolute():
            manifest_path = root / manifest_path
        manifest_label = _manifest_location(root, manifest_path)

        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return self._uncheckable(
                f"PR manifest cannot be read or parsed: {exc}",
                manifest_label,
                symbol="manifest",
                rule="pr_scope.manifest_missing",
            )
        if not isinstance(payload, dict):
            return self._uncheckable(
                "PR manifest must be a JSON object.",
                manifest_label,
                symbol="manifest",
                rule="pr_scope.manifest_invalid",
            )
        return payload, manifest_label

    def _validate_manifest_shape(
        self, manifest: dict[str, Any], manifest_label: str
    ) -> tuple[dict[str, Any], dict[str, Any], float | None, float | None] | Finding:
        # A v1 manifest parses fine but pins no base SHA, so drift detection
        # would silently never run and the gate would pass for the wrong reason.
        version = manifest.get("schema_version")
        if version != _SCHEMA_VERSION:
            return self._uncheckable(
                f"PR manifest declares schema_version={version!r}; "
                f"pr_scope requires {_SCHEMA_VERSION!r}.",
                manifest_label,
                symbol="schema_version",
                rule="pr_scope.schema_version_mismatch",
            )

        diff_range = manifest.get("diff_range")
        scope = manifest.get("scope")
        if not isinstance(diff_range, dict) or not isinstance(scope, dict):
            return self._uncheckable(
                "PR manifest must contain object-valued scope and diff_range fields.",
                manifest_label,
                symbol="manifest",
                rule="pr_scope.manifest_invalid",
            )

        try:
            min_coverage_percent = self._manifest_percent(
                scope.get("min_coverage_percent"),
                "scope.min_coverage_percent",
            )
        except ValueError as exc:
            return self._uncheckable(
                str(exc), manifest_label, symbol="scope.min_coverage_percent",
                rule="pr_scope.manifest_invalid",
            )
        try:
            declared_context_coverage = self._manifest_percent(
                manifest.get("file_context_coverage_percent"),
                "file_context_coverage_percent",
            )
        except ValueError as exc:
            return self._uncheckable(
                str(exc), manifest_label, symbol="file_context_coverage_percent",
                rule="pr_scope.manifest_invalid",
            )
        return diff_range, scope, min_coverage_percent, declared_context_coverage

    def _pinned_base_sha(
        self,
        diff_range: dict[str, Any],
        manifest: dict[str, Any],
        manifest_label: str,
    ) -> str | Finding:
        if "base_sha" in diff_range:
            value, symbol = diff_range["base_sha"], "diff_range.base_sha"
        elif "pinned_merge_base" in diff_range:
            value, symbol = diff_range["pinned_merge_base"], "diff_range.pinned_merge_base"
        elif "base_sha" in manifest:
            value, symbol = manifest["base_sha"], "base_sha"
        else:
            return self._uncheckable(
                "Manifest has no immutable base SHA. Use CBSP21 v2 and record "
                "diff_range.base_sha.",
                manifest_label,
                symbol="diff_range.base_sha",
                rule="pr_scope.base_pin_missing",
            )
        if not _is_nonempty_str(value):
            return self._uncheckable(
                f"{symbol} must be a non-empty string when provided.",
                manifest_label,
                symbol=symbol,
                rule="pr_scope.manifest_invalid",
            )
        return value

    # ── git refs / diff ─────────────────────────────────────────────

    def _resolve_refs(
        self,
        root: Path,
        diff_range: dict[str, Any],
        manifest: dict[str, Any],
        manifest_label: str,
    ) -> tuple[_ResolvedRefs, list[Finding]] | Finding:
        if self.base is not None:
            base_ref = self.base
        elif "base" in diff_range:
            base_ref = diff_range["base"]
        else:
            base_ref = None
        if self.head is not None:
            head_ref = self.head
        elif "head" in diff_range:
            head_ref = diff_range["head"]
        else:
            head_ref = "HEAD"

        if not _is_nonempty_str(base_ref):
            return self._uncheckable(
                "No target base ref was supplied.", manifest_label,
                symbol="diff_range.base", rule="pr_scope.manifest_invalid",
            )
        if not _is_nonempty_str(head_ref):
            return self._uncheckable(
                "No head ref was supplied.", manifest_label,
                symbol="diff_range.head", rule="pr_scope.manifest_invalid",
            )

        pinned_base = self._pinned_base_sha(diff_range, manifest, manifest_label)
        if isinstance(pinned_base, Finding):
            return pinned_base

        resolved: dict[str, str] = {}
        for label, ref, rule in (
            ("base", base_ref, "pr_scope.base_unresolved"),
            ("head", head_ref, "pr_scope.head_unresolved"),
            ("pinned base", pinned_base, "pr_scope.pinned_base_unresolved"),
        ):
            result = _git(root, self.git_timeout, "rev-parse", "--verify", f"{ref}^{{commit}}")
            if result.returncode != 0 or not result.stdout.strip():
                return self._git_finding(
                    result,
                    fallback_rule=rule,
                    message=f"Cannot resolve {label} ref {ref!r}; PR scope cannot be verified.",
                )
            resolved[label] = result.stdout.strip().splitlines()[0]

        merge = _git(root, self.git_timeout, "merge-base", resolved["base"], resolved["head"])
        if merge.returncode != 0 or not merge.stdout.strip():
            return self._git_finding(
                merge,
                fallback_rule="pr_scope.base_unresolved",
                message=(
                    "Cannot resolve the merge-base; "
                    f"{self._shallow_hint(root)}."
                ),
            )
        merge_base = merge.stdout.strip().splitlines()[0]
        return _ResolvedRefs(
            base=resolved["base"],
            head=resolved["head"],
            pinned_base=resolved["pinned base"],
            merge_base=merge_base,
        ), []

    def _drift_findings(
        self,
        root: Path,
        diff_range: dict[str, Any],
        resolved: _ResolvedRefs,
        manifest_label: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if resolved.pinned_base != resolved.merge_base:
            findings.append(self._finding(
                Severity.HIGH,
                0.95,
                "Base drift: manifest pins "
                f"{resolved.pinned_base[:12]}, but the current merge-base is "
                f"{resolved.merge_base[:12]}.",
                ".",
                symbol="diff_range.base_sha",
                rule="pr_scope.base_drift",
                metadata={
                    "pinned_base": resolved.pinned_base,
                    "actual_merge_base": resolved.merge_base,
                },
            ))

        if "head_sha" not in diff_range:
            return findings
        pinned_head = diff_range["head_sha"]
        if not _is_nonempty_str(pinned_head):
            findings.append(self._uncheckable(
                "diff_range.head_sha must be a non-empty string when provided.",
                manifest_label,
                symbol="diff_range.head_sha",
                rule="pr_scope.manifest_invalid",
            ))
            return findings
        result = _git(
            root,
            self.git_timeout,
            "rev-parse",
            "--verify",
            f"{pinned_head}^{{commit}}",
        )
        if result.returncode != 0 or not result.stdout.strip():
            findings.append(self._git_finding(
                result,
                fallback_rule="pr_scope.pinned_head_unresolved",
                message=f"Cannot resolve pinned head SHA {pinned_head!r}.",
            ))
        elif result.stdout.strip().splitlines()[0] != resolved.head:
            findings.append(self._finding(
                Severity.HIGH,
                0.95,
                "Head drift: the reviewed head commit no longer matches diff_range.head_sha.",
                ".",
                symbol="diff_range.head_sha",
                rule="pr_scope.head_drift",
                metadata={
                    "pinned_head": result.stdout.strip().splitlines()[0],
                    "actual_head": resolved.head,
                },
            ))
        return findings

    def _changed_paths(
        self,
        root: Path,
        resolved: _ResolvedRefs,
    ) -> list[str] | Finding:
        diff = _git(
            root,
            self.git_timeout,
            "diff",
            "--name-status",
            # -z keeps paths raw; without it core.quotePath escapes non-ASCII
            # names and every scope comparison against them fails.
            "-z",
            "--find-renames",
            f"{resolved.merge_base}..{resolved.head}",
            "--",
        )
        if diff.returncode != 0 or diff.failure_rule:
            return self._git_finding(
                diff,
                fallback_rule="pr_scope.diff_failed",
                message="Git diff failed; PR scope cannot be verified.",
            )
        changed, error = _parse_name_status(diff.stdout)
        if error is not None:
            return self._uncheckable(
                error,
                ".",
                symbol="git",
                rule="pr_scope.diff_failed",
            )
        return sorted(set(changed))

    # ── observed-file cross-checks / coverage ───────────────────────

    def _reconcile_observed(
        self,
        manifest: dict[str, Any],
        changed: list[str],
        manifest_label: str,
    ) -> list[Finding] | Finding:
        findings: list[Finding] = []
        changed_set = set(changed)
        observed = manifest.get("changed_files_exact")
        if observed is not None:
            normalized_observed, invalid = _unique_normalized_paths(
                observed, field="changed_files_exact", array_of_paths=True,
            )
            if invalid is not None:
                return self._uncheckable(
                    invalid, manifest_label, symbol="changed_files_exact",
                    rule="pr_scope.manifest_invalid",
                )
            normalized_set = set(normalized_observed)
            if normalized_set != changed_set:
                findings.append(self._finding(
                    Severity.HIGH,
                    0.95,
                    "Manifest changed_files_exact does not match the committed Git diff.",
                    manifest_label,
                    symbol="changed_files_exact",
                    rule="pr_scope.observed_files_mismatch",
                    metadata={
                        "manifest_only": sorted(normalized_set - changed_set),
                        "git_only": sorted(changed_set - normalized_set),
                    },
                ))

        observed_count = manifest.get("changed_files_count")
        if observed_count is not None and (
            not isinstance(observed_count, int) or isinstance(observed_count, bool)
        ):
            return self._uncheckable(
                "changed_files_count must be an integer.",
                manifest_label, symbol="changed_files_count",
                rule="pr_scope.manifest_invalid",
            )
        if isinstance(observed_count, int) and observed_count != len(changed_set):
            findings.append(self._finding(
                Severity.HIGH,
                0.95,
                f"Manifest reports {observed_count} changed files, but Git reports "
                f"{len(changed_set)}.",
                manifest_label,
                symbol="changed_files_count",
                rule="pr_scope.observed_count_mismatch",
                metadata={"manifest_count": observed_count, "git_count": len(changed_set)},
            ))
        return findings

    def _scope_and_coverage_findings(
        self,
        changed: list[str],
        declared: list[str],
        prefixes: list[str],
        declared_context_coverage: float | None,
        threshold: float,
    ) -> list[Finding]:
        findings: list[Finding] = []
        undeclared = sorted(
            path
            for path in changed
            if not _is_declared(path, declared, prefixes)
        )
        coverage = 1.0 if not changed else (len(changed) - len(undeclared)) / len(changed)
        for path in undeclared:
            findings.append(self._finding(
                Severity.MEDIUM,
                0.9,
                f"Scope contamination: {path} is in the branch diff but outside "
                "the declared file set.",
                path,
                symbol=path,
                rule="pr_scope.undeclared_file",
                metadata={"declared_coverage": round(coverage, 6)},
            ))

        # Two independent metrics share the threshold: scope coverage (share of
        # the real diff that was declared) and file_context_coverage_percent
        # (the author's declared review depth). Name whichever tripped so the
        # message is never misleading.
        causes: list[str] = []
        if undeclared:
            causes.append(
                f"{len(undeclared)}/{len(changed)} changed files outside declared "
                f"scope (coverage {coverage:.1%})"
            )
        context_short = (
            declared_context_coverage is not None
            and declared_context_coverage / 100.0 < threshold
        )
        if context_short:
            causes.append(
                f"manifest file_context_coverage_percent="
                f"{declared_context_coverage:.1f}%"
            )
        if not causes:
            return findings
        below = coverage < threshold or context_short
        if context_short and not undeclared:
            message = (
                f"Declared file_context_coverage_percent is below the review "
                f"threshold: {declared_context_coverage:.1f}% "
                f"(threshold {threshold:.1%})."
            )
        else:
            message = (
                f"Branch diff scope coverage is under review: {'; '.join(causes)} "
                f"(threshold {threshold:.1%})."
            )
        findings.append(self._finding(
            Severity.HIGH if below else Severity.MEDIUM,
            0.95,
            message,
            ".",
            symbol="scope_summary",
            rule="pr_scope.coverage_below_threshold",
            metadata={
                "declared_coverage": round(coverage, 6),
                "coverage_percent": round(coverage * 100.0, 6),
                "coverage_threshold": threshold,
                "threshold_percent": round(threshold * 100.0, 6),
                "undeclared_count": len(undeclared),
                "changed_count": len(changed),
                "file_context_coverage_percent": declared_context_coverage,
                "triggered_by": (
                    ["scope_coverage"] if undeclared else []
                ) + (["file_context_coverage"] if context_short else []),
            },
        ))
        return findings

    # ── manifest helpers ────────────────────────────────────────────

    @staticmethod
    def _manifest_percent(value: Any, field: str) -> float | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(
                f"{field} must be numeric, got {type(value).__name__}"
            )
        number = float(value)
        if not 0.0 <= number <= 100.0:
            raise ValueError(
                f"{field} must be between 0 and 100, got {number:g}"
            )
        return number

    def _shallow_hint(self, root: Path) -> str:
        result = _git(root, self.git_timeout, "rev-parse", "--is-shallow-repository")
        if result.returncode == 0 and result.stdout.strip().lower() == "true":
            return "this is a shallow clone — fetch full history (fetch-depth: 0)"
        return "the base ref may not be fetched in this checkout"

    # ── finding constructors ────────────────────────────────────────

    def _git_finding(self, result: _GitResult, *, fallback_rule: str, message: str) -> Finding:
        rule = result.failure_rule or fallback_rule
        detail = result.stderr.strip()
        if detail:
            message = f"{message} Git reported: {detail}"
        return self._finding(
            Severity.CRITICAL, 0.99, message, ".", symbol="git", rule=rule,
            metadata={"git_returncode": result.returncode},
        )

    def _uncheckable(
        self, message: str, path: str, *, symbol: str, rule: str
    ) -> Finding:
        return self._finding(
            Severity.CRITICAL,
            0.99,
            f"{message} pr_scope failing loud — an uncheckable review is never "
            f"a clean pass.",
            path,
            symbol=symbol,
            rule=rule,
        )

    def _finding(
        self,
        severity: Severity,
        confidence: float,
        message: str,
        path: str,
        *,
        symbol: str,
        rule: str,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        # Fingerprint excludes volatile detail (percentages, SHAs) so the same
        # problem keeps one identity across runs and stays baseline-able.
        fingerprint = make_fingerprint(rule, path, symbol, "")
        finding_metadata = {"rule_id": rule}
        if metadata:
            finding_metadata.update(metadata)
        return Finding(
            finding_id=fingerprint,
            type=AnalyzerType.PR_SCOPE,
            severity=severity,
            confidence=confidence,
            message=message,
            location=Location(path=path, line_start=1, line_end=1),
            fingerprint=fingerprint,
            metadata=finding_metadata,
        )


def _is_declared(path: str, declared: list[str], prefixes: list[str]) -> bool:
    """Declared by glob match on a file pattern, or by directory prefix."""
    if any(fnmatch.fnmatchcase(path, pattern) for pattern in declared):
        return True
    for prefix in prefixes:
        if path == prefix.rstrip("/"):
            return True
        directory = prefix if prefix.endswith("/") else prefix + "/"
        if path.startswith(directory):
            return True
    return False
