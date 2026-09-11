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


def _git(root: Path, timeout: float, *args: str) -> _GitResult:
    """Run Git without a shell and turn process failures into data."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            text=True,
            # Git emits path bytes as UTF-8; the platform locale codec (cp1252
            # on Windows) would mojibake non-ASCII names into false findings.
            encoding="utf-8",
            errors="replace",
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
    return _GitResult(proc.returncode, proc.stdout, proc.stderr)


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


# ── sub-file dependency-direction helpers (v2.1.0) ──────────────────
# package.json at any depth (root or a workspace package).
_PACKAGE_JSON_RE = re.compile(r"(^|/)package\.json$")
# Leading semver-range operators to strip before a numeric compare.
# An orderable specifier: at most one pinned or lower-bound operator, then a bare
# numeric version and nothing else. See _parse_version for what falls outside.
_ORDERABLE_SPEC_RE = re.compile(r"(?:\^|~|>=|>|=)?\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_DEP_KEYS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")


def _is_package_json(path: str) -> bool:
    return bool(_PACKAGE_JSON_RE.search(path))


def _parse_version(spec: str) -> tuple[int, int, int] | None:
    """Numeric (major, minor, patch) of a single orderable specifier, else None.

    Orderable: a bare version, optionally behind ONE of ``^ ~ >= > =`` and an
    optional ``v`` — ``^4.4.3`` → (4, 4, 3); ``~3.25`` → (3, 25, 0).

    Deliberately NOT ordered (returns None, so the caller records direction
    'unknown' at MEDIUM — the change is still reported, never silently passed):

    * compound ranges — ``>=4.4.3 <5``, ``1.2.3 - 2.0.0``, ``1 || 2``
    * upper bounds — ``<5``, ``<=4.9.0`` (the bound is not the version in use)
    * wildcards and tags — ``*``, ``1.2.x``, ``latest``, ``next``
    * prerelease / build suffixes — ``1.0.0-rc.1`` (semver orders rc below the
      release; comparing only the numeric core would call a downgrade 'same')
    * non-registry sources — git/URL/``github:``/``file:``/``workspace:`` specs
      and ``npm:`` aliases
    """
    m = _ORDERABLE_SPEC_RE.fullmatch(spec.strip())
    if not m:
        return None
    return tuple(int(g) if g else 0 for g in m.groups())  # type: ignore[return-value]


def _version_direction(base_spec: str, head_spec: str) -> str:
    """'downgrade' | 'upgrade' | 'same' | 'unknown' comparing head vs base."""
    b = _parse_version(base_spec)
    h = _parse_version(head_spec)
    if b is None or h is None:
        return "unknown"
    if h < b:
        return "downgrade"
    if h > b:
        return "upgrade"
    return "same"


def _read_package_deps(root: Path, ref: str, path: str, timeout: float):
    """Return (deps_dict, status). status ∈ {'ok','absent','malformed','git_error'}.

    Reads the REAL git surface (``git show <ref>:<path>``) — never a caller-supplied
    diff, preserving the no-injection guarantee. 'absent' (file not at that ref) is
    treated as no-deps so an added/removed package.json is not mistaken for a change;
    'malformed' (present but not JSON) is uncheckable.
    """
    res = _git(root, timeout, "show", f"{ref}:{path}")
    if res.returncode != 0:
        # Path not present at ref, or a git error. Either way there is no baseline
        # dependency map on this side to compare against — treat as absent.
        return {}, "absent"
    try:
        data = json.loads(res.stdout)
    except (json.JSONDecodeError, ValueError):
        return None, "malformed"
    if not isinstance(data, dict):
        return None, "malformed"
    deps: dict[str, str] = {}
    for key in _DEP_KEYS:
        section = data.get(key)
        if isinstance(section, dict):
            for name, ver in section.items():
                if isinstance(name, str) and isinstance(ver, str):
                    deps[name] = ver
    return deps, "ok"


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

        manifest_path = self.manifest
        if not manifest_path.is_absolute():
            manifest_path = root / manifest_path
        manifest_label = _manifest_location(root, manifest_path)

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [self._uncheckable(
                f"PR manifest cannot be read or parsed: {exc}",
                manifest_label,
                symbol="manifest",
                rule="pr_scope.manifest_missing",
            )]
        if not isinstance(manifest, dict):
            return [self._uncheckable(
                "PR manifest must be a JSON object.",
                manifest_label,
                symbol="manifest",
                rule="pr_scope.manifest_invalid",
            )]

        # A v1 manifest parses fine but pins no base SHA, so drift detection
        # would silently never run and the gate would pass for the wrong reason.
        version = manifest.get("schema_version")
        if version != _SCHEMA_VERSION:
            return [self._uncheckable(
                f"PR manifest declares schema_version={version!r}; "
                f"pr_scope requires {_SCHEMA_VERSION!r}.",
                manifest_label,
                symbol="schema_version",
                rule="pr_scope.schema_version_mismatch",
            )]

        diff_range = manifest.get("diff_range")
        scope = manifest.get("scope")
        if not isinstance(diff_range, dict) or not isinstance(scope, dict):
            return [self._uncheckable(
                "PR manifest must contain object-valued scope and diff_range fields.",
                manifest_label,
                symbol="manifest",
                rule="pr_scope.manifest_invalid",
            )]

        base_ref = self.base or diff_range.get("base")
        head_ref = self.head or diff_range.get("head") or "HEAD"
        # base_sha is canonical; pinned_merge_base is the accepted alias.
        pinned_base = (
            diff_range.get("base_sha")
            or diff_range.get("pinned_merge_base")
            or manifest.get("base_sha")
        )
        if not isinstance(base_ref, str) or not base_ref:
            return [self._uncheckable(
                "No target base ref was supplied.", manifest_label,
                symbol="diff_range.base", rule="pr_scope.manifest_invalid",
            )]
        if not isinstance(head_ref, str) or not head_ref:
            return [self._uncheckable(
                "No head ref was supplied.", manifest_label,
                symbol="diff_range.head", rule="pr_scope.manifest_invalid",
            )]
        if not isinstance(pinned_base, str) or not pinned_base:
            return [self._uncheckable(
                "Manifest has no immutable base SHA. Use CBSP21 v2 and record "
                "diff_range.base_sha.",
                manifest_label,
                symbol="diff_range.base_sha",
                rule="pr_scope.base_pin_missing",
            )]

        try:
            min_coverage_percent = self._manifest_percent(
                scope.get("min_coverage_percent")
            )
            declared_context_coverage = self._manifest_percent(
                manifest.get("file_context_coverage_percent")
            )
        except ValueError as exc:
            return [self._uncheckable(
                str(exc), manifest_label, symbol="scope.min_coverage_percent",
                rule="pr_scope.manifest_invalid",
            )]
        threshold = _effective_threshold(self.coverage_threshold, min_coverage_percent)

        resolved: dict[str, str] = {}
        for label, ref, rule in (
            ("base", base_ref, "pr_scope.base_unresolved"),
            ("head", head_ref, "pr_scope.head_unresolved"),
            ("pinned base", pinned_base, "pr_scope.pinned_base_unresolved"),
        ):
            result = _git(root, self.git_timeout, "rev-parse", "--verify", f"{ref}^{{commit}}")
            if result.returncode != 0 or not result.stdout.strip():
                return [self._git_finding(
                    result,
                    fallback_rule=rule,
                    message=f"Cannot resolve {label} ref {ref!r}; PR scope cannot be verified.",
                )]
            resolved[label] = result.stdout.strip().splitlines()[0]

        merge = _git(root, self.git_timeout, "merge-base", resolved["base"], resolved["head"])
        if merge.returncode != 0 or not merge.stdout.strip():
            return [self._git_finding(
                merge,
                fallback_rule="pr_scope.base_unresolved",
                message=(
                    "Cannot resolve the merge-base; "
                    f"{self._shallow_hint(root)}."
                ),
            )]
        merge_base = merge.stdout.strip().splitlines()[0]

        findings: list[Finding] = []
        if resolved["pinned base"] != merge_base:
            findings.append(self._finding(
                Severity.HIGH,
                0.95,
                "Base drift: manifest pins "
                f"{resolved['pinned base'][:12]}, but the current merge-base is "
                f"{merge_base[:12]}.",
                ".",
                symbol="diff_range.base_sha",
                rule="pr_scope.base_drift",
                metadata={
                    "pinned_base": resolved["pinned base"],
                    "actual_merge_base": merge_base,
                },
            ))

        pinned_head = diff_range.get("head_sha")
        if pinned_head:
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
            elif result.stdout.strip().splitlines()[0] != resolved["head"]:
                findings.append(self._finding(
                    Severity.HIGH,
                    0.95,
                    "Head drift: the reviewed head commit no longer matches diff_range.head_sha.",
                    ".",
                    symbol="diff_range.head_sha",
                    rule="pr_scope.head_drift",
                    metadata={
                        "pinned_head": result.stdout.strip().splitlines()[0],
                        "actual_head": resolved["head"],
                    },
                ))

        diff = _git(
            root,
            self.git_timeout,
            "diff",
            "--name-only",
            # -z keeps paths raw; without it core.quotePath escapes non-ASCII
            # names and every scope comparison against them fails.
            "-z",
            "--find-renames",
            f"{merge_base}..{resolved['head']}",
            "--",
        )
        if diff.returncode != 0:
            return findings + [self._git_finding(
                diff,
                fallback_rule="pr_scope.diff_failed",
                message="Git diff failed; PR scope cannot be verified.",
            )]
        changed = sorted({
            path
            for raw in diff.stdout.split("\0")
            if raw and (path := _normalized_path(raw)) is not None
        })
        changed_set = set(changed)

        declared, invalid = self._declared_patterns(scope, "files_expected_to_change")
        if invalid is not None:
            return findings + [self._uncheckable(
                invalid, manifest_label, symbol="scope.files_expected_to_change",
                rule="pr_scope.manifest_invalid",
            )]
        prefixes, invalid = self._declared_patterns(scope, "paths_in_scope")
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

        observed = manifest.get("changed_files_exact")
        if observed is not None:
            if not isinstance(observed, list) or any(not isinstance(p, str) for p in observed):
                return findings + [self._uncheckable(
                    "changed_files_exact must be an array of paths.",
                    manifest_label, symbol="changed_files_exact",
                    rule="pr_scope.manifest_invalid",
                )]
            normalized_observed = {_normalized_path(p) for p in observed}
            if None in normalized_observed:
                return findings + [self._uncheckable(
                    "changed_files_exact contains an unsafe path.",
                    manifest_label, symbol="changed_files_exact",
                    rule="pr_scope.manifest_invalid",
                )]
            if normalized_observed != changed_set:
                findings.append(self._finding(
                    Severity.HIGH,
                    0.95,
                    "Manifest changed_files_exact does not match the committed Git diff.",
                    manifest_label,
                    symbol="changed_files_exact",
                    rule="pr_scope.observed_files_mismatch",
                    metadata={
                        "manifest_only": sorted(normalized_observed - changed_set),
                        "git_only": sorted(changed_set - normalized_observed),
                    },
                ))

        observed_count = manifest.get("changed_files_count")
        if observed_count is not None and (
            not isinstance(observed_count, int) or isinstance(observed_count, bool)
        ):
            return findings + [self._uncheckable(
                "changed_files_count must be an integer.",
                manifest_label, symbol="changed_files_count",
                rule="pr_scope.manifest_invalid",
            )]
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
        if causes:
            below = coverage < threshold or context_short
            findings.append(self._finding(
                Severity.HIGH if below else Severity.MEDIUM,
                0.95,
                f"Branch diff scope coverage is under review: {'; '.join(causes)} "
                f"(threshold {threshold:.1%}).",
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

        # v2.1.0: sub-file dependency-direction check. File-level scope catches an
        # undeclared *file*; it cannot see an undeclared *change inside a declared
        # file* — the #296 shape, where a legitimately-declared package.json carried
        # a second, undeclared zod downgrade. This looks INSIDE each declared
        # package.json at dependency direction.
        findings.extend(
            _DependencyDirectionCheck(
                self, root, merge_base, resolved["head"], declared, prefixes,
            ).run(changed, manifest, scope)
        )
        return findings

    # ── manifest helpers ────────────────────────────────────────────

    @staticmethod
    def _manifest_percent(value: Any) -> float | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(
                f"coverage percentages must be numeric, got {type(value).__name__}"
            )
        number = float(value)
        if not 0.0 <= number <= 100.0:
            raise ValueError(
                f"coverage percentages must be between 0 and 100, got {number:g}"
            )
        return number

    @staticmethod
    def _declared_patterns(
        scope: dict[str, Any], field: str
    ) -> tuple[list[str], str | None]:
        raw_patterns = scope.get(field)
        if raw_patterns is None:
            return [], None
        if not isinstance(raw_patterns, list):
            return [], f"scope.{field} must be an array."
        patterns: list[str] = []
        for raw in raw_patterns:
            if not isinstance(raw, str) or (pattern := _normalized_path(raw)) is None:
                return [], f"Unsafe or invalid declared path: {raw!r}."
            patterns.append(pattern)
        return patterns, None

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


# ── sub-file dependency-direction check (v2.1.0) ────────────────────


def _declared_dependency_names(
    scope: dict[str, Any], manifest: dict[str, Any]
) -> tuple[set[str], str]:
    """Dependency names the manifest declares as intentionally changed, plus the
    ``diff_articulation`` text.

    Only ``scope.dependency_changes`` (a list of names or ``{name, ...}``
    objects) declares a change. The articulation text is returned so a mention
    can be *recorded* on the finding, but prose never declares: substring
    matching is fuzzy, and a sentence such as "zod is untouched" would
    otherwise silence exactly the zod downgrade this rule exists to catch.
    """
    names: set[str] = set()
    dc = scope.get("dependency_changes")
    if isinstance(dc, list):
        for item in dc:
            if isinstance(item, str):
                names.add(item)
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                names.add(item["name"])
    da = manifest.get("diff_articulation")
    da_text = json.dumps(da) if da is not None else ""
    return names, da_text


def _mentioned_in(dep: str, text: str) -> bool:
    """Whole-name mention of *dep* in *text*: ``react`` does not match
    ``react-dom`` or ``preact``, and ``node`` does not match ``@types/node``."""
    pattern = rf"(?<![\w@/.-]){re.escape(dep)}(?![\w/-]|\.\w)"
    return re.search(pattern, text) is not None


@dataclass(frozen=True, slots=True)
class _DependencyDirectionCheck:
    """Looks inside each declared, changed package.json for undeclared
    dependency-version changes, between the merge-base and head.

    Carries the resolved review context so the per-file and per-dependency
    steps don't thread it through long argument lists. Findings are built with
    the owning analyzer's constructors so rule ids, fingerprints and severities
    stay identical to the rest of pr_scope.
    """

    analyzer: PrScopeAnalyzer
    root: Path
    merge_base: str
    head: str
    declared: list[str]
    prefixes: list[str]

    def run(
        self, changed: list[str], manifest: dict[str, Any], scope: dict[str, Any]
    ) -> list[Finding]:
        # Every failure mode is a Finding — an exception escaping here would abort the
        # scan, i.e. the silent pass this check exists to prevent. Belt-and-suspenders
        # around the whole body.
        try:
            declared_deps, da_text = _declared_dependency_names(scope, manifest)
            findings: list[Finding] = []
            for path in changed:
                # Sub-file rule applies to DECLARED package.json — an *undeclared*
                # package.json is already flagged by pr_scope.undeclared_file.
                if _is_package_json(path) and _is_declared(path, self.declared, self.prefixes):
                    findings.extend(self._file_findings(path, declared_deps, da_text))
            return findings
        except Exception as exc:  # noqa: BLE001 — fail loud as a finding, never raise
            return [self.analyzer._uncheckable(
                f"Dependency-direction check raised {type(exc).__name__}: {exc}.",
                ".", symbol="dependency_check", rule="pr_scope.dependency_check_error",
            )]

    def _read(self, ref: str, path: str):
        return _read_package_deps(self.root, ref, path, self.analyzer.git_timeout)

    def _file_findings(
        self, path: str, declared_deps: set[str], da_text: str
    ) -> list[Finding]:
        base_deps, base_status = self._read(self.merge_base, path)
        head_deps, head_status = self._read(self.head, path)

        if base_status == "malformed" or head_status == "malformed":
            return [self.analyzer._uncheckable(
                f"'{path}' is not valid JSON at "
                f"{'merge-base' if base_status == 'malformed' else 'head'}; "
                "its dependency changes cannot be verified.",
                path, symbol=path, rule="pr_scope.dependency_check_uncheckable",
            )]
        if base_deps is None or head_deps is None:  # defensive; malformed handled above
            return []

        findings: list[Finding] = []
        for dep in sorted(set(base_deps) & set(head_deps)):
            base_ver, head_ver = base_deps[dep], head_deps[dep]
            if base_ver == head_ver:
                continue  # unchanged
            if dep in declared_deps:
                continue  # declared in scope.dependency_changes — legitimate
            findings.append(self._dependency_finding(
                path, dep, base_ver, head_ver, _mentioned_in(dep, da_text)))
        return findings

    def _dependency_finding(
        self, path: str, dep: str, base_ver: str, head_ver: str, mentioned: bool
    ) -> Finding:
        direction = _version_direction(base_ver, head_ver)
        reverts = self._reverts_base_landing(path, dep, head_ver)

        # A downgrade or an undone landing is HIGH; an upgrade, a version that is
        # the same after normalization, or an 'unknown' range is MEDIUM.
        severity = Severity.HIGH if direction == "downgrade" or reverts else Severity.MEDIUM

        revert_note = (
            " It reverts a dependency version the merge-base itself just "
            "landed — silently undoing committed work."
            if reverts else ""
        )
        mention_note = (
            f" '{dep}' is mentioned in diff_articulation, but prose is not a "
            f"declaration — list it in scope.dependency_changes."
            if mentioned else ""
        )
        return self.analyzer._finding(
            severity,
            0.9,
            f"Undeclared dependency change in declared file '{path}': "
            f"{dep} {base_ver} → {head_ver} ({direction}). The file is in "
            f"scope but this dependency change is not declared in "
            f"scope.dependency_changes.{revert_note}{mention_note}",
            path,
            symbol=dep,
            rule="pr_scope.undeclared_dependency_change",
            metadata={
                "dependency": dep,
                "base_version": base_ver,
                "head_version": head_ver,
                "direction": direction,
                "reverts_base_landing": reverts,
                "mentioned_in_diff_articulation": mentioned,
            },
        )

    def _reverts_base_landing(self, path: str, dep: str, head_ver: str) -> bool:
        """True if the merge-base commit itself changed ``dep`` and the branch sets
        it back to the pre-merge-base value — i.e. the branch undoes a landing.
        Best-effort: any read failure returns False (never a raised exception)."""
        parent_deps, status = self._read(f"{self.merge_base}~1", path)
        if status != "ok" or parent_deps is None:
            return False
        base_deps, base_status = self._read(self.merge_base, path)
        if base_status != "ok" or base_deps is None:
            return False
        parent_ver = parent_deps.get(dep)
        base_ver = base_deps.get(dep)
        # merge-base changed dep (parent != base), and the branch restores parent.
        return (
            parent_ver is not None
            and base_ver is not None
            and parent_ver != base_ver
            and head_ver == parent_ver
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
