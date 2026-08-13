"""PR-scope / CBSP21 scope-contract detector.

Compares the real ``merge-base..HEAD`` changed-file set against a declared
CBSP21/RPMCC24 patch manifest (``patch_input_v2``) and fails loudly when the
check itself cannot be performed.

**Ordinary scans without review context remain silent** (return ``[]``).
Review context is activated by constructing the analyzer with a
``review_context`` (manifest path, optional git overrides for tests, optional
base ref).

Every manifest read goes through the ``_as_*`` coercion helpers below. A
malformed manifest must surface as a CRITICAL "uncheckable" finding, never as
an exception escaping ``run()`` — an exception aborts the scan, which is the
silent pass this detector exists to prevent.

Acceptance contract: ``cbsp21/pr_scope_acceptance.json``.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_RULE_CONTAMINATION = "PR_SCOPE_CONTAMINATION_001"
_RULE_BASE_DRIFT = "PR_SCOPE_BASE_DRIFT_001"
_RULE_COVERAGE = "PR_SCOPE_COVERAGE_001"
_RULE_UNCHECKABLE = "PR_SCOPE_UNCHECKABLE_001"

# Contract floor (cbsp21/pr_scope_acceptance.json → "coverage_below_95"):
# in-scope coverage below 95% is always a finding. A manifest may raise this
# bar via scope.min_coverage_percent but may never lower it — see
# _coverage_floor().
_DEFAULT_MIN_COVERAGE = 95.0

_SCHEMA_VERSION = "cbsp21_patch_manifest_v2"

# Ceiling on any single git invocation. Without it a git process that blocks
# on a credential prompt or an unresponsive remote hangs the whole scan.
_GIT_TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True, slots=True)
class ReviewContext:
    """Activates pr_scope enforcement for a scan.

    ``changed_files`` / ``actual_merge_base`` are test/injection hooks. When
    omitted, the analyzer resolves them via ``git`` under ``root``.
    """

    manifest_path: str | Path
    base_ref: str | None = None  # override manifest diff_range.base
    changed_files: list[str] | None = None
    actual_merge_base: str | None = None


class PrScopeAnalyzer:
    """Enforce declared patch scope against the real merge-base..HEAD diff."""

    id: str = "pr_scope"
    version: str = "1.1.0"

    def __init__(self, review_context: ReviewContext | dict[str, Any] | None = None):
        if review_context is None:
            self._ctx: ReviewContext | None = None
        elif isinstance(review_context, ReviewContext):
            self._ctx = review_context
        else:
            self._ctx = ReviewContext(
                manifest_path=review_context["manifest_path"],
                base_ref=review_context.get("base_ref"),
                changed_files=review_context.get("changed_files"),
                actual_merge_base=review_context.get("actual_merge_base"),
            )

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        # Ordinary scans: no review context → silent.
        ctx = self._ctx
        if ctx is None:
            return []
        try:
            return self._run_checked(root, ctx)
        except PrScopeUncheckable as exc:
            return [_uncheckable_finding(str(exc), exc.kind)]

    def _run_checked(self, root: Path, ctx: ReviewContext) -> list[Finding]:
        """Body of :meth:`run`; every failure path raises PrScopeUncheckable."""
        manifest_path = Path(ctx.manifest_path)
        if not manifest_path.is_absolute():
            manifest_path = (root / manifest_path).resolve()

        manifest = _load_manifest(manifest_path)
        _check_schema_version(manifest, manifest_path)

        scope = _as_mapping(manifest.get("scope"), "scope")
        paths_in_scope = [_norm(p) for p in _as_str_list(
            scope.get("paths_in_scope"), "scope.paths_in_scope"
        )]
        expected_files = [_norm(p) for p in _as_str_list(
            scope.get("files_expected_to_change"), "scope.files_expected_to_change"
        )]
        paths_in_scope = [p for p in paths_in_scope if p]
        expected_files = [p for p in expected_files if p]
        if not paths_in_scope and not expected_files:
            raise PrScopeUncheckable(
                "manifest declares an empty scope (scope.paths_in_scope and "
                "scope.files_expected_to_change are both empty) — every changed "
                "file would be contamination; declare the real scope",
                kind="empty_declared_scope",
            )

        min_coverage = _as_percent(
            scope.get("min_coverage_percent", _DEFAULT_MIN_COVERAGE),
            "scope.min_coverage_percent",
        )
        declared_coverage = _as_percent(
            manifest.get("file_context_coverage_percent", 100.0),
            "file_context_coverage_percent",
        )

        diff_range = _as_mapping(manifest.get("diff_range"), "diff_range")
        base_ref = ctx.base_ref or _as_opt_str(
            diff_range.get("base"), "diff_range.base"
        )
        pinned_mb = _as_opt_str(
            diff_range.get("pinned_merge_base"), "diff_range.pinned_merge_base"
        )
        if not base_ref and not pinned_mb:
            raise PrScopeUncheckable(
                "manifest diff_range.base / pinned_merge_base is empty",
                kind="missing_pinned_base",
            )

        # Fall back to the pinned merge-base as the diff base rather than to
        # "HEAD": `git merge-base HEAD HEAD` resolves to HEAD, yielding an empty
        # changed set and a silent clean pass.
        effective_base = base_ref or pinned_mb or ""

        actual_mb, changed = _resolve_git_surface(
            root,
            base_ref=effective_base,
            override_mb=ctx.actual_merge_base,
            override_changed=ctx.changed_files,
        )

        findings: list[Finding] = []

        # Base drift: only when an explicit pinned_merge_base SHA is declared.
        if pinned_mb and pinned_mb != actual_mb:
            findings.append(
                _finding(
                    rule=_RULE_BASE_DRIFT,
                    rel=".",
                    line=1,
                    symbol="diff_range.pinned_merge_base",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    message=(
                        f"Pinned merge-base {pinned_mb[:12]} differs from the "
                        f"actual merge-base {actual_mb[:12]} (base drift). "
                        f"Re-pin diff_range.pinned_merge_base to the true "
                        f"merge-base before review."
                    ),
                    snippet=f"pinned={pinned_mb[:12]} actual={actual_mb[:12]}",
                    metadata={
                        "rule_id": _RULE_BASE_DRIFT,
                        "pinned_merge_base": pinned_mb,
                        "actual_merge_base": actual_mb,
                        "base_ref": str(base_ref or ""),
                    },
                )
            )

        in_scope_changed: list[str] = []
        for path in changed:
            if _is_declared(path, expected_files, paths_in_scope):
                in_scope_changed.append(path)
            else:
                findings.append(
                    _finding(
                        rule=_RULE_CONTAMINATION,
                        rel=path,
                        line=1,
                        symbol=path,
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        message=(
                            f"Changed file {path!r} is not declared in the patch "
                            f"manifest scope (files_expected_to_change / "
                            f"paths_in_scope). Scope contamination — update the "
                            f"manifest or remove the file from this change."
                        ),
                        snippet=path,
                        metadata={
                            "rule_id": _RULE_CONTAMINATION,
                            "path": path,
                            "kind": "undeclared_changed",
                        },
                    )
                )

        if changed:
            coverage = 100.0 * (len(in_scope_changed) / len(changed))
        else:
            coverage = 100.0

        floor = _coverage_floor(min_coverage)
        # Two independent metrics, one threshold. scope coverage = share of the
        # real diff that was declared; file_context_coverage_percent = the
        # author's declaration of how much file context they reviewed. Report
        # whichever actually tripped so the message is never misleading.
        causes: list[str] = []
        if coverage < floor:
            causes.append(
                f"in-scope changed {len(in_scope_changed)}/{len(changed)} "
                f"= {coverage:.1f}%"
            )
        if declared_coverage < floor:
            causes.append(
                f"manifest file_context_coverage_percent={declared_coverage:.1f}%"
            )
        if causes:
            findings.append(
                _finding(
                    rule=_RULE_COVERAGE,
                    rel=".",
                    line=1,
                    symbol="scope_coverage",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    message=(
                        f"Declared-scope coverage is below the {floor:.0f}% "
                        f"threshold ({'; '.join(causes)}). Tighten the change "
                        f"set or expand the declared scope."
                    ),
                    snippet=f"coverage={coverage:.1f}% declared={declared_coverage:.1f}%",
                    metadata={
                        "rule_id": _RULE_COVERAGE,
                        "coverage_percent": coverage,
                        "declared_coverage_percent": declared_coverage,
                        "threshold_percent": floor,
                        "changed_count": len(changed),
                        "in_scope_changed_count": len(in_scope_changed),
                        "triggered_by": (
                            ["scope_coverage"] if coverage < floor else []
                        ) + (
                            ["file_context_coverage"]
                            if declared_coverage < floor
                            else []
                        ),
                    },
                )
            )

        findings.sort(
            key=lambda f: (f.location.path, f.location.line_start, f.fingerprint)
        )
        return findings


# ── errors / helpers ────────────────────────────────────────────────


class PrScopeUncheckable(RuntimeError):
    """Raised when review context is active but the check cannot run."""

    def __init__(self, message: str, *, kind: str):
        super().__init__(message)
        self.kind = kind


def _norm(value: str) -> str:
    """Normalize a manifest/git path to a repo-relative POSIX form."""
    path = str(value).strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _coverage_floor(min_coverage: float) -> float:
    """Effective coverage threshold.

    ``scope.min_coverage_percent`` may only *tighten* the contract floor. Using
    ``min()`` here would let a manifest declare ``min_coverage_percent: 50`` and
    opt itself out of the 95% acceptance criterion, while silently clamping an
    intentionally strict ``100`` back down to 95 — i.e. the field would only
    work in the direction that weakens the gate.
    """
    return max(min_coverage, _DEFAULT_MIN_COVERAGE)


def _as_mapping(value: Any, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PrScopeUncheckable(
            f"manifest field {field!r} must be an object, got "
            f"{type(value).__name__}",
            kind="malformed_manifest",
        )
    return value


def _as_str_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
        raise PrScopeUncheckable(
            f"manifest field {field!r} must be an array of strings",
            kind="malformed_manifest",
        )
    return value


def _as_opt_str(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PrScopeUncheckable(
            f"manifest field {field!r} must be a string, got "
            f"{type(value).__name__}",
            kind="malformed_manifest",
        )
    return value.strip() or None


def _as_percent(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PrScopeUncheckable(
            f"manifest field {field!r} must be a number between 0 and 100",
            kind="malformed_manifest",
        )
    number = float(value)
    if not 0.0 <= number <= 100.0:
        raise PrScopeUncheckable(
            f"manifest field {field!r} must be between 0 and 100, got {number:g}",
            kind="malformed_manifest",
        )
    return number


def _load_manifest(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise PrScopeUncheckable(
            f"scope manifest not found: {path}", kind="missing_manifest"
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PrScopeUncheckable(
            f"scope manifest unreadable: {path} ({exc})", kind="missing_manifest"
        ) from exc
    if not isinstance(data, dict):
        raise PrScopeUncheckable(
            f"scope manifest must be a JSON object: {path}",
            kind="missing_manifest",
        )
    return data


def _check_schema_version(manifest: dict[str, Any], path: Path) -> None:
    """Reject non-v2 manifests loudly.

    A v1 manifest parses fine but carries no ``pinned_merge_base`` and no
    ``min_coverage_percent``, so the base-drift check would silently no-op and
    the scan would look clean for the wrong reason.
    """
    version = manifest.get("schema_version")
    if version != _SCHEMA_VERSION:
        raise PrScopeUncheckable(
            f"scope manifest {path} declares schema_version={version!r}; "
            f"pr_scope requires {_SCHEMA_VERSION!r}",
            kind="schema_version_mismatch",
        )


def _resolve_git_surface(
    root: Path,
    *,
    base_ref: str,
    override_mb: str | None,
    override_changed: list[str] | None,
) -> tuple[str, list[str]]:
    if override_changed is not None and override_mb is not None:
        return override_mb, sorted({_norm(p) for p in override_changed})

    mb = override_mb or _git_merge_base(root, base_ref)
    if override_changed is not None:
        changed = sorted({_norm(p) for p in override_changed})
    else:
        changed = _git_diff_names(root, mb)
    return mb, changed


def _is_declared(
    path: str, expected_files: list[str], paths_in_scope: list[str]
) -> bool:
    norm = _norm(path)
    if norm in expected_files:
        return True
    for prefix in paths_in_scope:
        p = _norm(prefix)
        if not p:
            continue
        if norm == p.rstrip("/"):
            return True
        if not p.endswith("/"):
            p = p + "/"
        if norm.startswith(p):
            return True
    return False


def _git_merge_base(root: Path, base_ref: str) -> str:
    out = _run_git(root, "merge-base", "HEAD", base_ref)
    mb = out.strip()
    if not mb:
        raise PrScopeUncheckable(
            f"git merge-base HEAD {base_ref} returned empty "
            f"({_shallow_hint(root)})",
            kind="shallow_clone" if _is_shallow(root) else "unresolved_merge_base",
        )
    return mb


def _git_diff_names(root: Path, merge_base: str) -> list[str]:
    # -z: NUL-separated, unquoted paths. Without it git applies core.quotePath
    # and returns e.g. "src/\303\251.py" for non-ASCII names, which then fails
    # every scope comparison and reports a declared file as contamination.
    out = _run_git(root, "diff", "--name-only", "-z", f"{merge_base}..HEAD")
    return sorted({_norm(p) for p in out.split("\0") if p.strip()})


def _is_shallow(root: Path) -> bool:
    """Ask git directly instead of pattern-matching stderr prose."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"],
            cwd=str(root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and proc.stdout.strip().lower() == "true"


def _shallow_hint(root: Path) -> str:
    if _is_shallow(root):
        return "shallow clone — fetch with full history (fetch-depth: 0)"
    return "the base ref may not be fetched in this checkout"


def _run_git(root: Path, *args: str) -> str:
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
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PrScopeUncheckable(
            f"git {' '.join(args)} timed out after {_GIT_TIMEOUT_SECONDS:g}s",
            kind="git_timeout",
        ) from exc
    except OSError as exc:
        raise PrScopeUncheckable(
            f"git execution failed: {exc}", kind="git_diff_failed"
        ) from exc

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        low = err.lower()
        if "not a git repository" in low:
            kind = "unresolved_merge_base"
        elif _is_shallow(root):
            kind = "shallow_clone"
        elif "merge-base" in args:
            kind = "unresolved_merge_base"
        else:
            kind = "git_diff_failed"
        raise PrScopeUncheckable(
            f"git {' '.join(args)} failed (exit {proc.returncode}): {err}",
            kind=kind,
        )
    return proc.stdout


def _uncheckable_finding(message: str, kind: str) -> Finding:
    return _finding(
        rule=_RULE_UNCHECKABLE,
        rel=".",
        line=1,
        symbol=kind,
        severity=Severity.CRITICAL,
        confidence=1.0,
        message=(
            f"pr_scope cannot be checked ({kind}): {message}. "
            f"Failing loud — never treat an uncheckable review as a clean pass."
        ),
        snippet=kind,
        metadata={"rule_id": _RULE_UNCHECKABLE, "kind": kind},
    )


def _finding(
    *,
    rule: str,
    rel: str,
    line: int,
    symbol: str,
    severity: Severity,
    confidence: float,
    message: str,
    snippet: str,
    metadata: dict[str, Any],
) -> Finding:
    # Fingerprint deliberately excludes the snippet: it carries live percentages
    # and SHAs, and folding those in would mint a new identity for the same
    # problem on every run, defeating baselining and dedup.
    fp = make_fingerprint(rule, rel, symbol, "")
    return Finding(
        finding_id=fp,
        type=AnalyzerType.PR_SCOPE,
        severity=severity,
        confidence=confidence,
        message=message,
        location=Location(path=rel, line_start=line, line_end=line),
        fingerprint=fp,
        snippet=snippet[:80],
        metadata=metadata,
    )
