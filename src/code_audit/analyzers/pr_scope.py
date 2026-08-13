"""PR-scope / CBSP21 scope-contract detector.

Compares the real ``merge-base..HEAD`` changed-file set against a declared
CBSP21/RPMCC24 patch manifest (``patch_input_v2``) and fails loudly when the
check itself cannot be performed.

**Ordinary scans without review context remain silent** (return ``[]``).
Review context is activated by constructing the analyzer with a
``review_context`` (manifest path, optional git overrides for tests, optional
base ref).

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

_DEFAULT_MIN_COVERAGE = 95.0


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
    version: str = "1.0.0"

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
        if self._ctx is None:
            return []

        manifest_path = Path(self._ctx.manifest_path)
        if not manifest_path.is_absolute():
            manifest_path = (root / manifest_path).resolve()

        try:
            manifest = _load_manifest(manifest_path)
        except PrScopeUncheckable as exc:
            return [_uncheckable_finding(str(exc), exc.kind)]

        scope = manifest.get("scope") or {}
        paths_in_scope = [
            str(p).replace("\\", "/") for p in (scope.get("paths_in_scope") or [])
        ]
        expected_files = [
            str(p).replace("\\", "/")
            for p in (scope.get("files_expected_to_change") or [])
        ]
        min_coverage = float(scope.get("min_coverage_percent", _DEFAULT_MIN_COVERAGE))
        declared_coverage = float(manifest.get("file_context_coverage_percent", 100.0))

        diff_range = manifest.get("diff_range") or {}
        base_ref = self._ctx.base_ref or diff_range.get("base")
        pinned_mb = (diff_range.get("pinned_merge_base") or "").strip() or None
        if not base_ref and not pinned_mb:
            return [
                _uncheckable_finding(
                    "manifest diff_range.base / pinned_merge_base is empty",
                    "missing_pinned_base",
                )
            ]

        try:
            actual_mb, changed = _resolve_git_surface(
                root,
                base_ref=str(base_ref or "HEAD"),
                override_mb=self._ctx.actual_merge_base,
                override_changed=self._ctx.changed_files,
            )
        except PrScopeUncheckable as exc:
            return [_uncheckable_finding(str(exc), exc.kind)]

        findings: list[Finding] = []

        # Base drift: only when an explicit pinned_merge_base SHA is declared.
        if pinned_mb and pinned_mb != actual_mb:
            findings.append(
                _finding(
                    rule=_RULE_BASE_DRIFT,
                    rel=".",
                    line=1,
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

        coverage_floor = min(min_coverage, 95.0)
        if coverage < coverage_floor or declared_coverage < coverage_floor:
            findings.append(
                _finding(
                    rule=_RULE_COVERAGE,
                    rel=".",
                    line=1,
                    severity=Severity.HIGH,
                    confidence=0.9,
                    message=(
                        f"Declared-scope coverage is below 95% "
                        f"(in-scope changed {len(in_scope_changed)}/{len(changed)} "
                        f"= {coverage:.1f}%; manifest "
                        f"file_context_coverage_percent={declared_coverage:.1f}%; "
                        f"threshold={coverage_floor:.0f}%). Tighten the change set "
                        f"or expand the declared scope."
                    ),
                    snippet=f"coverage={coverage:.1f}% declared={declared_coverage:.1f}%",
                    metadata={
                        "rule_id": _RULE_COVERAGE,
                        "coverage_percent": coverage,
                        "declared_coverage_percent": declared_coverage,
                        "threshold_percent": coverage_floor,
                        "changed_count": len(changed),
                        "in_scope_changed_count": len(in_scope_changed),
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


def _resolve_git_surface(
    root: Path,
    *,
    base_ref: str,
    override_mb: str | None,
    override_changed: list[str] | None,
) -> tuple[str, list[str]]:
    if override_changed is not None and override_mb is not None:
        changed = sorted({p.replace("\\", "/") for p in override_changed})
        return override_mb, changed

    mb = override_mb or _git_merge_base(root, base_ref)
    if override_changed is not None:
        changed = sorted({p.replace("\\", "/") for p in override_changed})
    else:
        changed = _git_diff_names(root, mb)
    return mb, changed


def _is_declared(
    path: str, expected_files: list[str], paths_in_scope: list[str]
) -> bool:
    norm = path.replace("\\", "/")
    if norm in expected_files:
        return True
    for prefix in paths_in_scope:
        p = prefix.replace("\\", "/")
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
            f"(shallow clone? fetch the base ref)",
            kind="unresolved_merge_base",
        )
    return mb


def _git_diff_names(root: Path, merge_base: str) -> list[str]:
    out = _run_git(root, "diff", "--name-only", f"{merge_base}...HEAD")
    return sorted({line.replace("\\", "/") for line in out.splitlines() if line.strip()})


def _run_git(root: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise PrScopeUncheckable(
            f"git execution failed: {exc}", kind="git_diff_failed"
        ) from exc

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        kind = "git_diff_failed"
        low = err.lower()
        if "not a git repository" in low:
            kind = "unresolved_merge_base"
        elif "shallow" in low or "not enough" in low or "no merge base" in low:
            kind = "shallow_clone"
        elif "merge-base" in " ".join(args):
            kind = "unresolved_merge_base"
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
    severity: Severity,
    confidence: float,
    message: str,
    snippet: str,
    metadata: dict[str, Any],
) -> Finding:
    fp = make_fingerprint(rule, rel, rule, snippet)
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
