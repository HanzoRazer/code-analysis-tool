#!/usr/bin/env python3
"""
copy_lint_vibe_saas.py
Schema-aware copy linter for the beginner Vibe Coder SaaS i18n JSON structure.

Usage:
  python copy_lint_vibe_saas.py lint i18n/en --format text
  python copy_lint_vibe_saas.py lint i18n/en --format json
  python copy_lint_vibe_saas.py init-config > copylint.json
  python copy_lint_vibe_saas.py lint i18n/en --config copylint.json
Exit codes:
  0 = no errors
  1 = errors found
  2 = config/usage error
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

# ----------------------------
# Default config
# ----------------------------

DEFAULT_CONFIG: Dict[str, Any] = {
    "copy_lint": {
        # Hard disallowed (fail)
        "forbidden_words": [
            "bad", "wrong", "sloppy", "dangerous", "failed", "failure",
            "incorrect", "must", "ignore", "false positive", "error-prone",
            "invalid"
        ],
        "jargon_blacklist": [
            "cyclomatic", "mutation", "global state", "side effects",
            "race condition", "refactor", "polymorphism", "stack trace",
            "exception handling"
        ],
        "imperative_starts": [
            "fix this", "you must", "you should", "do this", "remove this", "delete this"
        ],

        # Reassurance required on yellow/red summaries (fail if missing)
        "reassurance_phrases": [
            "this is common",
            "you didn't do anything wrong",
            "you're not doing anything wrong",
            "it's okay to leave this for now",
            "it\u2019s okay to leave this for now",
            "this is fixable",
            "we'll help you",
            "we\u2019ll help you",
            "you're catching this early",
            "you\u2019re catching this early",
            "totally okay",
            "no rush"
        ],

        # Permission language recommended on optional signals footers (warn if missing)
        "permission_phrases": [
            "okay to leave",
            "safe to leave for now",
            "no rush",
            "totally fine to leave",
            "come back to this",
            "later is fine",
            "not now",
            "ship first"
        ],

        # Sentence length guidance
        "sentence_length": {"warn": 20, "error": 30},

        # Allowed button labels (strict)
        "allowed_buttons": {
            "primary": ["Fix now", "Let\u2019s fix this", "Let's fix this", "Secure this now", "Make errors visible", "Add guardrails"],
            "secondary": ["Later", "Not now", "Later is fine", "Ship first"],
            "tertiary": ["I get it", "That makes sense", "Got it", "Okay, understood"]
        },

        # Allowed action urgency values
        "allowed_action_urgency": ["optional", "recommended", "important"],

        # Which signal keys are considered "optional-ish" and should contain permission language in footer/action text
        "optional_signal_keys": ["complexity", "dead_code", "global_state"],

        # File name expectations (by basename)
        "files": {
            "signals.json": {"root_key": "signals"},
            "buttons.json": {"root_key": "buttons"},
            "feedback.json": {"root_key": "feedback"},
            "compounds.json": {"root_key": "compounds"},
            "summaries.json": {"root_key": "summaries"}
        },

        "extensions": [".json"]
    }
}

# ----------------------------
# Diagnostics
# ----------------------------

@dataclass
class Diagnostic:
    level: str   # ERROR/WARN
    rule: str
    message: str
    file: str
    pointer: str  # JSON pointer, e.g. /signals/exceptions/summary
    excerpt: str

# ----------------------------
# Helpers
# ----------------------------

def load_config(path: Optional[str]) -> Dict[str, Any]:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if not path:
        return cfg
    with open(path, "r", encoding="utf-8") as f:
        user = json.load(f)
    if isinstance(user, dict) and "copy_lint" in user and isinstance(user["copy_lint"], dict):
        cfg["copy_lint"].update(user["copy_lint"])
    return cfg

def iter_files(root: str, exts: List[str]) -> List[str]:
    if os.path.isfile(root):
        return [root]
    out: List[str] = []
    exts_set = {e.lower() for e in exts}
    for dp, _, fns in os.walk(root):
        for fn in fns:
            if os.path.splitext(fn)[1].lower() in exts_set:
                out.append(os.path.join(dp, fn))
    return out

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")

def split_sentences(text: str) -> List[str]:
    t = text.strip()
    if not t:
        return []
    parts = [p.strip() for p in _SENTENCE_SPLIT_RE.split(t) if p.strip()]
    return parts if parts else [t]

def word_count(sentence: str) -> int:
    return len([w for w in re.split(r"\s+", sentence.strip()) if w])

def to_pointer(*parts: str) -> str:
    # JSON Pointer encoding
    enc = []
    for p in parts:
        enc.append(p.replace("~", "~0").replace("/", "~1"))
    return "/" + "/".join(enc)

def lower(s: str) -> str:
    return s.lower()

def contains_any(hay: str, needles: List[str]) -> bool:
    h = hay.lower()
    return any(n.lower() in h for n in needles)

def starts_with_any(text: str, starts: List[str]) -> Optional[str]:
    t = text.lstrip().lower()
    for s in starts:
        if t.startswith(s.lower()):
            return s
    return None

# ----------------------------
# Core lint: string rules
# ----------------------------

def lint_string_common(
    *,
    file: str,
    pointer: str,
    value: str,
    cfg: Dict[str, Any],
    field_kind: str
) -> List[Diagnostic]:
    """
    Common checks:
      - forbidden words (ERROR)
      - jargon blacklist (ERROR)
      - imperative sentence starts (ERROR) for most fields
      - sentence length (WARN/ERROR)
    """
    c = cfg["copy_lint"]
    forbidden = c["forbidden_words"]
    jargon = c["jargon_blacklist"]
    imperative = c["imperative_starts"]
    sl_warn = int(c["sentence_length"]["warn"])
    sl_err = int(c["sentence_length"]["error"])

    diags: List[Diagnostic] = []
    text = value.strip()

    # Forbidden words
    for w in forbidden:
        if w.lower() in text.lower():
            diags.append(Diagnostic(
                level="ERROR",
                rule="A1.forbidden_word",
                message=f"Forbidden word/phrase: '{w}'",
                file=file,
                pointer=pointer,
                excerpt=text[:180]
            ))

    # Jargon
    for j in jargon:
        if j.lower() in text.lower():
            diags.append(Diagnostic(
                level="ERROR",
                rule="A3.jargon",
                message=f"Jargon not allowed in beginner-facing copy: '{j}'",
                file=file,
                pointer=pointer,
                excerpt=text[:180]
            ))

    # Imperative starts (not for tooltips maybe, but still applies gently)
    if field_kind not in {"icon"}:
        hit = starts_with_any(text, imperative)
        if hit:
            diags.append(Diagnostic(
                level="ERROR",
                rule="A2.imperative_command",
                message=f"Imperative command start not allowed: '{hit}\u2026'",
                file=file,
                pointer=pointer,
                excerpt=text[:180]
            ))

    # Sentence length
    for s in split_sentences(text):
        wc = word_count(s)
        if wc >= sl_err:
            diags.append(Diagnostic(
                level="ERROR",
                rule="B1.sentence_too_long",
                message=f"Sentence too long ({wc} words). Keep < {sl_err}.",
                file=file,
                pointer=pointer,
                excerpt=s[:200]
            ))
        elif wc > sl_warn:
            diags.append(Diagnostic(
                level="WARN",
                rule="B1.sentence_long",
                message=f"Sentence long ({wc} words). Prefer \u2264 {sl_warn}.",
                file=file,
                pointer=pointer,
                excerpt=s[:200]
            ))

    return diags

# ----------------------------
# File-specific validators
# ----------------------------

def lint_signals_like(
    *,
    file: str,
    root: Dict[str, Any],
    root_key: str,
    cfg: Dict[str, Any]
) -> List[Diagnostic]:
    """
    Validates signals.json and compounds.json (same shape).
    """
    c = cfg["copy_lint"]
    reass = c["reassurance_phrases"]
    perm = c["permission_phrases"]
    allowed_urgency = set(c["allowed_action_urgency"])
    optional_keys = set(c["optional_signal_keys"])

    diags: List[Diagnostic] = []

    if root_key not in root or not isinstance(root[root_key], dict):
        diags.append(Diagnostic("ERROR", "S0.schema", f"Missing top-level key '{root_key}'", file, "/", "(root)"))
        return diags

    for signal_key, obj in root[root_key].items():
        ptr_base = to_pointer(root_key, signal_key)

        if not isinstance(obj, dict):
            diags.append(Diagnostic("ERROR", "S0.schema", "Signal must be an object", file, ptr_base, str(obj)[:120]))
            continue

        # Required: risk_level, title, summary, why, action.text, action.urgency
        risk_level = obj.get("risk_level")
        if not isinstance(risk_level, str) or risk_level.lower() not in {"green", "yellow", "red"}:
            diags.append(Diagnostic("ERROR", "S0.schema", "risk_level must be green|yellow|red", file, ptr_base + "/risk_level", str(risk_level)))
            risk_level_norm = None
        else:
            risk_level_norm = risk_level.lower()

        def req_str(field: str) -> Optional[str]:
            v = obj.get(field)
            if not isinstance(v, str) or not v.strip():
                diags.append(Diagnostic("ERROR", "S0.schema", f"'{field}' must be a non-empty string", file, ptr_base + f"/{field}", str(v)))
                return None
            return v

        title = req_str("title")
        summary = req_str("summary")
        why = req_str("why")

        # action
        action = obj.get("action")
        if not isinstance(action, dict):
            diags.append(Diagnostic("ERROR", "S0.schema", "'action' must be an object", file, ptr_base + "/action", str(action)))
            action_text = None
            urgency = None
        else:
            action_text = action.get("text")
            if not isinstance(action_text, str) or not action_text.strip():
                diags.append(Diagnostic("ERROR", "S0.schema", "action.text must be a non-empty string", file, ptr_base + "/action/text", str(action_text)))
                action_text = None
            urgency = action.get("urgency")
            if not isinstance(urgency, str) or urgency not in allowed_urgency:
                diags.append(Diagnostic("ERROR", "S0.schema", f"action.urgency must be one of {sorted(allowed_urgency)}", file, ptr_base + "/action/urgency", str(urgency)))
                urgency = None

        footer = obj.get("footer")
        if footer is not None and (not isinstance(footer, str) or not footer.strip()):
            diags.append(Diagnostic("ERROR", "S0.schema", "footer must be a non-empty string if present", file, ptr_base + "/footer", str(footer)))
        footer_icon = obj.get("footer_icon")
        if footer_icon is not None and (not isinstance(footer_icon, str) or not footer_icon.strip()):
            diags.append(Diagnostic("ERROR", "S0.schema", "footer_icon must be a non-empty string if present", file, ptr_base + "/footer_icon", str(footer_icon)))

        # Content lint: title/summary/why/action.text/footer
        if title:
            diags += lint_string_common(file=file, pointer=ptr_base + "/title", value=title, cfg=cfg, field_kind="title")
            if len(title) > 60:
                diags.append(Diagnostic("WARN", "B5.title_length", "Title is long; aim for \u2264 60 characters.", file, ptr_base + "/title", title[:180]))

        if summary:
            diags += lint_string_common(file=file, pointer=ptr_base + "/summary", value=summary, cfg=cfg, field_kind="summary")
            # Required reassurance for yellow/red summaries
            if risk_level_norm in {"yellow", "red"}:
                if not contains_any(summary, reass):
                    diags.append(Diagnostic(
                        "ERROR", "A4.required_reassurance",
                        f"{root_key}.{signal_key} summary should include a reassurance phrase for risk_level={risk_level_norm}.",
                        file, ptr_base + "/summary", summary[:200]
                    ))

        if why:
            diags += lint_string_common(file=file, pointer=ptr_base + "/why", value=why, cfg=cfg, field_kind="body")

        if action_text:
            diags += lint_string_common(file=file, pointer=ptr_base + "/action/text", value=action_text, cfg=cfg, field_kind="action")
            # Prefer one action (warn if multi-step connective)
            low = action_text.lower()
            if any(tok in low for tok in [" and ", " then ", " also ", ", and "]):
                diags.append(Diagnostic("WARN", "B2.one_action_preferred", "Prefer a single action in action.text.", file, ptr_base + "/action/text", action_text[:200]))

        if isinstance(footer, str):
            diags += lint_string_common(file=file, pointer=ptr_base + "/footer", value=footer, cfg=cfg, field_kind="footer")
            # Permission language recommended for optional signals (warn) and yellow (warn)
            if (signal_key in optional_keys) or (risk_level_norm == "yellow"):
                if not contains_any(footer, perm):
                    diags.append(Diagnostic(
                        "WARN", "B4.permission_language_recommended",
                        "Footer should include permission language (e.g., 'Totally fine to leave for now').",
                        file, ptr_base + "/footer", footer[:200]
                    ))

        # Icons: allow emojis; still check not empty if present (already done)
        if isinstance(footer_icon, str):
            # No heavy lint; but forbid forbidden/jargon in icons is nonsense
            pass

    return diags

def lint_buttons(
    *,
    file: str,
    root: Dict[str, Any],
    cfg: Dict[str, Any]
) -> List[Diagnostic]:
    c = cfg["copy_lint"]
    allowed = c["allowed_buttons"]

    diags: List[Diagnostic] = []
    buttons = root.get("buttons")
    if not isinstance(buttons, dict):
        return [Diagnostic("ERROR", "S0.schema", "Missing top-level 'buttons' object", file, "/buttons", "(root)")]

    def lint_label(pointer: str, label: Any, kind: str) -> None:
        if not isinstance(label, str) or not label.strip():
            diags.append(Diagnostic("ERROR", "S0.schema", "label must be a non-empty string", file, pointer, str(label)))
            return
        if label not in set(allowed[kind]):
            diags.append(Diagnostic("ERROR", "C1.button_label_not_allowed", f"Label '{label}' not allowed for {kind}.", file, pointer, label))

    def lint_tooltip(pointer: str, tooltip: Any) -> None:
        if not isinstance(tooltip, str) or not tooltip.strip():
            diags.append(Diagnostic("ERROR", "S0.schema", "tooltip must be a non-empty string", file, pointer, str(tooltip)))
            return
        diags.extend(lint_string_common(file=file, pointer=pointer, value=tooltip, cfg=cfg, field_kind="tooltip"))

    # primary/secondary/tertiary variants
    for tier in ["primary", "secondary", "tertiary"]:
        tier_obj = buttons.get(tier)
        ptr_tier = to_pointer("buttons", tier)
        if not isinstance(tier_obj, dict):
            diags.append(Diagnostic("ERROR", "S0.schema", f"buttons.{tier} must be an object", file, ptr_tier, str(tier_obj)))
            continue
        for variant, vo in tier_obj.items():
            ptr_var = ptr_tier + "/" + variant
            if not isinstance(vo, dict):
                diags.append(Diagnostic("ERROR", "S0.schema", f"buttons.{tier}.{variant} must be an object", file, ptr_var, str(vo)))
                continue
            lint_label(ptr_var + "/label", vo.get("label"), tier)
            lint_tooltip(ptr_var + "/tooltip", vo.get("tooltip"))

    # subtext_by_risk
    sbr = buttons.get("subtext_by_risk")
    ptr_sbr = to_pointer("buttons", "subtext_by_risk")
    if not isinstance(sbr, dict):
        diags.append(Diagnostic("ERROR", "S0.schema", "buttons.subtext_by_risk must be an object", file, ptr_sbr, str(sbr)))
        return diags

    for risk in ["red", "yellow", "green"]:
        ro = sbr.get(risk)
        ptr_r = ptr_sbr + "/" + risk
        if not isinstance(ro, dict):
            diags.append(Diagnostic("ERROR", "S0.schema", f"subtext_by_risk.{risk} must be an object", file, ptr_r, str(ro)))
            continue
        for k in ["primary", "secondary", "tertiary"]:
            v = ro.get(k)
            ptr_k = ptr_r + "/" + k
            if not isinstance(v, str) or not v.strip():
                diags.append(Diagnostic("ERROR", "S0.schema", "must be a non-empty string", file, ptr_k, str(v)))
                continue
            diags.extend(lint_string_common(file=file, pointer=ptr_k, value=v, cfg=cfg, field_kind="subtext"))

    return diags

def lint_feedback(
    *,
    file: str,
    root: Dict[str, Any],
    cfg: Dict[str, Any]
) -> List[Diagnostic]:
    diags: List[Diagnostic] = []
    fb = root.get("feedback")
    if not isinstance(fb, dict):
        return [Diagnostic("ERROR", "S0.schema", "Missing top-level 'feedback' object", file, "/feedback", "(root)")]

    for key, obj in fb.items():
        ptr = to_pointer("feedback", key)
        if not isinstance(obj, dict):
            diags.append(Diagnostic("ERROR", "S0.schema", "Feedback entry must be an object", file, ptr, str(obj)))
            continue
        icon = obj.get("icon")
        text = obj.get("text")
        if not isinstance(icon, str) or not icon.strip():
            diags.append(Diagnostic("ERROR", "S0.schema", "icon must be a non-empty string", file, ptr + "/icon", str(icon)))
        if not isinstance(text, str) or not text.strip():
            diags.append(Diagnostic("ERROR", "S0.schema", "text must be a non-empty string", file, ptr + "/text", str(text)))
        else:
            diags.extend(lint_string_common(file=file, pointer=ptr + "/text", value=text, cfg=cfg, field_kind="feedback_text"))
    return diags

def lint_summaries(
    *,
    file: str,
    root: Dict[str, Any],
    cfg: Dict[str, Any]
) -> List[Diagnostic]:
    diags: List[Diagnostic] = []
    sm = root.get("summaries")
    if not isinstance(sm, dict):
        return [Diagnostic("ERROR", "S0.schema", "Missing top-level 'summaries' object", file, "/summaries", "(root)")]

    vibe_status = sm.get("vibe_status")
    if not isinstance(vibe_status, dict):
        diags.append(Diagnostic("ERROR", "S0.schema", "summaries.vibe_status must be an object", file, "/summaries/vibe_status", str(vibe_status)))
    else:
        for k in ["green", "yellow", "red"]:
            v = vibe_status.get(k)
            ptr = to_pointer("summaries", "vibe_status", k)
            if not isinstance(v, str) or not v.strip():
                diags.append(Diagnostic("ERROR", "S0.schema", "must be a non-empty string", file, ptr, str(v)))
            else:
                diags.extend(lint_string_common(file=file, pointer=ptr, value=v, cfg=cfg, field_kind="summary"))

    for k in ["empty_state", "first_scan_celebration"]:
        v = sm.get(k)
        ptr = to_pointer("summaries", k)
        if not isinstance(v, str) or not v.strip():
            diags.append(Diagnostic("ERROR", "S0.schema", "must be a non-empty string", file, ptr, str(v)))
        else:
            diags.extend(lint_string_common(file=file, pointer=ptr, value=v, cfg=cfg, field_kind="summary"))

    return diags

# ----------------------------
# Dispatch based on filename
# ----------------------------

def lint_file(path: str, cfg: Dict[str, Any]) -> List[Diagnostic]:
    base = os.path.basename(path)
    c = cfg["copy_lint"]
    expected = c["files"]

    with open(path, "r", encoding="utf-8") as f:
        try:
            root = json.load(f)
        except json.JSONDecodeError as e:
            return [Diagnostic("ERROR", "IO.invalid_json", f"Invalid JSON: {e}", path, "/", "(invalid json)")]

    if not isinstance(root, dict):
        return [Diagnostic("ERROR", "S0.schema", "Root must be a JSON object", path, "/", str(root)[:120])]

    if base == "signals.json":
        return lint_signals_like(file=path, root=root, root_key="signals", cfg=cfg)
    if base == "compounds.json":
        return lint_signals_like(file=path, root=root, root_key="compounds", cfg=cfg)
    if base == "buttons.json":
        return lint_buttons(file=path, root=root, cfg=cfg)
    if base == "feedback.json":
        return lint_feedback(file=path, root=root, cfg=cfg)
    if base == "summaries.json":
        return lint_summaries(file=path, root=root, cfg=cfg)

    # Unknown JSON: skip by default (or warn)
    return []

# ----------------------------
# CLI
# ----------------------------

def cmd_init_config() -> None:
    print(json.dumps(DEFAULT_CONFIG, indent=2, sort_keys=True))

def cmd_lint(paths: List[str], config_path: Optional[str], out_format: str, *, strict: bool = False) -> int:
    try:
        cfg = load_config(config_path)
    except Exception as e:
        print(f"[copy-lint] Config error: {e}", file=sys.stderr)
        return 2

    exts = cfg["copy_lint"].get("extensions", [".json"])
    files: List[str] = []
    for p in paths:
        files.extend(iter_files(p, exts))
    files = sorted(set(files))

    if not files:
        print("[copy-lint] No JSON files found.", file=sys.stderr)
        return 0

    all_diags: List[Diagnostic] = []
    for fp in files:
        all_diags.extend(lint_file(fp, cfg))

    errors = sum(1 for d in all_diags if d.level == "ERROR")
    warnings = sum(1 for d in all_diags if d.level == "WARN")

    if strict:
        # Promote warnings to errors for exit-code purposes
        effective_errors = errors + warnings
    else:
        effective_errors = errors

    if out_format == "json":
        payload = {
            "tool": "copy_lint_vibe_saas",
            "version": "0.2.0",
            "strict": strict,
            "errors": errors,
            "warnings": warnings,
            "diagnostics": [asdict(d) for d in all_diags],
        }
        print(json.dumps(payload, indent=2))
    else:
        for d in all_diags:
            print(f"{d.file}#{d.pointer} [{d.level}] {d.rule} - {d.message}\n  {d.excerpt}")
        mode = "STRICT" if strict else "normal"
        print(f"\n[copy-lint] mode={mode}, errors={errors}, warnings={warnings}")
        if strict and warnings:
            print(f"  ⚠ --strict: {warnings} warning(s) promoted to errors")

    return 1 if effective_errors else 0

def main() -> None:
    parser = argparse.ArgumentParser(prog="copy_lint_vibe_saas")
    sub = parser.add_subparsers(dest="cmd")

    p_lint = sub.add_parser("lint", help="Lint i18n JSON copy files")
    p_lint.add_argument("paths", nargs="+", help="Files or directories")
    p_lint.add_argument("--config", default=None, help="Path to config JSON")
    p_lint.add_argument("--format", default="text", choices=["text", "json"])
    p_lint.add_argument("--strict", action="store_true", help="Treat warnings as errors (use on main/release branches)")

    sub.add_parser("init-config", help="Print default config JSON")

    args = parser.parse_args()
    if args.cmd == "init-config":
        cmd_init_config()
        return
    if args.cmd == "lint":
        raise SystemExit(cmd_lint(args.paths, args.config, args.format, strict=args.strict))
    parser.print_help()
    raise SystemExit(2)

if __name__ == "__main__":
    main()
