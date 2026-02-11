#!/usr/bin/env python3
"""
copy_lint.py - Confidence-first copy linter for beginner Vibe Coder SaaS.

Usage:
  python copy_lint.py lint path/to/file_or_dir [--config copylint.yaml] [--format text|json]
  python copy_lint.py init-config > copylint.yaml

Exit codes:
  0 = no errors
  1 = errors found
  2 = bad usage / config error
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
# Defaults (can be overridden)
# ----------------------------

DEFAULT_CONFIG: Dict[str, Any] = {
    "copy_lint": {
        "forbidden_words": [
            "bad", "wrong", "sloppy", "dangerous", "failed", "failure",
            "incorrect", "must", "ignore", "false positive", "error-prone",
            "invalid"
        ],
        "imperative_starts": [
            "fix this", "you must", "you should", "do this", "remove this",
            "delete this"
        ],
        "jargon_blacklist": [
            "cyclomatic", "mutation", "global state", "side effects",
            "race condition", "refactor", "polymorphism", "stack trace",
            "exception handling"
        ],
        "required_reassurance": {
            "risk_levels": ["yellow", "red"],
            "phrases": [
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
            ]
        },
        "sentence_length": {"warn": 20, "error": 30},
        "allowed_buttons": {
            "primary": ["Fix now", "Let's fix this", "Secure this now", "Add guardrails", "Make errors visible"],
            "secondary": ["Later", "Not now", "Later is fine", "Ship first"],
            "tertiary": ["I get it", "That makes sense", "Got it", "Okay, understood"]
        },
        "file_globs": [
            ".md", ".txt", ".json", ".yaml", ".yml", ".ts", ".tsx", ".js", ".jsx"
        ],
        "json_string_fields_only": False
    }
}

# ----------------------------
# Diagnostics
# ----------------------------

@dataclass
class Diagnostic:
    level: str  # "ERROR" or "WARN"
    rule: str
    message: str
    file: str
    line: int
    col: int
    excerpt: str

# ----------------------------
# Minimal YAML loader (optional)
# ----------------------------

def try_load_yaml(path: str) -> Optional[Dict[str, Any]]:
    """
    Tries to load YAML config if PyYAML is installed.
    If not installed, returns None.
    """
    try:
        import yaml  # type: ignore
    except Exception:
        return None

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else None

def load_config(path: Optional[str]) -> Dict[str, Any]:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if not path:
        return cfg

    if not os.path.exists(path):
        raise FileNotFoundError(f"Config not found: {path}")

    if path.lower().endswith(".json"):
        with open(path, "r", encoding="utf-8") as f:
            user = json.load(f)
    elif path.lower().endswith((".yml", ".yaml")):
        user = try_load_yaml(path)
        if user is None:
            raise RuntimeError(
                "YAML config provided but PyYAML is not installed. "
                "Install with: pip install pyyaml"
            )
    else:
        raise ValueError("Config must be .json, .yml, or .yaml")

    # shallow merge at top-level + nested copy_lint
    if isinstance(user, dict):
        if "copy_lint" in user and isinstance(user["copy_lint"], dict):
            cfg["copy_lint"].update(user["copy_lint"])
        for k, v in user.items():
            if k != "copy_lint":
                cfg[k] = v
    return cfg

# ----------------------------
# Helpers
# ----------------------------

CODE_FENCE_RE = re.compile(r"^```")

def iter_files(root: str, exts: List[str]) -> List[str]:
    files: List[str] = []
    if os.path.isfile(root):
        return [root]
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            _, ext = os.path.splitext(fn)
            if ext.lower() in {e.lower() for e in exts}:
                files.append(os.path.join(dirpath, fn))
    return files

def strip_markdown_code_fences(lines: List[str]) -> List[Tuple[int, str]]:
    """
    Returns list of (original_line_number, line_text) excluding fenced code blocks.
    """
    out: List[Tuple[int, str]] = []
    in_fence = False
    for i, line in enumerate(lines, start=1):
        if CODE_FENCE_RE.match(line.strip()):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append((i, line))
    return out

def detect_risk_level(lines: List[str]) -> Optional[str]:
    """
    Simple hinting system:
    If file contains a line like:
      risk_level: red
    anywhere in first ~60 lines, we treat it as tagged.
    Useful for UI content files with metadata/frontmatter.
    """
    max_scan = min(len(lines), 60)
    pat = re.compile(r"\brisk_level\s*:\s*(red|yellow|green)\b", re.IGNORECASE)
    for i in range(max_scan):
        m = pat.search(lines[i])
        if m:
            return m.group(1).lower()
    return None

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")

def sentences_with_positions(text: str) -> List[Tuple[str, int]]:
    """
    Returns list of (sentence, start_index).
    Approximate, good enough for lint.
    """
    sents: List[Tuple[str, int]] = []
    idx = 0
    for chunk in _SENTENCE_SPLIT_RE.split(text):
        chunk = chunk.strip()
        if not chunk:
            continue
        start = text.find(chunk, idx)
        if start < 0:
            start = idx
        sents.append((chunk, start))
        idx = start + len(chunk)
    return sents

def word_count(sentence: str) -> int:
    return len([w for w in re.split(r"\s+", sentence.strip()) if w])

def find_all_case_insensitive(hay: str, needle: str) -> List[int]:
    """
    Return starting indices of all occurrences (case-insensitive).
    """
    hay_l = hay.lower()
    ned_l = needle.lower()
    idxs = []
    start = 0
    while True:
        pos = hay_l.find(ned_l, start)
        if pos == -1:
            break
        idxs.append(pos)
        start = pos + max(1, len(ned_l))
    return idxs

def excerpt_at(line: str, col: int, width: int = 80) -> str:
    if col < 0:
        col = 0
    start = max(0, col - 20)
    end = min(len(line), start + width)
    return line[start:end].rstrip("\n")

# ----------------------------
# Lint rules
# ----------------------------

def lint_text(file_path: str, raw: str, cfg: Dict[str, Any]) -> List[Diagnostic]:
    c = cfg["copy_lint"]
    forbidden = c.get("forbidden_words", [])
    jargon = c.get("jargon_blacklist", [])
    imperative_starts = c.get("imperative_starts", [])
    sentence_len_warn = int(c.get("sentence_length", {}).get("warn", 20))
    sentence_len_err = int(c.get("sentence_length", {}).get("error", 30))
    req_reass = c.get("required_reassurance", {})
    reass_levels = set([x.lower() for x in req_reass.get("risk_levels", [])])
    reass_phrases = [p.lower() for p in req_reass.get("phrases", [])]

    allowed_buttons = c.get("allowed_buttons", {})
    allowed_button_set = set()
    for k in ("primary", "secondary", "tertiary"):
        for lbl in allowed_buttons.get(k, []) or []:
            allowed_button_set.add(lbl)

    lines = raw.splitlines(True)  # keep endings
    risk_level = detect_risk_level(lines)

    # For markdown: skip fenced blocks
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".md":
        visible_lines = strip_markdown_code_fences(lines)
    else:
        visible_lines = list(enumerate(lines, start=1))

    diags: List[Diagnostic] = []

    # Collect content for reassurance checks (visible only)
    visible_text = "".join([ln for _, ln in visible_lines]).lower()

    # A4 required reassurance if risk_level is yellow/red
    if risk_level and risk_level.lower() in reass_levels:
        if not any(phrase in visible_text for phrase in reass_phrases):
            diags.append(Diagnostic(
                level="ERROR",
                rule="A4.required_reassurance",
                message=f"risk_level={risk_level} requires at least one reassurance phrase.",
                file=file_path,
                line=1,
                col=0,
                excerpt="(file-level)"
            ))

    # Scan line-by-line for forbidden/jargon/imperative/button labels
    for (lineno, line) in visible_lines:
        l = line.rstrip("\n")
        l_lower = l.lower()

        # A1 forbidden words
        for w in forbidden:
            for pos in find_all_case_insensitive(l, w):
                diags.append(Diagnostic(
                    level="ERROR",
                    rule="A1.forbidden_word",
                    message=f"Forbidden word/phrase: '{w}'",
                    file=file_path,
                    line=lineno,
                    col=pos,
                    excerpt=excerpt_at(l, pos)
                ))

        # A3 jargon blacklist
        for j in jargon:
            for pos in find_all_case_insensitive(l, j):
                diags.append(Diagnostic(
                    level="ERROR",
                    rule="A3.jargon",
                    message=f"Jargon not allowed in beginner-facing copy: '{j}'",
                    file=file_path,
                    line=lineno,
                    col=pos,
                    excerpt=excerpt_at(l, pos)
                ))

        # A2 imperative starts (approx: check trimmed lower)
        trimmed = l.strip()
        trimmed_lower = trimmed.lower()
        for s in imperative_starts:
            if trimmed_lower.startswith(s):
                diags.append(Diagnostic(
                    level="ERROR",
                    rule="A2.imperative_command",
                    message=f"Imperative command start not allowed: '{s}…'",
                    file=file_path,
                    line=lineno,
                    col=max(0, l_lower.find(trimmed_lower)),
                    excerpt=trimmed[:80]
                ))

        # C1 allowed button labels (heuristic: lines that look like button labels)
        m = re.search(r'\b(button|label)\s*:\s*["\']?([^"\']+)["\']?\s*$', l, re.IGNORECASE)
        if m:
            label = m.group(2).strip()
            if label and label not in allowed_button_set:
                diags.append(Diagnostic(
                    level="ERROR",
                    rule="C1.button_label_not_allowed",
                    message=f"Button label '{label}' is not in allowed set.",
                    file=file_path,
                    line=lineno,
                    col=m.start(2),
                    excerpt=excerpt_at(l, m.start(2))
                ))

        # C2 negative button labels in list items
        m2 = re.match(r'^\s*[-*]\s+(.+?)\s*$', l)
        if m2:
            candidate = m2.group(1).strip()
            if candidate in {"Ignore", "Dismiss", "Skip", "Not important", "False positive"}:
                diags.append(Diagnostic(
                    level="ERROR",
                    rule="C2.negative_button",
                    message=f"Negative button label not allowed: '{candidate}'",
                    file=file_path,
                    line=lineno,
                    col=l.find(candidate),
                    excerpt=excerpt_at(l, l.find(candidate))
                ))

    # B1 sentence length (warn/error)
    for (lineno, line) in visible_lines:
        text = line.strip()
        if not text:
            continue
        for sent, _start in sentences_with_positions(text):
            wc = word_count(sent)
            if wc >= sentence_len_err:
                diags.append(Diagnostic(
                    level="ERROR",
                    rule="B1.sentence_too_long",
                    message=f"Sentence too long ({wc} words). Keep ≤ {sentence_len_err - 1}.",
                    file=file_path,
                    line=lineno,
                    col=max(0, line.find(sent.strip().split()[0])),
                    excerpt=sent[:120]
                ))
            elif wc > sentence_len_warn:
                diags.append(Diagnostic(
                    level="WARN",
                    rule="B1.sentence_long",
                    message=f"Sentence long ({wc} words). Prefer ≤ {sentence_len_warn}.",
                    file=file_path,
                    line=lineno,
                    col=max(0, line.find(sent.strip().split()[0])),
                    excerpt=sent[:120]
                ))

    return diags

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

    exts = cfg["copy_lint"].get("file_globs", [])
    all_files: List[str] = []
    for p in paths:
        all_files.extend(iter_files(p, exts))

    if not all_files:
        print("[copy-lint] No matching files found.", file=sys.stderr)
        return 0

    all_diags: List[Diagnostic] = []
    for fp in sorted(set(all_files)):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                raw = f.read()
        except UnicodeDecodeError:
            with open(fp, "r", encoding="latin-1") as f:
                raw = f.read()
        except Exception as e:
            all_diags.append(Diagnostic(
                level="ERROR",
                rule="IO.read_failed",
                message=f"Failed to read file: {e}",
                file=fp,
                line=1,
                col=0,
                excerpt="(unreadable)"
            ))
            continue

        all_diags.extend(lint_text(fp, raw, cfg))

    # Output
    errors = sum(1 for d in all_diags if d.level == "ERROR")
    warnings = sum(1 for d in all_diags if d.level == "WARN")

    if strict:
        effective_errors = errors + warnings
    else:
        effective_errors = errors

    if out_format == "json":
        payload = {
            "tool": "copy_lint",
            "version": "0.1.0",
            "strict": strict,
            "errors": errors,
            "warnings": warnings,
            "diagnostics": [asdict(d) for d in all_diags],
        }
        print(json.dumps(payload, indent=2))
    else:
        for d in all_diags:
            print(f"{d.file}:{d.line}:{d.col} [{d.level}] {d.rule} - {d.message}\n  {d.excerpt}")
        mode = "STRICT" if strict else "normal"
        print(f"\n[copy-lint] mode={mode}, errors={errors}, warnings={warnings}")
        if strict and warnings:
            print(f"  \u26a0 --strict: {warnings} warning(s) promoted to errors")

    return 1 if effective_errors else 0

def main() -> None:
    parser = argparse.ArgumentParser(prog="copy_lint", add_help=True)
    sub = parser.add_subparsers(dest="cmd")

    p_lint = sub.add_parser("lint", help="Lint files or directories")
    p_lint.add_argument("paths", nargs="+", help="Files or directories to lint")
    p_lint.add_argument("--config", default=None, help="Path to copylint.yaml or copylint.json")
    p_lint.add_argument("--format", default="text", choices=["text", "json"], help="Output format")
    p_lint.add_argument("--strict", action="store_true", help="Treat warnings as errors (use on main/release branches)")

    sub.add_parser("init-config", help="Print default config JSON to stdout")

    args = parser.parse_args()

    if args.cmd == "init-config":
        cmd_init_config()
        return
    if args.cmd == "lint":
        rc = cmd_lint(args.paths, args.config, args.format, strict=args.strict)
        raise SystemExit(rc)

    parser.print_help()
    raise SystemExit(2)

if __name__ == "__main__":
    main()
