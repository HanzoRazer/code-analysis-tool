"""Unit tests for the unguarded stdout-encoding detector (the cp1252 class).

A CLI entry module that writes non-ASCII to stdout/stderr with no UTF-8 guard
fails on Windows when the stream is a pipe/redirect/capture: an encode crash on
stdout for characters outside cp1252, backslash escapes on stderr, and cp1252
bytes a UTF-8 reader cannot decode for characters cp1252 can encode.

Born-from acceptance tests reproduce the three witnessed instances:
  - CAM-Assist-Blueprint: U+2192 arrow in subprocess stdout (encode crash);
  - code-audit's own ``__main__.py`` before fix/utf8-stdout-cp1252: emoji and
    em-dash on stderr, the emoji reached through a ``dict.get`` two bindings away;
  - the AGENTS.md scaffolder (MAINT-DEFER-015): ``--dry-run`` prints ``content``
    assembled from a template holding U+2500 -- not traceable to the sink, so it
    must still fire at the LOW tier.
Each has a guarded twin that must stay silent.
"""
from __future__ import annotations

from pathlib import Path

from code_audit.analyzers.unguarded_stdout_encoding import (
    UnguardedStdoutEncodingAnalyzer,
)
from code_audit.model import AnalyzerType, Severity

ARROW = "U+2192 RIGHTWARDS ARROW"
EM_DASH = "U+2014 EM DASH"
BOX = "U+2500 BOX DRAWINGS LIGHT HORIZONTAL"


def _run(tmp_path: Path, source: str, name: str = "cli.py"):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return UnguardedStdoutEncodingAnalyzer().run(tmp_path, [path])


def _one(tmp_path: Path, source: str, name: str = "cli.py"):
    found = _run(tmp_path, source, name)
    assert len(found) == 1, [f.metadata for f in found]
    return found[0]


# ── born-from acceptance: instance 1, CAM-Assist arrow (encode crash) ────

_CAM_ASSIST = (
    "import sys\n"
    "\n"
    "def main():\n"
    "    for a, b in [('rough', 'finish')]:\n"
    "        print(f'{a} \u2192 {b}')\n"
    "\n"
    "if __name__ == '__main__':\n"
    "    main()\n"
)


def test_acceptance_cam_assist_arrow_fires_high_encode_crash(tmp_path):
    f = _one(tmp_path, _CAM_ASSIST)
    assert f.type is AnalyzerType.UNGUARDED_STDOUT_ENCODING
    assert f.severity is Severity.LOW  # advisory v1
    assert f.metadata["confidence_tier"] == "high"
    assert f.metadata["failure_modes"] == ["encode_crash"]
    assert f.metadata["encode_crash_chars"] == [ARROW]
    assert f.metadata["traced_sites"] == [
        {"line": 5, "stream": "stdout", "chars": [ARROW]}
    ]
    assert f.location.line_start == 5
    assert f.finding_id  # non-empty (schema minLength)
    assert f.metadata["guard_confirmed"] is False


def test_acceptance_cam_assist_guarded_twin_silent(tmp_path):
    guarded = _CAM_ASSIST.replace(
        "def main():\n",
        "def main():\n    sys.stdout.reconfigure(encoding='utf-8')\n",
    )
    assert _run(tmp_path, guarded) == []


# ── instance 2, code-audit __main__.py (stderr, emoji via dict.get) ──────

_CODE_AUDIT_MAIN = (
    '"""Entry point \u2014 docstrings are never evidence unless read."""\n'
    "import sys\n"
    "\n"
    "_TIER_EMOJI = {'green': '\U0001f7e2', 'red': '\U0001f534'}\n"
    "\n"
    "def _print_human(summary):\n"
    "    tier = summary.get('vibe_tier')\n"
    "    emoji = _TIER_EMOJI.get(tier, '\u26aa')\n"
    "    print(f'{emoji}  Confidence', file=sys.stderr)\n"
    "    print('   red signal(s) \u2014 fix before shipping:', file=sys.stderr)\n"
    "\n"
    "def main(argv=None):\n"
    "    _print_human({})\n"
    "    return 0\n"
)

_FIX_BRANCH_GUARD = (
    "def main(argv=None):\n"
    "    for _stream in (sys.stdout, sys.stderr):\n"
    "        try:\n"
    "            _stream.reconfigure(encoding='utf-8')\n"
    "        except Exception:\n"
    "            pass\n"
)


def test_acceptance_code_audit_main_fires_on_stderr(tmp_path):
    f = _one(tmp_path, _CODE_AUDIT_MAIN, name="__main__.py")
    m = f.metadata
    assert m["entry_kind"] == "__main__.py"
    assert m["confidence_tier"] == "high"
    assert [s["stream"] for s in m["traced_sites"]] == ["stderr", "stderr"]
    # stderr never crashes (backslashreplace): emoji -> escapes, em-dash -> 0x97.
    assert m["failure_modes"] == ["escaped_output", "undecodable_bytes"]
    assert "encode_crash" not in m["failure_modes"]
    # the emoji is two bindings from the sink: emoji -> _TIER_EMOJI.get -> dict
    assert any("LARGE GREEN CIRCLE" in c for c in m["traced_sites"][0]["chars"])
    assert "U+26AA MEDIUM WHITE CIRCLE" in m["traced_sites"][0]["chars"]
    assert m["cp1252_mappable_chars"] == [EM_DASH]
    # the docstring's em-dash is not listed as untraced evidence
    assert m["untraced_constants"] == []


def test_acceptance_code_audit_fix_branch_loop_guard_silent(tmp_path):
    fixed = _CODE_AUDIT_MAIN.replace("def main(argv=None):\n", _FIX_BRANCH_GUARD)
    assert _run(tmp_path, fixed, name="__main__.py") == []


# ── instance 3, the scaffolder (template many steps from the sink) ───────

_SCAFFOLDER = (
    "import argparse\n"
    "\n"
    "_AGENTS = '''# Agent instructions\n"
    "<!-- INCIDENTS \u2500\u2500\u2500\u2500\u2500\u2500 -->\n"
    "'''\n"
    "\n"
    "def main():\n"
    "    ap = argparse.ArgumentParser()\n"
    "    ap.add_argument('--dry-run', action='store_true')\n"
    "    args = ap.parse_args()\n"
    "    agents = _AGENTS.format()\n"
    "    targets = [('AGENTS.md', agents)]\n"
    "    for rel, content in targets:\n"
    "        if args.dry_run:\n"
    "            print(f'--- would write {rel} ---')\n"
    "            print(content)\n"
    "    return 0\n"
    "\n"
    "if __name__ == '__main__':\n"
    "    raise SystemExit(main())\n"
)


def test_acceptance_scaffolder_template_fires_low(tmp_path):
    """``content`` is a loop variable over a list built from a template: not
    traceable, so the literal-in-print reading misses it. The LOW tier is what
    catches it -- and it must still name U+2500 as an encode-crash character."""
    f = _one(tmp_path, _SCAFFOLDER)
    m = f.metadata
    assert m["confidence_tier"] == "low"
    assert f.confidence < 0.5
    assert m["traced_sites"] == []
    assert m["failure_modes"] == []
    assert m["untraced_failure_modes"] == ["encode_crash"]
    assert m["encode_crash_chars"] == [BOX]
    assert m["untraced_constants"] == [{"line": 3, "chars": [BOX]}]
    # Anchored at the first unguarded opaque sink: line 15 prints the loop
    # variable ``rel``, one line before ``print(content)``.
    assert f.location.line_start == 15
    assert "would write" in f.snippet
    assert "not traced" in f.message


def test_acceptance_scaffolder_with_direct_em_dash_is_high(tmp_path):
    """The real scaffolder also prints em-dashes directly, which traces: HIGH,
    with the template's U+2500 still reported as untraced crash evidence."""
    src = _SCAFFOLDER.replace(
        "    return 0\n",
        "    print('SKIP \u2014 already exists')\n    return 0\n",
    )
    m = _one(tmp_path, src).metadata
    assert m["confidence_tier"] == "high"
    assert m["failure_modes"] == ["undecodable_bytes"]
    assert m["untraced_failure_modes"] == ["encode_crash"]
    assert m["encode_crash_chars"] == [BOX]
    assert m["cp1252_mappable_chars"] == [EM_DASH]


def test_acceptance_scaffolder_guarded_twin_silent(tmp_path):
    guarded = _SCAFFOLDER.replace(
        "import argparse\n", "import argparse\nimport sys\n"
    ).replace(
        "def main():\n",
        "def main():\n"
        "    sys.stdout.reconfigure(encoding='utf-8')\n"
        "    sys.stderr.reconfigure(encoding='utf-8')\n",
    )
    assert _run(tmp_path, guarded) == []


# ── silent controls ──────────────────────────────────────────────────────


def test_pure_ascii_cli_silent(tmp_path):
    src = "import sys\nif __name__ == '__main__':\n    print('ok -> done')\n"
    assert _run(tmp_path, src) == []


def test_library_module_is_not_an_entry(tmp_path):
    src = "def report(x):\n    print(f'{x} \u2192 done')\n"
    assert _run(tmp_path, src) == []


def test_print_to_a_file_is_not_a_std_stream(tmp_path):
    src = (
        "if __name__ == '__main__':\n"
        "    with open('out.txt', 'w', encoding='utf-8') as fh:\n"
        "        print('a \u2192 b', file=fh)\n"
    )
    assert _run(tmp_path, src) == []


def test_non_ascii_only_in_matcher_positions_silent(tmp_path):
    """Text that matches input rather than producing output is not evidence."""
    src = (
        "import re, sys\n"
        "_DASHES = re.compile('[\u2013\u2014]')\n"
        "def main():\n"
        "    line = sys.stdin.readline()\n"
        "    if line.startswith('\u2500') or line == '\u2192':\n"
        "        line = line.replace('\u2014', '-')\n"
        "    print(line)\n"
        "if __name__ == '__main__':\n"
        "    main()\n"
    )
    assert _run(tmp_path, src) == []


def test_non_ascii_only_in_docstrings_and_comments_silent(tmp_path):
    src = (
        '"""Tool \u2014 does things."""\n'
        "import sys\n"
        "# arrows \u2192 in comments are not in the AST\n"
        "def main(argv):\n"
        '    """Run it \u2014 really."""\n'
        "    print(argv[0])\n"
        "if __name__ == '__main__':\n"
        "    main(sys.argv)\n"
    )
    assert _run(tmp_path, src) == []


def test_module_docstring_is_evidence_when_printed_via_doc(tmp_path):
    src = (
        '"""Tool \u2192 does things."""\n'
        "import argparse\n"
        "def main():\n"
        "    ap = argparse.ArgumentParser(description=__doc__)\n"
        "    args = ap.parse_args()\n"
        "    print(args)\n"
    )
    m = _one(tmp_path, src).metadata
    assert m["confidence_tier"] == "low"
    assert m["untraced_constants"] == [{"line": 1, "chars": [ARROW]}]


def test_member_doc_read_does_not_release_the_module_docstring(tmp_path):
    """``cls.__doc__`` prints class docstrings, not the module docstring (the
    deployment.py false positive found while dogfooding)."""
    src = (
        '"""Deployment analyzer \u2014 module docstring, never printed."""\n'
        "import argparse\n"
        "class V:\n"
        '    """Checks things."""\n'
        "def main():\n"
        "    argparse.ArgumentParser().parse_args()\n"
        "    print(V.__doc__)\n"
    )
    assert _run(tmp_path, src) == []


def test_string_after_future_import_is_not_a_docstring_but_still_discarded(tmp_path):
    """A "docstring" after ``from __future__`` is a no-op expression statement
    (found dogfooding luthiers-toolbox): its value never reaches a stream."""
    src = (
        "from __future__ import annotations\n"
        '"""Checker — Fence-Aware Edition"""\n'
        "import sys\n"
        "def main(argv):\n"
        "    print(argv[1])\n"
        "if __name__ == '__main__':\n"
        "    main(sys.argv)\n"
    )
    assert _run(tmp_path, src) == []


def test_json_dumps_default_is_ascii_safe(tmp_path):
    """``json.dumps`` escapes non-ASCII unless ensure_ascii=False (found
    dogfooding luthiers-toolbox: a dict with U+00B7 printed via json.dumps)."""
    src = (
        "import json\n"
        "RESULT = {'subtitle': 'Classical · Tile'}\n"
        "if __name__ == '__main__':\n"
        "    print(json.dumps(RESULT, indent=2))\n"
    )
    assert _run(tmp_path, src) == []


def test_json_dumps_ensure_ascii_false_is_traced(tmp_path):
    src = (
        "from json import dumps as d\n"
        "RESULT = {'subtitle': 'a → b'}\n"
        "if __name__ == '__main__':\n"
        "    print(d(RESULT, ensure_ascii=False))\n"
    )
    m = _one(tmp_path, src).metadata
    assert m["confidence_tier"] == "high"
    assert m["encode_crash_chars"] == [ARROW]


def test_no_opaque_sink_means_untraced_text_cannot_reach_a_stream(tmp_path):
    src = (
        "_BANNER = 'x \u2192 y'\n"
        "def build():\n"
        "    return _BANNER\n"
        "if __name__ == '__main__':\n"
        "    print('done')\n"
    )
    assert _run(tmp_path, src) == []


def test_parameter_shadows_module_constant(tmp_path):
    """``def f(content): print(content)`` must not trace to a module constant
    that happens to share the name -- the parameter is opaque."""
    src = (
        "content = 'x \u2192 y'\n"
        "def show(content):\n"
        "    print(content)\n"
        "if __name__ == '__main__':\n"
        "    show('ascii')\n"
    )
    m = _one(tmp_path, src).metadata
    assert m["confidence_tier"] == "low"  # untraced, never HIGH
    assert m["traced_sites"] == []


# ── guards ───────────────────────────────────────────────────────────────


def test_guard_is_per_stream(tmp_path):
    src = (
        "import sys\n"
        "def main():\n"
        "    sys.stdout.reconfigure(encoding='utf-8')\n"
        "    print('ok \u2192 stdout')\n"
        "    print('bad \u2192 stderr', file=sys.stderr)\n"
        "if __name__ == '__main__':\n"
        "    main()\n"
    )
    m = _one(tmp_path, src).metadata
    assert m["guarded_streams"] == ["stdout"]
    assert m["unguarded_streams"] == ["stderr"]
    assert [s["line"] for s in m["traced_sites"]] == [5]
    assert m["failure_modes"] == ["escaped_output"]


def test_textiowrapper_rebind_is_a_guard(tmp_path):
    src = (
        "import io, sys\n"
        "sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')\n"
        "if __name__ == '__main__':\n"
        "    print('a \u2192 b')\n"
    )
    assert _run(tmp_path, src) == []


def test_errors_only_reconfigure_is_not_a_guard(tmp_path):
    """``errors='replace'`` stops the crash but still writes cp1252 bytes."""
    src = (
        "import sys\n"
        "sys.stdout.reconfigure(errors='replace')\n"
        "if __name__ == '__main__':\n"
        "    print('a \u2014 b')\n"
    )
    m = _one(tmp_path, src).metadata
    assert m["failure_modes"] == ["undecodable_bytes"]


def test_pythonioencoding_set_in_process_is_not_a_guard(tmp_path):
    src = (
        "import os\n"
        "os.environ['PYTHONIOENCODING'] = 'utf-8'\n"
        "if __name__ == '__main__':\n"
        "    print('a \u2192 b')\n"
    )
    assert _one(tmp_path, src).metadata["failure_modes"] == ["encode_crash"]


def test_from_sys_import_alias_is_resolved(tmp_path):
    src = (
        "from sys import stderr as err\n"
        "if __name__ == '__main__':\n"
        "    err.write('a \u2192 b\\n')\n"
    )
    m = _one(tmp_path, src).metadata
    assert m["traced_sites"][0]["stream"] == "stderr"


# ── entry detection & tracing bounds ─────────────────────────────────────


def test_cli_main_entry_without_name_guard(tmp_path):
    """A console_scripts target: imports argparse and defines main()."""
    src = (
        "import argparse\n"
        "def main():\n"
        "    argparse.ArgumentParser().parse_args()\n"
        "    print('done \u2713')\n"
    )
    assert _one(tmp_path, src).metadata["entry_kind"] == "cli main()"


def test_three_bindings_away_is_not_traced(tmp_path):
    """The trace is bounded at two bindings (rail 7): further out is LOW."""
    src = (
        "A = '\u2192'\n"
        "B = A\n"
        "C = B\n"
        "if __name__ == '__main__':\n"
        "    D = C\n"
        "    print(D)\n"
    )
    m = _one(tmp_path, src).metadata
    assert m["confidence_tier"] == "low"


def test_ruler_multiplication_is_traced(tmp_path):
    src = "if __name__ == '__main__':\n    print('\u2500' * 60)\n"
    m = _one(tmp_path, src).metadata
    assert m["confidence_tier"] == "high"
    assert m["encode_crash_chars"] == [BOX]


def test_one_finding_per_module_with_stable_fingerprint(tmp_path):
    src = (
        "if __name__ == '__main__':\n"
        "    print('a \u2192 b')\n"
        "    print('c \u2192 d')\n"
    )
    first = _one(tmp_path, src)
    assert first.metadata["traced_site_count"] == 2
    # Editing the anchored line does not change the module-level identity.
    second = _one(tmp_path, src.replace("a \u2192 b", "a \u2192 bb"))
    assert first.finding_id == second.finding_id


def test_message_is_ascii_only(tmp_path):
    """The finding is itself written to a std stream; it must not carry the bug."""
    f = _one(tmp_path, _CAM_ASSIST)
    f.message.encode("ascii")
    for key in ("encode_crash_chars", "cp1252_mappable_chars"):
        for text in f.metadata[key]:
            text.encode("ascii")


def test_syntax_error_file_is_skipped(tmp_path):
    assert _run(tmp_path, "if __name__ == '__main__':\n    print('\u2192'\n") == []
