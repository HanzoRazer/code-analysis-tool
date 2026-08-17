"""Unit tests for the context-pinned-hash detector.

The detector flags a hash asserted byte-equal across a context it wasn't computed
in — line endings (CRLF/LF/OS), interpreter version (ast.dump), or float
shortest-repr (platform ULP / formatting drift). v1 is a source-pattern heuristic
that records the axis + whether an in-file mitigation is visible, leaving
``context_confirmed=False`` for the v2 enrichment pass.
"""
from __future__ import annotations

from pathlib import Path

from code_audit.analyzers.context_pinned_hash import ContextPinnedHashAnalyzer
from code_audit.model import AnalyzerType, Severity


def _run(tmp_path: Path, src: str, name: str = "m.py"):
    p = tmp_path / name
    p.write_text(src, encoding="utf-8")
    return ContextPinnedHashAnalyzer().run(tmp_path, [p])


# ── byte / line-ending axis ─────────────────────────────────────────


def test_byte_hash_of_file_flagged_unmitigated(tmp_path):
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def h(p: Path):\n"
        "    return hashlib.sha256(p.read_bytes()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].type is AnalyzerType.CONTEXT_PINNED_HASH
    assert f[0].metadata["context_axis"] == "line_ending"
    assert f[0].metadata["mitigation_detected"] is False
    assert f[0].metadata["context_confirmed"] is False
    assert f[0].severity is Severity.MEDIUM
    # finding_id must be non-empty (schema minLength) — the web_api scan path
    # validates findings and 500s on an empty id.
    assert f[0].finding_id
    assert f[0].finding_id == f[0].fingerprint


def test_byte_hash_with_lf_normalize_is_mitigated(tmp_path):
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def h(p: Path):\n"
        "    b = p.read_bytes().replace(b'\\r\\n', b'\\n')\n"
        "    return hashlib.sha256(b).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["mitigation_detected"] is True
    assert f[0].metadata["mitigation_kind"] == "input_lf_normalized"
    assert f[0].severity is Severity.LOW


def test_str_lf_normalize_is_mitigated(tmp_path):
    # The str form of the same shape, not just the bytes one.
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def h(p: Path):\n"
        "    s = p.read_bytes().decode().replace('\\r\\n', '\\n')\n"
        "    return hashlib.sha256(s.encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["mitigation_kind"] == "input_lf_normalized"
    assert f[0].severity is Severity.LOW


# ── LF normalization: the replacement half must be checked too ──────


def test_crlf_deleted_is_not_lf_normalization(tmp_path):
    # ``replace(b'\r\n', b'')`` deletes the break rather than normalizing it:
    # a CRLF file and an LF file still hash differently afterwards. Crediting
    # it downgraded a live finding to LOW.
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def h(p: Path):\n"
        "    b = p.read_bytes().replace(b'\\r\\n', b'')\n"
        "    return hashlib.sha256(b).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "line_ending"
    assert f[0].metadata["mitigation_detected"] is False
    assert f[0].metadata["mitigation_kind"] is None
    assert f[0].severity is Severity.MEDIUM


def test_single_arg_replace_is_not_lf_normalization(tmp_path):
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def h(p: Path):\n"
        "    b = p.read_bytes().replace(b'\\r\\n')\n"
        "    return hashlib.sha256(b).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["mitigation_detected"] is False


def test_mixed_type_replace_is_not_lf_normalization(tmp_path):
    # ``bytes.replace(b'\r\n', '\n')`` is a TypeError at runtime — not this shape.
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def h(p: Path):\n"
        "    b = p.read_bytes().replace(b'\\r\\n', '\\n')\n"
        "    return hashlib.sha256(b).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["mitigation_detected"] is False


def test_non_constant_replacement_is_not_credited(tmp_path):
    # The replacement is opaque, so the mitigation is not *visible*. Declining
    # to credit it costs one severity step; crediting it wrongly hides the bug.
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def h(p: Path, nl):\n"
        "    b = p.read_bytes().replace(b'\\r\\n', nl)\n"
        "    return hashlib.sha256(b).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["mitigation_detected"] is False


# ── scope boundaries: one hash, one finding ─────────────────────────


def test_nested_function_hash_reported_once(tmp_path):
    # The hash belongs to ``inner``. Walking it again from ``outer`` reported
    # the same defect twice, under two different function names.
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def outer(p: Path):\n"
        "    def inner():\n"
        "        return hashlib.sha256(p.read_bytes()).hexdigest()\n"
        "    return inner()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "line_ending"
    assert "'inner'" in f[0].message


def test_nested_function_float_hash_reported_once(tmp_path):
    src = (
        "import hashlib, json\n"
        "def outer(c):\n"
        "    def inner():\n"
        "        return hashlib.sha256(json.dumps({'x': c / 2.0}).encode()).hexdigest()\n"
        "    return inner()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "float_repr"
    assert "'inner'" in f[0].message


def test_method_in_class_still_detected(tmp_path):
    # Guard against over-pruning: a class body is not a scope of its own here,
    # so its methods must still be reached.
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "class C:\n"
        "    def h(self, p: Path):\n"
        "        return hashlib.sha256(p.read_bytes()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "line_ending"


def test_method_in_function_nested_class_still_detected(tmp_path):
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def outer():\n"
        "    class C:\n"
        "        def h(self, p: Path):\n"
        "            return hashlib.sha256(p.read_bytes()).hexdigest()\n"
        "    return C\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert "'h'" in f[0].message


def test_lambda_body_still_analysed(tmp_path):
    # ``_scan_module`` does not visit lambdas as scopes, so pruning them would
    # drop their bodies entirely rather than reattribute them.
    src = (
        "import hashlib, json\n"
        "def h(xs):\n"
        "    f = lambda v: json.dumps({'x': v / 2.0})\n"
        "    return hashlib.sha256(f(xs).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert [x.metadata["context_axis"] for x in f] == ["float_repr"]


# ── name resolution is bounded ──────────────────────────────────────


def test_pathlib_division_down_a_name_chain_is_not_float_evidence(tmp_path):
    # Found by dogfooding on this repo. ``ROOT / meta['path']`` is pathlib
    # division, not float division, and an unbounded name chase reached it four
    # names away from the serialised payload (ids -> reg -> p -> ROOT / ...).
    src = (
        "import hashlib, json\n"
        "from pathlib import Path\n"
        "ROOT = Path('.')\n"
        "def h(meta):\n"
        "    p = ROOT / meta['path']\n"
        "    reg = json.loads(p.read_text(encoding='utf-8'))\n"
        "    ids = sorted(set(reg.get('ids', [])))\n"
        "    return hashlib.sha256(json.dumps(ids).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert all(x.metadata["context_axis"] != "float_repr" for x in f)


def test_float_evidence_one_binding_from_the_payload_is_followed(tmp_path):
    # The shape the hop budget must keep: q -> payload -> dumps.
    src = (
        "import hashlib, json\n"
        "def h(a):\n"
        "    q = a / 2.0\n"
        "    payload = {'x': q}\n"
        "    return hashlib.sha256(json.dumps(payload).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert [x.metadata["context_axis"] for x in f] == ["float_repr"]


def test_serialiser_two_bindings_from_the_hash_is_followed(tmp_path):
    # Reaching the hash is a chain of rebindings: s -> b -> sha256(b).
    src = (
        "import hashlib, json\n"
        "def h(a):\n"
        "    s = json.dumps({'x': a / 2.0})\n"
        "    b = s.encode()\n"
        "    return hashlib.sha256(b).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert [x.metadata["context_axis"] for x in f] == ["float_repr"]


def test_float_evidence_beyond_the_hop_budget_is_not_followed(tmp_path):
    # Three bindings deep the value is no longer plausibly "in the payload".
    src = (
        "import hashlib, json\n"
        "def h(a):\n"
        "    one = a / 2.0\n"
        "    two = {'v': one}\n"
        "    three = {'w': two}\n"
        "    payload = {'x': three}\n"
        "    return hashlib.sha256(json.dumps(payload).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert f == []


def test_binary_open_read_flagged(tmp_path):
    src = (
        "import hashlib\n"
        "def sha(path):\n"
        "    h = hashlib.sha256()\n"
        "    with open(path, 'rb') as fh:\n"
        "        for chunk in iter(lambda: fh.read(4096), b''):\n"
        "            h.update(chunk)\n"
        "    return h.hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "line_ending"


def test_read_text_not_flagged(tmp_path):
    # read_text() uses universal newlines → normalized on read → not the risk.
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def h(p: Path):\n"
        "    return hashlib.sha256(p.read_text().encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert f == []


# ── ast.dump / interpreter-version axis ─────────────────────────────


def test_ast_dump_hash_flagged_unmitigated(tmp_path):
    src = (
        "import ast, hashlib\n"
        "def h(src: str):\n"
        "    tree = ast.parse(src)\n"
        "    return hashlib.sha256(ast.dump(tree).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "python_version"
    assert f[0].metadata["mitigation_detected"] is False


def test_ast_dump_hash_with_version_guard_is_mitigated(tmp_path):
    src = (
        "import ast, hashlib, sys\n"
        "def _require_ci_python():\n"
        "    assert sys.version_info[:2] == (3, 11)\n"
        "def h(src: str):\n"
        "    tree = ast.parse(src)\n"
        "    return hashlib.sha256(ast.dump(tree).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "python_version"
    assert f[0].metadata["mitigation_detected"] is True
    assert f[0].metadata["mitigation_kind"] == "generator_python_pinned"


# ── float shortest-repr axis (POS-007) ──────────────────────────────


def test_float_json_dumps_hash_flagged_unmitigated(tmp_path):
    # POS-007 shape: hash over json.dumps of divided geometry floats.
    src = (
        "import hashlib, json\n"
        "def compute_report_id(coords, frequency):\n"
        "    payload = {\n"
        "        'x': coords[0] / 1000.0,\n"
        "        'y': coords[1] / 1000.0,\n"
        "        'f': frequency,\n"
        "    }\n"
        "    return hashlib.sha256(\n"
        "        json.dumps(payload, sort_keys=True).encode()\n"
        "    ).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].type is AnalyzerType.CONTEXT_PINNED_HASH
    assert f[0].metadata["rule_id"] == "CTX_PINNED_HASH_FLOAT_001"
    assert f[0].metadata["context_axis"] == "float_repr"
    assert f[0].metadata["mitigation_detected"] is False
    assert f[0].metadata["mitigation_kind"] is None
    assert f[0].metadata["context_confirmed"] is False
    assert f[0].severity is Severity.MEDIUM
    assert "quantize" in f[0].message.lower()
    assert "ulp" in f[0].message.lower()


def test_float_json_dumps_with_round_is_mitigated(tmp_path):
    src = (
        "import hashlib, json\n"
        "def compute_report_id_safe(coords, frequency):\n"
        "    payload = {\n"
        "        'x': round(coords[0] / 1000.0, 9),\n"
        "        'y': round(coords[1] / 1000.0, 9),\n"
        "        'f': frequency,\n"
        "    }\n"
        "    return hashlib.sha256(\n"
        "        json.dumps(payload, sort_keys=True).encode()\n"
        "    ).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "float_repr"
    assert f[0].metadata["mitigation_detected"] is True
    assert f[0].metadata["mitigation_kind"] == "floats_quantized"
    assert f[0].severity is Severity.LOW


def test_float_fstring_precision_is_mitigated(tmp_path):
    src = (
        "import hashlib\n"
        "def compute_report_id_fstring(x, y):\n"
        "    s = f'{x:.9g}|{y:.9g}'\n"
        "    return hashlib.sha256(s.encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "float_repr"
    assert f[0].metadata["mitigation_detected"] is True
    assert f[0].metadata["mitigation_kind"] == "floats_quantized"
    assert f[0].severity is Severity.LOW


def test_plain_byte_hash_no_float_axis(tmp_path):
    # Line-ending axis may fire; float axis must stay silent.
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def hash_plain_bytes(p: Path):\n"
        "    return hashlib.sha256(p.read_bytes()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert all(x.metadata["context_axis"] != "float_repr" for x in f)
    assert any(x.metadata["context_axis"] == "line_ending" for x in f)


def test_float_annotated_param_is_evidence(tmp_path):
    # No literal and no division — the ``: float`` annotation is the evidence.
    src = (
        "import hashlib, json\n"
        "def h(x: float, name: str):\n"
        "    return hashlib.sha256(json.dumps({'x': x, 'n': name}).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert [x.metadata["context_axis"] for x in f] == ["float_repr"]
    assert f[0].metadata["mitigation_detected"] is False


def test_float_fstring_dynamic_precision_is_mitigated(tmp_path):
    # f"{x:.{p}f}" pins the precision even though the constant spec text is ".f".
    src = (
        "import hashlib\n"
        "def h(x, p):\n"
        "    return hashlib.sha256(f'{x:.{p}f}'.encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "float_repr"
    assert f[0].metadata["mitigation_kind"] == "floats_quantized"
    assert f[0].severity is Severity.LOW


# ── float axis: payload scoping (false-positive guards) ─────────────


def test_json_dumps_without_float_payload_not_flagged(tmp_path):
    # str/bool/int payload — dumps alone must not open the float axis.
    src = (
        "import hashlib, json\n"
        "def h():\n"
        "    payload = {'name': 'alice', 'enabled': True, 'count': 3}\n"
        "    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert f == []


def test_json_dumps_of_ast_dump_keeps_only_python_version_axis(tmp_path):
    # A serialiser in a hash function is not, by itself, a float hash.
    src = (
        "import ast, hashlib, json\n"
        "def h(src: str):\n"
        "    return hashlib.sha256(json.dumps(ast.dump(ast.parse(src))).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert [x.metadata["context_axis"] for x in f] == ["python_version"]


def test_unrelated_round_does_not_mitigate_float_hash(tmp_path):
    # ``z`` never reaches the hashed payload — it must not downgrade to LOW.
    src = (
        "import hashlib, json\n"
        "def h(x, y):\n"
        "    z = round(x, 2)\n"
        "    payload = {'raw': y / 3.0}\n"
        "    return hashlib.sha256(json.dumps(payload).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "float_repr"
    assert f[0].metadata["mitigation_detected"] is False
    assert f[0].metadata["mitigation_kind"] is None
    assert f[0].severity is Severity.MEDIUM


def test_pickle_dumps_not_float_serialiser(tmp_path):
    # pickle writes IEEE-754 bytes — exact round-trip, not shortest-repr.
    src = (
        "import hashlib, pickle\n"
        "def h(coords):\n"
        "    return hashlib.sha256(pickle.dumps({'x': coords[0] / 1000.0})).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert all(x.metadata["context_axis"] != "float_repr" for x in f)


def test_fstring_without_precision_is_not_mitigated(tmp_path):
    # f"{x:g}" serialises a float with no pinned precision — still MEDIUM.
    src = (
        "import hashlib\n"
        "def h(x):\n"
        "    return hashlib.sha256(f'{x:g}'.encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "float_repr"
    assert f[0].metadata["mitigation_detected"] is False
    assert f[0].severity is Severity.MEDIUM


def test_fstring_one_unquantized_field_defeats_mitigation(tmp_path):
    # One bare float field leaves the whole string repr-sensitive.
    src = (
        "import hashlib\n"
        "def h(x, y):\n"
        "    return hashlib.sha256(f'{x:.9g}|{y:g}'.encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["mitigation_detected"] is False
    assert f[0].severity is Severity.MEDIUM


def test_fstring_non_float_field_does_not_defeat_mitigation(tmp_path):
    # ``{name}`` carries no float spec — it is not evidence either way.
    src = (
        "import hashlib\n"
        "def h(x, name):\n"
        "    return hashlib.sha256(f'{name}|{x:.9g}'.encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["mitigation_detected"] is True
    assert f[0].severity is Severity.LOW


def test_quantized_field_does_not_mitigate_raw_sibling_field(tmp_path):
    # One field is pinned, the sibling is a raw quotient — payload still drifts.
    src = (
        "import hashlib, json\n"
        "def h(x, y):\n"
        "    payload = {'a': round(x, 9), 'b': y / 3.0}\n"
        "    return hashlib.sha256(json.dumps(payload).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "float_repr"
    assert f[0].metadata["mitigation_detected"] is False
    assert f[0].severity is Severity.MEDIUM


def test_quantized_site_does_not_mitigate_unquantized_sibling(tmp_path):
    # Two float serialisation sites, one quantized — the scope stays MEDIUM.
    src = (
        "import hashlib, json\n"
        "def h(a, b):\n"
        "    left = json.dumps({'v': round(a / 2.0, 9)})\n"
        "    right = json.dumps({'v': b / 3.0})\n"
        "    return hashlib.sha256((left + right).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "float_repr"
    assert f[0].metadata["mitigation_detected"] is False
    assert f[0].severity is Severity.MEDIUM


def test_float_serialisation_off_the_hashed_path_not_flagged(tmp_path):
    # Floats are serialised for a log line; the hash consumes a constant.
    # Co-location in one function is not a context-pinned hash.
    src = (
        "import hashlib, json, logging\n"
        "def h(a):\n"
        "    logging.info(json.dumps({'x': a / 2.0}))\n"
        "    return hashlib.sha256(b'const').hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert f == []


def test_float_serialisation_off_path_does_not_taint_byte_axis(tmp_path):
    # The byte axis still fires on its own evidence; float must not tag along.
    src = (
        "import hashlib, json, logging\n"
        "from pathlib import Path\n"
        "def h(p: Path, a):\n"
        "    logging.info(json.dumps({'x': a / 2.0}))\n"
        "    return hashlib.sha256(p.read_bytes()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert [x.metadata["context_axis"] for x in f] == ["line_ending"]


def test_float_payload_reaches_hash_via_local_binding(tmp_path):
    src = (
        "import hashlib, json\n"
        "def h(a):\n"
        "    s = json.dumps({'x': a / 2.0})\n"
        "    return hashlib.sha256(s.encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert [x.metadata["context_axis"] for x in f] == ["float_repr"]


def test_float_payload_reaches_hash_via_update(tmp_path):
    # Streaming shape: the payload enters through ``h.update(...)``, and the
    # finding anchors on that line rather than on the constructor.
    src = (
        "import hashlib, json\n"
        "def h(a):\n"
        "    d = hashlib.sha256()\n"
        "    d.update(json.dumps({'x': a / 2.0}).encode())\n"
        "    return d.hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert [x.metadata["context_axis"] for x in f] == ["float_repr"]
    assert f[0].location.line_start == 4


# ── float axis: serialiser resolution ───────────────────────────────


def test_unresolved_dumps_method_not_a_serialiser(tmp_path):
    # ``ser`` is an opaque local — its float semantics are unknown, so an
    # attribute call named ``dumps`` on it is not evidence of anything.
    src = (
        "import hashlib\n"
        "def h(ser, a):\n"
        "    return hashlib.sha256(ser.dumps({'x': a / 2.0}).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert f == []


def test_aliased_json_import_is_a_serialiser(tmp_path):
    src = (
        "import hashlib, json as J\n"
        "def h(a):\n"
        "    return hashlib.sha256(J.dumps({'x': a / 2.0}).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert [x.metadata["context_axis"] for x in f] == ["float_repr"]


def test_from_import_dumps_is_a_serialiser(tmp_path):
    src = (
        "import hashlib\n"
        "from orjson import dumps\n"
        "def h(a):\n"
        "    return hashlib.sha256(dumps({'x': a / 2.0})).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert [x.metadata["context_axis"] for x in f] == ["float_repr"]


# ── float axis: Decimal is not on this axis ─────────────────────────


def test_decimal_payload_not_float_repr(tmp_path):
    # Decimal carries its digits in the value rather than recovering them by
    # repr — it is the *cure* for this defect, not an instance of it.
    src = (
        "import hashlib, json\n"
        "from decimal import Decimal\n"
        "def h(c):\n"
        "    return hashlib.sha256(\n"
        "        json.dumps({'x': Decimal(c)}, default=str).encode()\n"
        "    ).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert f == []


def test_decimal_annotation_not_float_evidence(tmp_path):
    src = (
        "import hashlib, json\n"
        "from decimal import Decimal\n"
        "def h(x: Decimal):\n"
        "    return hashlib.sha256(json.dumps({'x': x}, default=str).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert f == []


def test_quantize_still_mitigates_a_real_float_payload(tmp_path):
    # ``.quantize`` is dropped as float *evidence* but kept as a mitigation:
    # here the division is the evidence and quantize is the visible pin.
    src = (
        "import hashlib, json\n"
        "from decimal import Decimal\n"
        "def h(a):\n"
        "    v = Decimal(a / 3.0).quantize(Decimal('0.000000001'))\n"
        "    return hashlib.sha256(json.dumps({'x': str(v)}).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert [x.metadata["context_axis"] for x in f] == ["float_repr"]
    assert f[0].metadata["mitigation_kind"] == "floats_quantized"
    assert f[0].severity is Severity.LOW


# ── float axis: annotation / operator evidence ──────────────────────


def test_augmented_division_is_float_evidence(tmp_path):
    # ``x /= n`` has no float literal — the operator is the evidence.
    src = (
        "import hashlib, json\n"
        "def h(x, n):\n"
        "    x /= n\n"
        "    return hashlib.sha256(json.dumps({'x': x}).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert [x.metadata["context_axis"] for x in f] == ["float_repr"]


def test_string_annotation_matches_float_as_a_whole_word(tmp_path):
    src = (
        "import hashlib, json\n"
        "def h(x: 'float | None'):\n"
        "    return hashlib.sha256(json.dumps({'x': x}).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert [x.metadata["context_axis"] for x in f] == ["float_repr"]


def test_string_annotation_substring_is_not_float_evidence(tmp_path):
    src = (
        "import hashlib, json\n"
        "def h(x: 'MyFloatWrapper'):\n"
        "    return hashlib.sha256(json.dumps({'x': x}).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert f == []


def test_float_axis_emit_branch_not_line_ending_copy(tmp_path):
    # Integration guard: float findings must not inherit the line-ending fix text.
    src = (
        "import hashlib, json\n"
        "def compute_report_id(coords):\n"
        "    return hashlib.sha256(json.dumps({'x': coords[0] / 2.0}).encode()).hexdigest()\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["context_axis"] == "float_repr"
    assert "line ending" not in f[0].message.lower()
    assert "gitattributes" not in f[0].message.lower()
    assert "quantize" in f[0].message.lower()


# ── helper / wrapper indirection ────────────────────────────────────


def test_hash_wrapper_indirection_caught(tmp_path):
    # hash constructor in one function, file read in the caller — the common
    # `_sha256_file -> _sha256_bytes` helper shape (contracts_bundle).
    src = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def _sha256_bytes(b):\n"
        "    return hashlib.sha256(b).hexdigest()\n"
        "def _sha256_file(p: Path):\n"
        "    return _sha256_bytes(p.read_bytes())\n"
    )
    f = _run(tmp_path, src)
    # _sha256_file is the context-pinned one (reads bytes, calls the wrapper).
    paths_axes = {(x.location.path, x.metadata["context_axis"]) for x in f}
    assert any(ax == "line_ending" for _, ax in paths_axes)


# ── negative cases ──────────────────────────────────────────────────


def test_no_hash_no_finding(tmp_path):
    src = "def add(a, b):\n    return a + b\n"
    assert _run(tmp_path, src) == []


def test_hash_of_non_file_literal_not_flagged(tmp_path):
    # Hashing an in-memory string constant is not context-pinned to a file.
    src = (
        "import hashlib\n"
        "def h():\n"
        "    return hashlib.sha256(b'constant').hexdigest()\n"
    )
    assert _run(tmp_path, src) == []


def test_syntax_error_file_skipped(tmp_path):
    f = _run(tmp_path, "def broken(:\n")
    assert f == []
