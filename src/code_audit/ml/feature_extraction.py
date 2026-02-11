"""Feature extraction — compute numerical code features for ML analysis.

Extracts per-file and per-function metrics from Python source code using
the stdlib ``ast`` module.  No external dependencies.

Features extracted:

*  **File level:** line count, function count, class count, import count,
   average function length, max function complexity (CC), comment density,
   global variable count.
*  **Function level:** line count, parameter count, cyclomatic complexity,
   nesting depth, return count, local variable count.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── cyclomatic complexity (reused from analyzers/complexity.py) ────────

def _cyclomatic_complexity(node: ast.AST) -> int:
    cc = 1
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.IfExp)):
            cc += 1
        elif isinstance(child, (ast.For, ast.AsyncFor)):
            cc += 1
        elif isinstance(child, (ast.While,)):
            cc += 1
        elif isinstance(child, ast.BoolOp):
            cc += len(child.values) - 1
        elif isinstance(child, ast.ExceptHandler):
            cc += 1
        elif isinstance(child, (ast.With, ast.AsyncWith)):
            cc += 1
    return cc


def _max_nesting(node: ast.AST, depth: int = 0) -> int:
    """Return maximum nesting depth of control-flow structures."""
    max_d = depth
    _NESTING = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With,
                ast.AsyncWith, ast.Try, ast.ExceptHandler)
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _NESTING):
            max_d = max(max_d, _max_nesting(child, depth + 1))
        else:
            max_d = max(max_d, _max_nesting(child, depth))
    return max_d


def _count_returns(node: ast.AST) -> int:
    return sum(1 for n in ast.walk(node) if isinstance(n, ast.Return))


def _count_local_vars(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Count unique local variable names (Name in Store context)."""
    names: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            names.add(n.id)
    return len(names)


# ── data structures ───────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class FunctionFeatures:
    """Numerical features for one function/method."""

    name: str
    line_start: int
    line_count: int
    param_count: int
    complexity: int
    nesting_depth: int
    return_count: int
    local_var_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "line_start": self.line_start,
            "line_count": self.line_count,
            "param_count": self.param_count,
            "complexity": self.complexity,
            "nesting_depth": self.nesting_depth,
            "return_count": self.return_count,
            "local_var_count": self.local_var_count,
        }


@dataclass(frozen=True, slots=True)
class FileFeatures:
    """Numerical features for one Python file."""

    path: str
    line_count: int
    function_count: int
    class_count: int
    import_count: int
    avg_function_length: float
    max_complexity: int
    comment_density: float      # ratio of comment lines to total lines
    global_var_count: int
    functions: list[FunctionFeatures] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "line_count": self.line_count,
            "function_count": self.function_count,
            "class_count": self.class_count,
            "import_count": self.import_count,
            "avg_function_length": round(self.avg_function_length, 2),
            "max_complexity": self.max_complexity,
            "comment_density": round(self.comment_density, 4),
            "global_var_count": self.global_var_count,
            "functions": [f.to_dict() for f in self.functions],
        }

    def feature_vector(self) -> list[float]:
        """Return a flat numeric vector for clustering / ML input."""
        return [
            float(self.line_count),
            float(self.function_count),
            float(self.class_count),
            float(self.import_count),
            self.avg_function_length,
            float(self.max_complexity),
            self.comment_density,
            float(self.global_var_count),
        ]


# ── extraction ─────────────────────────────────────────────────────────

def extract_file_features(
    path: Path,
    *,
    root: Path | None = None,
) -> FileFeatures | None:
    """Extract :class:`FileFeatures` from a single Python file.

    Returns *None* if the file cannot be parsed.
    """
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, OSError):
        return None

    lines = source.splitlines()
    line_count = len(lines)
    rel = str(path.relative_to(root)) if root else str(path)

    # Comment density
    comment_lines = sum(1 for l in lines if l.lstrip().startswith("#"))
    comment_density = comment_lines / line_count if line_count > 0 else 0.0

    # Top-level counts
    function_count = 0
    class_count = 0
    import_count = 0
    global_var_count = 0

    func_lengths: list[int] = []
    max_cc = 0
    func_features: list[FunctionFeatures] = []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_count += 1
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            length = end - node.lineno + 1
            func_lengths.append(length)
            cc = _cyclomatic_complexity(node)
            max_cc = max(max_cc, cc)

            params = node.args
            param_count = len(params.args) + len(params.posonlyargs) + len(params.kwonlyargs)
            if params.vararg:
                param_count += 1
            if params.kwarg:
                param_count += 1

            func_features.append(
                FunctionFeatures(
                    name=node.name,
                    line_start=node.lineno,
                    line_count=length,
                    param_count=param_count,
                    complexity=cc,
                    nesting_depth=_max_nesting(node),
                    return_count=_count_returns(node),
                    local_var_count=_count_local_vars(node),
                )
            )

        elif isinstance(node, ast.ClassDef):
            class_count += 1
            # Also count methods inside classes
            for item in ast.walk(node):
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    cc = _cyclomatic_complexity(item)
                    max_cc = max(max_cc, cc)
                    end = getattr(item, "end_lineno", item.lineno) or item.lineno
                    func_lengths.append(end - item.lineno + 1)

        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            import_count += 1

        elif isinstance(node, ast.Assign):
            global_var_count += len(node.targets)

    avg_func_len = sum(func_lengths) / len(func_lengths) if func_lengths else 0.0

    return FileFeatures(
        path=rel,
        line_count=line_count,
        function_count=function_count,
        class_count=class_count,
        import_count=import_count,
        avg_function_length=avg_func_len,
        max_complexity=max_cc,
        comment_density=comment_density,
        global_var_count=global_var_count,
        functions=func_features,
    )


def extract_batch(
    root: Path,
    files: list[Path],
) -> list[FileFeatures]:
    """Extract features for multiple files.  Skips unparseable files."""
    results: list[FileFeatures] = []
    for f in files:
        ff = extract_file_features(f, root=root)
        if ff is not None:
            results.append(ff)
    return results
