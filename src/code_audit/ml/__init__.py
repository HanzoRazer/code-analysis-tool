"""ML-based analysis — experimental heuristic and statistical modules.

These modules provide lightweight, dependency-free analysis using
statistical heuristics rather than full ML frameworks.  They can be
upgraded to real ML models later while keeping the same API surface.
"""

from code_audit.ml.feature_extraction import extract_file_features
from code_audit.ml.bug_predictor import BugPredictor
from code_audit.ml.code_clustering import CodeClusterer

__all__ = [
    "extract_file_features",
    "BugPredictor",
    "CodeClusterer",
]
