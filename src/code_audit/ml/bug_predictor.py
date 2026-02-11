"""Bug predictor — heuristic-based bug probability scoring.

Uses a weighted combination of code features to estimate bug probability
per file.  This is a **lightweight heuristic** approximation of ML bug
prediction models (e.g. logistic regression on code metrics).

The formula combines well-established correlations:

*  High **cyclomatic complexity** → more bugs
*  Long **files** → more bugs
*  Low **comment density** → more bugs
*  Many **global variables** → more bugs
*  High **function count** without matching structure → more bugs

No external ML libraries required.  Swap the ``_score()`` method for a
real model (sklearn, etc.) when training data is available.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from code_audit.ml.feature_extraction import (
    FileFeatures,
    extract_file_features,
    extract_batch,
)


# ── scoring weights (calibrated heuristics) ──────────────────────────

# Each weight represents the per-unit contribution to bug probability.
# Total is clipped to [0.0, 1.0].
_WEIGHTS = {
    "complexity": 0.020,      # per CC point above threshold
    "line_count": 0.0003,     # per line
    "low_comment_density": 0.15,   # flat penalty if density < threshold
    "global_vars": 0.03,      # per global variable
    "long_function": 0.01,    # per line of avg function length above threshold
}

_THRESHOLDS = {
    "complexity": 10,
    "comment_density": 0.05,
    "avg_function_length": 30,
}


@dataclass(frozen=True, slots=True)
class BugPrediction:
    """Bug probability prediction for a single file."""

    path: str
    probability: float       # 0.0 – 1.0
    risk_factors: list[str]  # human-readable risk factor descriptions
    features: FileFeatures


class BugPredictor:
    """Heuristic bug-probability predictor.

    Parameters
    ----------
    complexity_threshold:
        CC above which complexity contributes to bug probability.
    comment_density_threshold:
        Below this ratio, "low comment density" penalty applies.
    avg_func_length_threshold:
        Average function length above which penalty applies.
    """

    def __init__(
        self,
        *,
        complexity_threshold: int = 10,
        comment_density_threshold: float = 0.05,
        avg_func_length_threshold: int = 30,
    ) -> None:
        self._cc_thresh = complexity_threshold
        self._cd_thresh = comment_density_threshold
        self._fl_thresh = avg_func_length_threshold

    def predict_file(self, features: FileFeatures) -> BugPrediction:
        """Score a single file from its extracted features."""
        score = 0.0
        factors: list[str] = []

        # Complexity contribution
        cc_excess = max(0, features.max_complexity - self._cc_thresh)
        if cc_excess > 0:
            contrib = cc_excess * _WEIGHTS["complexity"]
            score += contrib
            factors.append(
                f"High complexity (CC={features.max_complexity}, "
                f"threshold={self._cc_thresh})"
            )

        # Line count contribution
        line_contrib = features.line_count * _WEIGHTS["line_count"]
        score += line_contrib
        if features.line_count > 300:
            factors.append(f"Large file ({features.line_count} lines)")

        # Comment density
        if features.comment_density < self._cd_thresh:
            score += _WEIGHTS["low_comment_density"]
            factors.append(
                f"Low comment density ({features.comment_density:.1%}, "
                f"threshold={self._cd_thresh:.1%})"
            )

        # Global variables
        if features.global_var_count > 0:
            score += features.global_var_count * _WEIGHTS["global_vars"]
            factors.append(f"Global variables ({features.global_var_count})")

        # Average function length
        fl_excess = max(0, features.avg_function_length - self._fl_thresh)
        if fl_excess > 0:
            score += fl_excess * _WEIGHTS["long_function"]
            factors.append(
                f"Long average function ({features.avg_function_length:.0f} lines, "
                f"threshold={self._fl_thresh})"
            )

        probability = min(1.0, max(0.0, score))

        return BugPrediction(
            path=features.path,
            probability=round(probability, 4),
            risk_factors=factors,
            features=features,
        )

    def predict(
        self,
        root: Path,
        files: list[Path],
    ) -> list[BugPrediction]:
        """Predict bug probability for multiple files.

        Returns predictions sorted by probability (highest first).
        """
        all_features = extract_batch(root, files)
        predictions = [self.predict_file(f) for f in all_features]
        predictions.sort(key=lambda p: -p.probability)
        return predictions

    def predict_from_features(
        self,
        features_list: list[FileFeatures],
    ) -> list[BugPrediction]:
        """Predict from pre-extracted features (avoids re-parsing)."""
        predictions = [self.predict_file(f) for f in features_list]
        predictions.sort(key=lambda p: -p.probability)
        return predictions
