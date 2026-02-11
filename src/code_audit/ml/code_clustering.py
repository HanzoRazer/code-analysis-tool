"""Code clusterer — group similar files by structural features.

Uses a **lightweight, dependency-free** k-means-style algorithm on the
feature vectors produced by :func:`feature_extraction.extract_file_features`.

This is a minimal implementation suitable for small-to-medium codebases.
For production use, replace the inner loop with ``sklearn.cluster.KMeans``
or similar.

Typical use cases:

*  Identify groups of structurally similar files for batch refactoring.
*  Detect outlier files that don't match any cluster.
*  Visualise codebase structure (export cluster assignments → plot).
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from code_audit.ml.feature_extraction import (
    FileFeatures,
    extract_batch,
)


# ── data structures ───────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class Cluster:
    """One cluster of similar files."""

    cluster_id: int
    centroid: list[float]
    members: list[FileFeatures]
    label: str = ""          # optional human-readable label


@dataclass(frozen=True, slots=True)
class ClusterResult:
    """Full clustering output."""

    clusters: list[Cluster]
    outliers: list[FileFeatures]   # files too far from any centroid
    inertia: float                 # total within-cluster distance

    def summary(self) -> str:
        parts = [f"{len(self.clusters)} cluster(s)"]
        for c in self.clusters:
            parts.append(f"  C{c.cluster_id}: {len(c.members)} file(s)")
        if self.outliers:
            parts.append(f"  Outliers: {len(self.outliers)}")
        return "\n".join(parts)


# ── distance / maths ─────────────────────────────────────────────────

def _euclidean(a: list[float], b: list[float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def _mean_vector(vectors: list[list[float]]) -> list[float]:
    if not vectors:
        return []
    k = len(vectors[0])
    return [sum(v[i] for v in vectors) / len(vectors) for i in range(k)]


def _normalize(vectors: list[list[float]]) -> tuple[list[list[float]], list[float], list[float]]:
    """Min-max normalize each feature to [0, 1].  Returns (normalized, mins, maxs)."""
    if not vectors:
        return [], [], []
    k = len(vectors[0])
    mins = [min(v[i] for v in vectors) for i in range(k)]
    maxs = [max(v[i] for v in vectors) for i in range(k)]
    spans = [maxs[i] - mins[i] if maxs[i] != mins[i] else 1.0 for i in range(k)]
    normed = [
        [(v[i] - mins[i]) / spans[i] for i in range(k)]
        for v in vectors
    ]
    return normed, mins, maxs


# ── k-means ───────────────────────────────────────────────────────────

def _kmeans(
    vectors: list[list[float]],
    k: int,
    max_iter: int = 50,
    seed: int | None = None,
) -> tuple[list[int], list[list[float]], float]:
    """Minimal k-means.  Returns (assignments, centroids, inertia)."""
    n = len(vectors)
    if n == 0 or k <= 0:
        return [], [], 0.0

    k = min(k, n)
    rng = random.Random(seed)

    # Init: random centroids from data points
    indices = rng.sample(range(n), k)
    centroids = [list(vectors[i]) for i in indices]
    assignments = [0] * n

    for _ in range(max_iter):
        # Assign
        new_assign = [0] * n
        for i, v in enumerate(vectors):
            dists = [_euclidean(v, c) for c in centroids]
            new_assign[i] = dists.index(min(dists))

        if new_assign == assignments:
            break
        assignments = new_assign

        # Update centroids
        for ci in range(k):
            members = [vectors[i] for i in range(n) if assignments[i] == ci]
            if members:
                centroids[ci] = _mean_vector(members)

    # Compute inertia
    inertia = sum(
        _euclidean(vectors[i], centroids[assignments[i]]) ** 2
        for i in range(n)
    )
    return assignments, centroids, inertia


# ── public API ────────────────────────────────────────────────────────

_CLUSTER_LABELS = {
    "small_simple": "Small & Simple",
    "large_complex": "Large & Complex",
    "moderate": "Moderate",
    "utility": "Utility / Glue",
}


def _auto_label(centroid: list[float]) -> str:
    """Assign a human-readable label based on centroid features.

    Feature vector order: line_count, function_count, class_count,
    import_count, avg_function_length, max_complexity, comment_density,
    global_var_count.
    """
    if len(centroid) < 6:
        return ""
    lc, fc, cc, ic, afl, mc = centroid[:6]
    if lc < 0.3 and mc < 0.3:
        return "Small & Simple"
    if lc > 0.7 or mc > 0.7:
        return "Large & Complex"
    return "Moderate"


class CodeClusterer:
    """Group Python files by structural similarity.

    Parameters
    ----------
    n_clusters:
        Number of clusters.  Use ``"auto"`` to try a range and pick the
        best via inertia elbow.
    outlier_threshold:
        Files farther than this (normalised) distance from their centroid
        are flagged as outliers.
    seed:
        Random seed for reproducibility.
    """

    def __init__(
        self,
        *,
        n_clusters: int | str = 3,
        outlier_threshold: float = 2.0,
        seed: int = 42,
    ) -> None:
        self._k = n_clusters
        self._outlier_thresh = outlier_threshold
        self._seed = seed

    def cluster(
        self,
        root: Path,
        files: list[Path],
    ) -> ClusterResult:
        """Extract features and cluster files."""
        features = extract_batch(root, files)
        return self.cluster_from_features(features)

    def cluster_from_features(
        self,
        features: list[FileFeatures],
    ) -> ClusterResult:
        """Cluster from pre-extracted features."""
        if not features:
            return ClusterResult(clusters=[], outliers=[], inertia=0.0)

        vectors = [f.feature_vector() for f in features]
        normed, _, _ = _normalize(vectors)

        # Determine k
        if isinstance(self._k, str) and self._k == "auto":
            k = self._auto_k(normed)
        else:
            k = min(int(self._k), len(normed))

        if k < 1:
            k = 1

        assignments, centroids, inertia = _kmeans(
            normed, k, seed=self._seed
        )

        # Build clusters
        clusters: list[Cluster] = []
        outliers: list[FileFeatures] = []

        for ci in range(k):
            member_indices = [i for i, a in enumerate(assignments) if a == ci]
            members: list[FileFeatures] = []
            for idx in member_indices:
                dist = _euclidean(normed[idx], centroids[ci])
                if dist > self._outlier_thresh:
                    outliers.append(features[idx])
                else:
                    members.append(features[idx])

            clusters.append(
                Cluster(
                    cluster_id=ci,
                    centroid=centroids[ci],
                    members=members,
                    label=_auto_label(centroids[ci]),
                )
            )

        return ClusterResult(
            clusters=clusters,
            outliers=outliers,
            inertia=inertia,
        )

    def _auto_k(self, vectors: list[list[float]]) -> int:
        """Pick k using simple inertia drop-off (elbow heuristic)."""
        max_k = min(6, len(vectors))
        if max_k <= 1:
            return 1

        prev_inertia = float("inf")
        best_k = 2
        for k in range(2, max_k + 1):
            _, _, inertia = _kmeans(vectors, k, seed=self._seed)
            # Simple threshold: if inertia drops less than 30%, stop
            if prev_inertia > 0 and inertia / prev_inertia > 0.7:
                break
            best_k = k
            prev_inertia = inertia

        return best_k
