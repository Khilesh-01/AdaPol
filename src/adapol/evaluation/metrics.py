"""
Evaluation Metrics for AdaPol

Implements four core metrics:
  1. Permission Reduction %   — how much smaller is the optimised policy
  2. False Positive Rate      — safe permissions incorrectly flagged for removal
  3. Breakage Rate            — removals that actually break execution
  4. Risk Reduction Score     — decrease in composite risk score (0–100)

All metrics are self-contained and work on plain dicts so they can be used
independently of any particular storage or pipeline.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class PolicySnapshot:
    """Minimal policy representation used by the evaluator."""
    function_id: str
    permissions: Set[str]           # full permission set
    risk_score: float               # 0–100 from the risk engine
    wildcard_count: int = 0
    resource_count: int = 0

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "PolicySnapshot":
        return PolicySnapshot(
            function_id=d["function_id"],
            permissions=set(d.get("permissions", [])),
            risk_score=float(d.get("risk_score", 0.0)),
            wildcard_count=int(d.get("wildcard_count", 0)),
            resource_count=int(d.get("resource_count", 0)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_id": self.function_id,
            "permissions": sorted(self.permissions),
            "risk_score": self.risk_score,
            "wildcard_count": self.wildcard_count,
            "resource_count": self.resource_count,
        }


@dataclass
class GroundTruth:
    """
    Ground-truth labels for a function's permissions.

    required_permissions  — permissions actually needed for correct execution
    used_in_logs          — permissions observed in runtime traces
    causes_breakage_if_removed — permissions whose removal definitely breaks things
    """
    function_id: str
    required_permissions: Set[str]
    used_in_logs: Set[str]
    causes_breakage_if_removed: Set[str]

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "GroundTruth":
        return GroundTruth(
            function_id=d["function_id"],
            required_permissions=set(d.get("required_permissions", [])),
            used_in_logs=set(d.get("used_in_logs", [])),
            causes_breakage_if_removed=set(d.get("causes_breakage_if_removed", [])),
        )


@dataclass
class MetricResult:
    """Result for a single function across all four metrics."""
    function_id: str

    # Metric 1: Permission Reduction %
    original_permission_count: int = 0
    optimised_permission_count: int = 0
    permission_reduction_pct: float = 0.0

    # Metric 2: False Positive Rate
    # FP = safe permission incorrectly flagged as removable
    false_positives: int = 0
    true_positives: int = 0         # correctly identified removable permissions
    false_positive_rate: float = 0.0

    # Metric 3: Breakage Rate
    # A breakage occurs when a required permission is removed
    permissions_removed: Set[str] = field(default_factory=set)
    breakage_count: int = 0
    breakage_rate: float = 0.0
    breaking_permissions: List[str] = field(default_factory=list)

    # Metric 4: Risk Reduction Score
    original_risk_score: float = 0.0
    optimised_risk_score: float = 0.0
    risk_reduction_score: float = 0.0   # positive = improvement

    # Baseline comparisons
    naive_permission_count: int = 0
    naive_risk_score: float = 0.0
    naive_reduction_pct: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["permissions_removed"] = sorted(self.permissions_removed)
        return d


@dataclass
class AggregateMetrics:
    """Aggregate metrics across all functions in a benchmark run."""
    total_functions: int = 0
    avg_permission_reduction_pct: float = 0.0
    avg_false_positive_rate: float = 0.0
    avg_breakage_rate: float = 0.0
    avg_risk_reduction_score: float = 0.0

    # Distribution info
    max_permission_reduction_pct: float = 0.0
    min_permission_reduction_pct: float = 0.0
    max_risk_reduction_score: float = 0.0
    min_risk_reduction_score: float = 0.0

    # vs baseline
    improvement_over_naive_pct: float = 0.0   # extra reduction vs naive approach
    functions_with_zero_breakage: int = 0
    functions_with_breakage: int = 0

    # Per-function breakdown
    per_function: List[MetricResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": {
                "total_functions": self.total_functions,
                "avg_permission_reduction_pct": round(self.avg_permission_reduction_pct, 2),
                "avg_false_positive_rate": round(self.avg_false_positive_rate, 4),
                "avg_breakage_rate": round(self.avg_breakage_rate, 4),
                "avg_risk_reduction_score": round(self.avg_risk_reduction_score, 2),
                "max_permission_reduction_pct": round(self.max_permission_reduction_pct, 2),
                "min_permission_reduction_pct": round(self.min_permission_reduction_pct, 2),
                "max_risk_reduction_score": round(self.max_risk_reduction_score, 2),
                "min_risk_reduction_score": round(self.min_risk_reduction_score, 2),
                "improvement_over_naive_pct": round(self.improvement_over_naive_pct, 2),
                "functions_with_zero_breakage": self.functions_with_zero_breakage,
                "functions_with_breakage": self.functions_with_breakage,
            },
            "per_function": [r.to_dict() for r in self.per_function],
        }


# ---------------------------------------------------------------------------
# Core metric calculator
# ---------------------------------------------------------------------------

class MetricsCalculator:
    """
    Calculates all four evaluation metrics for a set of policy snapshots.

    Usage::

        calc = MetricsCalculator()
        result = calc.evaluate(
            original=original_snap,
            optimised=optimised_snap,
            ground_truth=gt,
        )
        print(result.permission_reduction_pct)
    """

    # --------------- public interface ------------------------------------

    def evaluate(
        self,
        original: PolicySnapshot,
        optimised: PolicySnapshot,
        ground_truth: GroundTruth,
        naive: Optional[PolicySnapshot] = None,
    ) -> MetricResult:
        """
        Compute all metrics for a single function.

        Args:
            original:     Policy before optimisation.
            optimised:    Policy after optimisation.
            ground_truth: Known-correct labels.
            naive:        Naive least-privilege baseline (optional).

        Returns:
            MetricResult with all four metrics populated.
        """
        result = MetricResult(function_id=original.function_id)

        # --- Metric 1: Permission Reduction % ----------------------------
        result.original_permission_count = len(original.permissions)
        result.optimised_permission_count = len(optimised.permissions)
        result.permission_reduction_pct = self._reduction_pct(
            original.permissions, optimised.permissions
        )

        # --- Metric 2: False Positive Rate --------------------------------
        removed = original.permissions - optimised.permissions
        result.permissions_removed = removed
        safe_to_remove = original.permissions - ground_truth.required_permissions
        actually_required = ground_truth.required_permissions

        # FP: a removed permission that was actually required
        fp_set = removed & actually_required
        # TP: a removed permission that was genuinely not needed
        tp_set = removed & safe_to_remove
        result.false_positives = len(fp_set)
        result.true_positives = len(tp_set)

        # FPR = FP / (FP + TN);  TN = safe perms NOT removed
        true_negatives = safe_to_remove - removed   # safe perms kept (should be removed but weren't)
        denominator = len(fp_set) + len(true_negatives)
        result.false_positive_rate = (
            len(fp_set) / denominator if denominator > 0 else 0.0
        )

        # --- Metric 3: Breakage Rate -------------------------------------
        breakage_set = removed & ground_truth.causes_breakage_if_removed
        result.breakage_count = len(breakage_set)
        result.breaking_permissions = sorted(breakage_set)
        result.breakage_rate = (
            len(breakage_set) / len(removed) if removed else 0.0
        )

        # --- Metric 4: Risk Reduction Score ------------------------------
        result.original_risk_score = original.risk_score
        result.optimised_risk_score = optimised.risk_score
        result.risk_reduction_score = original.risk_score - optimised.risk_score

        # --- Naive baseline comparison -----------------------------------
        if naive:
            result.naive_permission_count = len(naive.permissions)
            result.naive_risk_score = naive.risk_score
            result.naive_reduction_pct = self._reduction_pct(
                original.permissions, naive.permissions
            )

        return result

    def aggregate(self, results: List[MetricResult]) -> AggregateMetrics:
        """
        Aggregate per-function MetricResults into a single summary.

        Args:
            results: List of MetricResult (one per function).

        Returns:
            AggregateMetrics with averages, distributions, and comparisons.
        """
        if not results:
            return AggregateMetrics()

        agg = AggregateMetrics(
            total_functions=len(results),
            per_function=results,
        )

        reductions    = [r.permission_reduction_pct for r in results]
        fp_rates      = [r.false_positive_rate for r in results]
        breakage_rates = [r.breakage_rate for r in results]
        risk_reductions = [r.risk_reduction_score for r in results]
        naive_reductions = [r.naive_reduction_pct for r in results if r.naive_reduction_pct]

        agg.avg_permission_reduction_pct = _mean(reductions)
        agg.avg_false_positive_rate = _mean(fp_rates)
        agg.avg_breakage_rate = _mean(breakage_rates)
        agg.avg_risk_reduction_score = _mean(risk_reductions)

        agg.max_permission_reduction_pct = max(reductions, default=0.0)
        agg.min_permission_reduction_pct = min(reductions, default=0.0)
        agg.max_risk_reduction_score = max(risk_reductions, default=0.0)
        agg.min_risk_reduction_score = min(risk_reductions, default=0.0)

        if naive_reductions:
            agg.improvement_over_naive_pct = (
                agg.avg_permission_reduction_pct - _mean(naive_reductions)
            )

        agg.functions_with_breakage = sum(1 for r in results if r.breakage_count > 0)
        agg.functions_with_zero_breakage = len(results) - agg.functions_with_breakage

        return agg

    # --------------- helpers --------------------------------------------

    @staticmethod
    def _reduction_pct(original: Set[str], optimised: Set[str]) -> float:
        """Percentage of permissions removed from original."""
        if not original:
            return 0.0
        removed = len(original) - len(optimised)
        return max(0.0, (removed / len(original)) * 100.0)


# ---------------------------------------------------------------------------
# Composite risk scorer (standalone, no graph needed)
# ---------------------------------------------------------------------------

# Permission weight map — higher = riskier
_PERM_WEIGHTS: Dict[str, float] = {
    "iam:*":               10.0,
    "*:*":                 10.0,
    "iam:AttachRolePolicy": 8.0,
    "iam:PutRolePolicy":    8.0,
    "iam:CreateAccessKey":  8.0,
    "sts:AssumeRole":       7.0,
    "kms:Decrypt":          6.0,
    "kms:*":               8.0,
    "s3:*":                5.0,
    "s3:DeleteObject":      4.0,
    "s3:PutObject":         3.0,
    "s3:GetObject":         2.0,
    "dynamodb:DeleteItem":  4.0,
    "dynamodb:PutItem":     3.0,
    "dynamodb:Query":       1.5,
    "dynamodb:GetItem":     1.5,
    "logs:PutLogEvents":    0.5,
    "logs:CreateLogGroup":  0.5,
}

_DEFAULT_WEIGHT = 1.0
_WILDCARD_BONUS  = 5.0   # extra risk per wildcard permission


def compute_risk_score(permissions: Set[str], cap: float = 100.0) -> float:
    """
    Compute a composite risk score for a set of permissions.

    Score is a weighted sum of individual permission risks, capped at `cap`.
    Wildcard permissions receive an additional bonus.

    Args:
        permissions: Set of IAM permission strings.
        cap:         Maximum score (default 100).

    Returns:
        Float risk score 0–cap.
    """
    score = 0.0
    for perm in permissions:
        weight = _PERM_WEIGHTS.get(perm, _DEFAULT_WEIGHT)
        if "*" in perm:
            weight += _WILDCARD_BONUS
        score += weight
    # Apply log dampening to avoid extreme scores with many low-risk perms
    if score > 0:
        score = 10.0 * math.log10(score + 1) * (score / (score + 10.0)) * 15.0
    return min(cap, round(score, 2))


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0
