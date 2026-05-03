"""Evaluation module — metrics, benchmarking, and visualization."""

from .metrics import (
    PolicySnapshot,
    GroundTruth,
    MetricResult,
    AggregateMetrics,
    MetricsCalculator,
    compute_risk_score,
)

from .benchmark import (
    SyntheticApp,
    BenchmarkRun,
    BenchmarkPipeline,
    generate_synthetic_dataset,
    apply_naive_strategy,
    apply_adapol_strategy,
)

__all__ = [
    # Metrics
    "PolicySnapshot",
    "GroundTruth",
    "MetricResult",
    "AggregateMetrics",
    "MetricsCalculator",
    "compute_risk_score",
    # Benchmark
    "SyntheticApp",
    "BenchmarkRun",
    "BenchmarkPipeline",
    "generate_synthetic_dataset",
    "apply_naive_strategy",
    "apply_adapol_strategy",
]
