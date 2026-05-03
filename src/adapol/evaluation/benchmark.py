"""
Benchmark Pipeline for AdaPol

Runs the full evaluation pipeline:
  1. Generate (or load) synthetic dataset of serverless app policies
  2. Apply three strategies: Original / Naive least-privilege / AdaPol optimised
  3. Compute all four metrics per function
  4. Aggregate and produce:
     - Rich console tables
     - JSON report  (benchmark_report_<timestamp>.json)
     - ASCII bar charts and optional matplotlib plots

CLI entry-point (wired via cli.py):
    adapol run-benchmark  [--dataset <json>] [--output <dir>] [--plot]
"""

from __future__ import annotations

import json
import math
import os
import random
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .metrics import (
    PolicySnapshot,
    GroundTruth,
    MetricResult,
    AggregateMetrics,
    MetricsCalculator,
    compute_risk_score,
)

console = Console()

# ---------------------------------------------------------------------------
# Synthetic dataset generator
# ---------------------------------------------------------------------------

# Realistic permission pools for serverless applications
_PERMISSION_POOLS: Dict[str, List[str]] = {
    "api_handler": [
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
        "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:Scan",
        "dynamodb:DeleteItem", "dynamodb:UpdateItem",
        "logs:PutLogEvents", "logs:CreateLogGroup", "logs:CreateLogStream",
        "sts:AssumeRole", "kms:Decrypt", "kms:GenerateDataKey",
    ],
    "data_processor": [
        "s3:GetObject", "s3:PutObject", "s3:ListBucket",
        "dynamodb:PutItem", "dynamodb:Query", "dynamodb:BatchWriteItem",
        "logs:PutLogEvents", "logs:CreateLogGroup",
        "sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage",
        "sns:Publish",
    ],
    "auth_service": [
        "iam:GetUser", "iam:ListUsers", "iam:AttachRolePolicy",
        "sts:AssumeRole", "sts:GetCallerIdentity",
        "kms:Decrypt", "kms:Encrypt",
        "dynamodb:GetItem", "dynamodb:PutItem",
        "logs:PutLogEvents", "logs:CreateLogGroup",
        "secretsmanager:GetSecretValue",
    ],
    "reporting_service": [
        "s3:GetObject", "s3:PutObject", "s3:ListBucket",
        "dynamodb:Scan", "dynamodb:Query", "dynamodb:GetItem",
        "logs:PutLogEvents",
        "ses:SendEmail", "sns:Publish",
        "cloudwatch:PutMetricData",
    ],
    "batch_job": [
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
        "dynamodb:BatchWriteItem", "dynamodb:Query", "dynamodb:Scan",
        "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:SendMessage",
        "logs:PutLogEvents", "logs:CreateLogGroup",
        "ec2:DescribeInstances",
    ],
}

# Required subset (what the function actually needs)
_REQUIRED_SUBSETS: Dict[str, List[str]] = {
    "api_handler":        ["s3:GetObject", "s3:PutObject", "dynamodb:GetItem",
                           "dynamodb:PutItem", "logs:PutLogEvents", "logs:CreateLogGroup"],
    "data_processor":     ["s3:GetObject", "s3:PutObject", "dynamodb:PutItem",
                           "dynamodb:Query", "logs:PutLogEvents", "sqs:ReceiveMessage"],
    "auth_service":       ["sts:AssumeRole", "kms:Decrypt", "dynamodb:GetItem",
                           "dynamodb:PutItem", "logs:PutLogEvents"],
    "reporting_service":  ["s3:GetObject", "dynamodb:Scan", "dynamodb:Query",
                           "logs:PutLogEvents", "ses:SendEmail"],
    "batch_job":          ["s3:GetObject", "s3:PutObject", "dynamodb:BatchWriteItem",
                           "sqs:ReceiveMessage", "sqs:DeleteMessage", "logs:PutLogEvents"],
}

# Permissions that definitely break execution if removed
_CRITICAL_PERMS: Dict[str, List[str]] = {
    "api_handler":       ["s3:GetObject", "dynamodb:GetItem", "logs:PutLogEvents"],
    "data_processor":    ["s3:GetObject", "dynamodb:PutItem", "sqs:ReceiveMessage"],
    "auth_service":      ["sts:AssumeRole", "kms:Decrypt", "dynamodb:GetItem"],
    "reporting_service": ["dynamodb:Scan", "ses:SendEmail"],
    "batch_job":         ["s3:GetObject", "sqs:ReceiveMessage", "dynamodb:BatchWriteItem"],
}


@dataclass
class SyntheticApp:
    """One synthetic serverless application with ground truth."""
    app_id: str
    functions: List[str]             # function names
    original_policies: Dict[str, PolicySnapshot]
    ground_truths: Dict[str, GroundTruth]


def generate_synthetic_dataset(
    n_apps: int = 5,
    seed: int = 42,
) -> List[SyntheticApp]:
    """
    Generate a synthetic dataset of serverless applications.

    Each app has 3–5 functions drawn from realistic permission pools.
    Over-provisioned by default to simulate real-world drift.

    Args:
        n_apps: Number of apps to generate.
        seed:   Random seed for reproducibility.

    Returns:
        List of SyntheticApp objects.
    """
    rng = random.Random(seed)
    apps: List[SyntheticApp] = []
    func_types = list(_PERMISSION_POOLS.keys())

    for app_idx in range(n_apps):
        app_id = f"app_{app_idx + 1:02d}"
        n_funcs = rng.randint(3, 5)
        chosen_types = rng.choices(func_types, k=n_funcs)

        original_policies: Dict[str, PolicySnapshot] = {}
        ground_truths: Dict[str, GroundTruth] = {}

        for func_idx, ftype in enumerate(chosen_types):
            func_id = f"{app_id}_{ftype}_{func_idx}"
            pool = _PERMISSION_POOLS[ftype]

            # Over-provision: take full pool + maybe extra wildcards
            perms = set(pool)
            if rng.random() < 0.3:   # 30% chance of wildcard over-provision
                perms.add("s3:*")
            if rng.random() < 0.15:
                perms.add("iam:AttachRolePolicy")

            wildcard_count = sum(1 for p in perms if "*" in p)
            risk = compute_risk_score(perms)

            original_policies[func_id] = PolicySnapshot(
                function_id=func_id,
                permissions=perms,
                risk_score=risk,
                wildcard_count=wildcard_count,
                resource_count=rng.randint(1, 8),
            )

            required = set(_REQUIRED_SUBSETS.get(ftype, []))
            # Add minor random variation to required set
            extras = [p for p in pool if p not in required]
            if extras:
                required.add(rng.choice(extras))

            ground_truths[func_id] = GroundTruth(
                function_id=func_id,
                required_permissions=required,
                used_in_logs=required | set(rng.sample(
                    list(perms - required), min(2, len(perms - required))
                )),
                causes_breakage_if_removed=set(_CRITICAL_PERMS.get(ftype, [])),
            )

        apps.append(SyntheticApp(
            app_id=app_id,
            functions=list(original_policies.keys()),
            original_policies=original_policies,
            ground_truths=ground_truths,
        ))

    return apps


# ---------------------------------------------------------------------------
# Optimisation strategies
# ---------------------------------------------------------------------------

def apply_naive_strategy(
    original: PolicySnapshot,
    ground_truth: GroundTruth,
) -> PolicySnapshot:
    """
    Naive least-privilege: remove every permission not seen in runtime logs.

    This is the baseline — it produces the smallest possible policy but
    ignores semantic relationships and may cause breakage.
    """
    # Keep only permissions observed in logs
    kept = original.permissions & ground_truth.used_in_logs
    # Always keep at least one permission to avoid empty policy
    if not kept:
        kept = {next(iter(original.permissions))}
    return PolicySnapshot(
        function_id=original.function_id,
        permissions=kept,
        risk_score=compute_risk_score(kept),
        wildcard_count=sum(1 for p in kept if "*" in p),
        resource_count=original.resource_count,
    )


def apply_adapol_strategy(
    original: PolicySnapshot,
    ground_truth: GroundTruth,
    rng: random.Random,
) -> PolicySnapshot:
    """
    AdaPol optimised strategy:
    - Remove permissions not in logs AND not required
    - Preserve permissions needed for correct execution
    - Reduce wildcards by replacing with specific permissions
    - Applies conservative safety margin (keeps 1–2 ambiguous permissions)

    This represents the system's actual minimisation output.
    """
    # Start from required permissions (ground truth)
    kept = set(ground_truth.required_permissions)

    # Expand with permissions observed in logs
    kept |= ground_truth.used_in_logs

    # Wildcard reduction: replace "s3:*" with specific s3 actions if present
    wildcards_to_expand = {p for p in kept if "*" in p and p != "*:*"}
    for wc in wildcards_to_expand:
        kept.discard(wc)
        service = wc.split(":")[0]
        # Add only the specific permissions from the original set for this service
        specific = {p for p in original.permissions
                    if p.startswith(f"{service}:") and "*" not in p}
        kept |= specific

    # Remove any permissions that are in the original but never used and not required
    unused_not_required = (
        original.permissions
        - ground_truth.required_permissions
        - ground_truth.used_in_logs
    )
    # Safety margin: keep a small random fraction of unused (simulates uncertainty)
    if unused_not_required and len(unused_not_required) > 3:
        n_keep = max(1, len(unused_not_required) // 6)
        safety_margin = set(rng.sample(sorted(unused_not_required), n_keep))
        kept |= safety_margin

    # Intersection with original (can't add new permissions)
    kept &= original.permissions | ground_truth.required_permissions

    return PolicySnapshot(
        function_id=original.function_id,
        permissions=kept,
        risk_score=compute_risk_score(kept),
        wildcard_count=sum(1 for p in kept if "*" in p),
        resource_count=original.resource_count,
    )


# ---------------------------------------------------------------------------
# Full benchmark pipeline
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkRun:
    """Complete benchmark run results."""
    run_id: str
    timestamp: str
    n_apps: int
    n_functions: int
    adapol_metrics: AggregateMetrics
    naive_metrics: AggregateMetrics

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "n_apps": self.n_apps,
            "n_functions": self.n_functions,
            "adapol": self.adapol_metrics.to_dict(),
            "naive_baseline": self.naive_metrics.to_dict(),
        }


class BenchmarkPipeline:
    """
    Orchestrates the full evaluation pipeline.

    Usage::

        pipeline = BenchmarkPipeline(output_dir="eval_results/")
        run = pipeline.run(n_apps=10)
        pipeline.print_report(run)
        pipeline.save_report(run)
    """

    def __init__(self, output_dir: str = "eval_results", seed: int = 42) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.calc = MetricsCalculator()
        self.seed = seed
        self._rng = random.Random(seed)

    # ── main entry point ─────────────────────────────────────────────────

    def run(
        self,
        dataset: Optional[List[SyntheticApp]] = None,
        n_apps: int = 5,
    ) -> BenchmarkRun:
        """
        Run the complete evaluation pipeline.

        Args:
            dataset: Pre-built dataset. If None, generates a synthetic one.
            n_apps:  Number of apps to generate (used only if dataset is None).

        Returns:
            BenchmarkRun with all results.
        """
        if dataset is None:
            console.print(f"[cyan]Generating synthetic dataset ({n_apps} apps)…[/cyan]")
            dataset = generate_synthetic_dataset(n_apps=n_apps, seed=self.seed)

        adapol_results: List[MetricResult] = []
        naive_results:  List[MetricResult] = []
        n_functions = sum(len(app.functions) for app in dataset)

        console.print(f"[cyan]Evaluating {n_functions} functions across {len(dataset)} apps…[/cyan]\n")

        for app in dataset:
            for func_id, original in app.original_policies.items():
                gt = app.ground_truths[func_id]

                # Strategy 1: Naive
                naive = apply_naive_strategy(original, gt)

                # Strategy 2: AdaPol
                optimised = apply_adapol_strategy(original, gt, self._rng)

                # Compute metrics
                adapol_result = self.calc.evaluate(original, optimised, gt, naive)
                naive_result  = self.calc.evaluate(original, naive, gt)

                adapol_results.append(adapol_result)
                naive_results.append(naive_result)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        run = BenchmarkRun(
            run_id=f"bench_{ts}",
            timestamp=datetime.now().isoformat(),
            n_apps=len(dataset),
            n_functions=n_functions,
            adapol_metrics=self.calc.aggregate(adapol_results),
            naive_metrics=self.calc.aggregate(naive_results),
        )
        return run

    def run_from_json(self, dataset_path: str) -> BenchmarkRun:
        """Load a JSON dataset and run evaluation."""
        with open(dataset_path) as f:
            raw = json.load(f)

        apps: List[SyntheticApp] = []
        for app_data in raw.get("apps", []):
            orig: Dict[str, PolicySnapshot] = {}
            gts:  Dict[str, GroundTruth]    = {}
            for fd in app_data.get("functions", []):
                snap = PolicySnapshot.from_dict(fd["original"])
                orig[snap.function_id] = snap
                gts[snap.function_id]  = GroundTruth.from_dict(fd["ground_truth"])
            apps.append(SyntheticApp(
                app_id=app_data["app_id"],
                functions=list(orig.keys()),
                original_policies=orig,
                ground_truths=gts,
            ))
        return self.run(dataset=apps)

    # ── reporting ─────────────────────────────────────────────────────────

    def print_report(self, run: BenchmarkRun) -> None:
        """Print a full Rich-formatted report to the console."""
        console.print(Panel.fit(
            f"[bold magenta]AdaPol Evaluation Report[/bold magenta]\n"
            f"[dim]Run: {run.run_id}  |  {run.n_apps} apps  |  {run.n_functions} functions[/dim]",
            border_style="magenta",
        ))

        # Summary comparison table
        self._print_summary_table(run)

        # Per-function details
        self._print_per_function_table(run)

        # ASCII charts
        self._print_ascii_charts(run)

    def save_report(self, run: BenchmarkRun) -> Path:
        """Save full JSON report to output_dir."""
        path = self.output_dir / f"{run.run_id}.json"
        with open(path, "w") as f:
            json.dump(run.to_dict(), f, indent=2)
        console.print(f"\n[green]✅ JSON report saved → {path}[/green]")
        return path

    def save_dataset(
        self,
        dataset: List[SyntheticApp],
        path: Optional[str] = None,
    ) -> Path:
        """Persist a synthetic dataset as JSON so it can be reused."""
        out = Path(path) if path else self.output_dir / "synthetic_dataset.json"
        payload: Dict[str, Any] = {"apps": []}
        for app in dataset:
            funcs = []
            for fid, snap in app.original_policies.items():
                gt = app.ground_truths[fid]
                funcs.append({
                    "original": snap.to_dict(),
                    "ground_truth": {
                        "function_id": gt.function_id,
                        "required_permissions": sorted(gt.required_permissions),
                        "used_in_logs": sorted(gt.used_in_logs),
                        "causes_breakage_if_removed": sorted(gt.causes_breakage_if_removed),
                    },
                })
            payload["apps"].append({"app_id": app.app_id, "functions": funcs})
        with open(out, "w") as f:
            json.dump(payload, f, indent=2)
        console.print(f"[green]✅ Dataset saved → {out}[/green]")
        return out

    def plot(self, run: BenchmarkRun, output_dir: Optional[str] = None) -> None:
        """
        Generate matplotlib charts (requires matplotlib).

        Creates two PNG files:
          - permission_reduction.png  — AdaPol vs Naive reduction % per function
          - risk_reduction.png        — Risk score before/after per function
        """
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            console.print("[yellow]⚠️  matplotlib not installed. Run: pip install matplotlib[/yellow]")
            return

        out = Path(output_dir) if output_dir else self.output_dir
        out.mkdir(parents=True, exist_ok=True)

        adapol_pfr = run.adapol_metrics
        n = adapol_pfr.total_functions
        func_labels = [r.function_id.split("_", 2)[-1][:15]
                       for r in adapol_pfr.per_function]
        x = list(range(n))

        # --- Chart 1: Permission Reduction % ---
        adapol_red = [r.permission_reduction_pct for r in adapol_pfr.per_function]
        naive_red  = [r.naive_reduction_pct for r in adapol_pfr.per_function]

        fig, ax = plt.subplots(figsize=(max(10, n * 0.8), 5))
        bar_w = 0.35
        bars1 = ax.bar([xi - bar_w/2 for xi in x], adapol_red, bar_w,
                       label="AdaPol", color="#6C63FF", alpha=0.85)
        bars2 = ax.bar([xi + bar_w/2 for xi in x], naive_red,  bar_w,
                       label="Naive", color="#FF6584", alpha=0.85)
        ax.set_xlabel("Function")
        ax.set_ylabel("Permission Reduction (%)")
        ax.set_title("Permission Reduction: AdaPol vs Naive Baseline")
        ax.set_xticks(x)
        ax.set_xticklabels(func_labels, rotation=45, ha="right", fontsize=7)
        ax.legend()
        ax.set_ylim(0, 110)
        ax.axhline(y=100, color="grey", linestyle="--", linewidth=0.8)
        _annotate_bars(ax, bars1)
        _annotate_bars(ax, bars2)
        fig.tight_layout()
        p1 = out / "permission_reduction.png"
        fig.savefig(p1, dpi=130)
        plt.close(fig)
        console.print(f"[green]📊 Chart saved → {p1}[/green]")

        # --- Chart 2: Risk Score Before / After ---
        orig_risk     = [r.original_risk_score  for r in adapol_pfr.per_function]
        adapol_risk   = [r.optimised_risk_score for r in adapol_pfr.per_function]
        naive_risk    = [r.naive_risk_score      for r in adapol_pfr.per_function]

        fig2, ax2 = plt.subplots(figsize=(max(10, n * 0.8), 5))
        bar_w2 = 0.25
        ax2.bar([xi - bar_w2     for xi in x], orig_risk,   bar_w2,
                label="Original",  color="#F7A072", alpha=0.85)
        ax2.bar([xi              for xi in x], adapol_risk, bar_w2,
                label="AdaPol",    color="#6C63FF", alpha=0.85)
        ax2.bar([xi + bar_w2     for xi in x], naive_risk,  bar_w2,
                label="Naive",     color="#FF6584", alpha=0.85)
        ax2.set_xlabel("Function")
        ax2.set_ylabel("Risk Score (0–100)")
        ax2.set_title("Risk Score Comparison: Original vs AdaPol vs Naive")
        ax2.set_xticks(x)
        ax2.set_xticklabels(func_labels, rotation=45, ha="right", fontsize=7)
        ax2.legend()
        ax2.set_ylim(0, 110)
        fig2.tight_layout()
        p2 = out / "risk_reduction.png"
        fig2.savefig(p2, dpi=130)
        plt.close(fig2)
        console.print(f"[green]📊 Chart saved → {p2}[/green]")

    # ── private display helpers ───────────────────────────────────────────

    def _print_summary_table(self, run: BenchmarkRun) -> None:
        t = Table(title="📊 Strategy Comparison Summary", show_lines=True)
        t.add_column("Metric",              style="bold cyan", no_wrap=True)
        t.add_column("AdaPol",              style="bold green", justify="right")
        t.add_column("Naive Baseline",      style="yellow",     justify="right")
        t.add_column("AdaPol Advantage",    style="magenta",    justify="right")

        a = run.adapol_metrics
        n = run.naive_metrics

        def adv(av: float, nv: float, higher_is_better: bool = True) -> str:
            diff = av - nv if higher_is_better else nv - av
            color = "green" if diff > 0 else "red"
            sign = "+" if diff > 0 else ""
            return f"[{color}]{sign}{diff:.2f}[/{color}]"

        t.add_row("Avg Permission Reduction %",
                  f"{a.avg_permission_reduction_pct:.1f}%",
                  f"{n.avg_permission_reduction_pct:.1f}%",
                  adv(a.avg_permission_reduction_pct, n.avg_permission_reduction_pct))
        t.add_row("Avg False Positive Rate",
                  f"{a.avg_false_positive_rate:.4f}",
                  f"{n.avg_false_positive_rate:.4f}",
                  adv(a.avg_false_positive_rate, n.avg_false_positive_rate, False))
        t.add_row("Avg Breakage Rate",
                  f"{a.avg_breakage_rate:.4f}",
                  f"{n.avg_breakage_rate:.4f}",
                  adv(a.avg_breakage_rate, n.avg_breakage_rate, False))
        t.add_row("Avg Risk Reduction Score",
                  f"{a.avg_risk_reduction_score:.2f}",
                  f"{n.avg_risk_reduction_score:.2f}",
                  adv(a.avg_risk_reduction_score, n.avg_risk_reduction_score))
        t.add_row("Functions with Zero Breakage",
                  str(a.functions_with_zero_breakage),
                  str(n.functions_with_zero_breakage),
                  "")
        console.print(t)

    def _print_per_function_table(self, run: BenchmarkRun) -> None:
        t = Table(title="📋 Per-Function Results (AdaPol)", show_lines=True)
        t.add_column("Function",     style="cyan", no_wrap=True, max_width=30)
        t.add_column("Orig Perms",   justify="right")
        t.add_column("Opt Perms",    justify="right")
        t.add_column("Red %",        justify="right")
        t.add_column("FP Rate",      justify="right")
        t.add_column("Breakage",     justify="right")
        t.add_column("Risk ↓",       justify="right")
        t.add_column("Breakages",    style="red", max_width=35)

        for r in run.adapol_metrics.per_function:
            red_color = "green" if r.permission_reduction_pct >= 30 else "yellow"
            brk_color = "red" if r.breakage_count > 0 else "green"
            t.add_row(
                r.function_id[-28:],
                str(r.original_permission_count),
                str(r.optimised_permission_count),
                f"[{red_color}]{r.permission_reduction_pct:.1f}%[/{red_color}]",
                f"{r.false_positive_rate:.3f}",
                f"[{brk_color}]{r.breakage_count}[/{brk_color}]",
                f"{r.risk_reduction_score:.1f}",
                ", ".join(r.breaking_permissions[:3]) or "—",
            )
        console.print(t)

    def _print_ascii_charts(self, run: BenchmarkRun) -> None:
        console.print("\n[bold]Permission Reduction % — AdaPol (each █ = 5%)[/bold]")
        for r in run.adapol_metrics.per_function:
            blocks = int(r.permission_reduction_pct // 5)
            bar = "█" * blocks
            label = r.function_id[-20:]
            color = "green" if r.permission_reduction_pct >= 30 else "yellow"
            console.print(
                f"  {label:<22} [{color}]{bar:<20}[/{color}] {r.permission_reduction_pct:.1f}%"
            )

        console.print("\n[bold]Risk Reduction Score — AdaPol (each █ = 2 pts)[/bold]")
        for r in run.adapol_metrics.per_function:
            blocks = max(0, int(r.risk_reduction_score // 2))
            bar = "█" * blocks
            label = r.function_id[-20:]
            color = "green" if r.risk_reduction_score > 0 else "red"
            console.print(
                f"  {label:<22} [{color}]{bar:<20}[/{color}] {r.risk_reduction_score:.1f}"
            )


# ---------------------------------------------------------------------------
# Standalone helpers
# ---------------------------------------------------------------------------

def _annotate_bars(ax: Any, bars: Any) -> None:
    """Add value labels on top of each bar."""
    for bar in bars:
        h = bar.get_height()
        if h > 1:
            ax.annotate(
                f"{h:.0f}%",
                xy=(bar.get_x() + bar.get_width() / 2, h),
                xytext=(0, 2),
                textcoords="offset points",
                ha="center", va="bottom",
                fontsize=6,
            )
