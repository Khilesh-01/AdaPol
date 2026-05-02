"""
Failure Prediction Engine

Generates specific, actionable warnings such as:
  "Removing s3:GetObject will break function upload_handler"

Works on top of the PermissionUsageAnalyzer to produce human-readable
failure predictions ranked by severity.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class FailureSeverity(Enum):
    """Severity of predicted failure if permission is removed."""
    CRITICAL = "CRITICAL"   # will definitely break
    HIGH = "HIGH"           # almost certainly break
    MEDIUM = "MEDIUM"       # likely to break under load
    LOW = "LOW"             # may break in edge cases
    NONE = "NONE"           # safe to remove


@dataclass
class FailureWarning:
    """
    A single failure prediction warning.

    Example: "Removing s3:GetObject will break function upload_handler"
    """
    permission: str
    function_id: str
    function_name: str
    severity: FailureSeverity
    message: str
    detail: str
    usage_count: int = 0
    last_used: Optional[str] = None
    resources_affected: List[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "permission": self.permission,
            "function_id": self.function_id,
            "function_name": self.function_name,
            "severity": self.severity.value,
            "message": self.message,
            "detail": self.detail,
            "usage_count": self.usage_count,
            "last_used": self.last_used,
            "resources_affected": self.resources_affected,
            "remediation": self.remediation,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "FailureWarning":
        d = data.copy()
        d["severity"] = FailureSeverity(d["severity"])
        return FailureWarning(**d)

    def formatted(self) -> str:
        """Return a one-line human-readable warning string."""
        icon = {
            FailureSeverity.CRITICAL: "🔴",
            FailureSeverity.HIGH:     "🟠",
            FailureSeverity.MEDIUM:   "🟡",
            FailureSeverity.LOW:      "🔵",
            FailureSeverity.NONE:     "✅",
        }[self.severity]
        return f"{icon} [{self.severity.value}] {self.message}"


@dataclass
class FailurePredictionReport:
    """Aggregated failure predictions for one or more permissions."""
    report_id: str
    timestamp: str
    permissions_evaluated: List[str]
    warnings: List[FailureWarning] = field(default_factory=list)
    safe_permissions: List[str] = field(default_factory=list)
    total_functions_checked: int = 0

    # ── summary counters ──────────────────────────────────────────────────
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    def add_warning(self, w: FailureWarning) -> None:
        self.warnings.append(w)
        if w.severity == FailureSeverity.CRITICAL:
            self.critical_count += 1
        elif w.severity == FailureSeverity.HIGH:
            self.high_count += 1
        elif w.severity == FailureSeverity.MEDIUM:
            self.medium_count += 1
        elif w.severity == FailureSeverity.LOW:
            self.low_count += 1

    def sorted_warnings(self) -> List[FailureWarning]:
        order = {
            FailureSeverity.CRITICAL: 0,
            FailureSeverity.HIGH: 1,
            FailureSeverity.MEDIUM: 2,
            FailureSeverity.LOW: 3,
            FailureSeverity.NONE: 4,
        }
        return sorted(self.warnings, key=lambda w: order[w.severity])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "permissions_evaluated": self.permissions_evaluated,
            "warnings": [w.to_dict() for w in self.warnings],
            "safe_permissions": self.safe_permissions,
            "total_functions_checked": self.total_functions_checked,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "FailurePredictionReport":
        d = data.copy()
        d["warnings"] = [FailureWarning.from_dict(w) for w in d.get("warnings", [])]
        return FailurePredictionReport(**d)


class FailurePredictor:
    """
    Generates human-readable failure warnings for permission removals.

    Usage::

        from simulation.simulator import PermissionUsageAnalyzer
        from simulation.failure_predictor import FailurePredictor

        analyzer = PermissionUsageAnalyzer()
        analyzer.load_events(Path("runtime_logs.json"))
        analyzer.analyze_events()

        predictor = FailurePredictor(analyzer)
        report = predictor.predict_failures(["s3:GetObject", "iam:ListRoles"])
        for w in report.sorted_warnings():
            print(w.formatted())
    """

    # Permissions that are nearly always critical if used
    _ALWAYS_CRITICAL = {
        "iam:*", "*:*", "iam:CreateAccessKey", "iam:AttachRolePolicy",
        "iam:PutRolePolicy", "sts:AssumeRole", "kms:Decrypt",
    }

    def __init__(self, analyzer: Any) -> None:
        """
        Args:
            analyzer: An initialised & analysed PermissionUsageAnalyzer instance.
        """
        self.analyzer = analyzer
        logger.info("FailurePredictor initialised")

    # ── public API ────────────────────────────────────────────────────────

    def predict_failures(self, permissions: List[str]) -> FailurePredictionReport:
        """
        Predict failure impact of removing each listed permission.

        Args:
            permissions: Permissions to evaluate.

        Returns:
            FailurePredictionReport with per-function warnings.
        """
        report = FailurePredictionReport(
            report_id=f"fp_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.now().isoformat(),
            permissions_evaluated=list(permissions),
            total_functions_checked=len(self.analyzer.function_profiles),
        )

        for permission in permissions:
            functions_using = self.analyzer.get_functions_using_permission(permission)
            if not functions_using:
                report.safe_permissions.append(permission)
                continue

            found_any_warning = False
            for func_id in functions_using:
                profile = self.analyzer.function_profiles.get(func_id)
                if not profile:
                    continue

                warning = self._build_warning(permission, func_id, profile)
                if warning.severity == FailureSeverity.NONE:
                    report.safe_permissions.append(permission)
                else:
                    report.add_warning(warning)
                    found_any_warning = True

            if not found_any_warning and permission not in report.safe_permissions:
                report.safe_permissions.append(permission)

        logger.info(
            "Failure prediction complete: %d warnings across %d permissions",
            len(report.warnings),
            len(permissions),
        )
        return report

    def predict_single(self, permission: str) -> List[FailureWarning]:
        """Predict failures for a single permission removal."""
        report = self.predict_failures([permission])
        return report.warnings

    def export_report(self, report: FailurePredictionReport, filepath: Path) -> None:
        """Export prediction report to JSON."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        logger.info("Failure prediction report saved to %s", filepath)

    # ── internals ─────────────────────────────────────────────────────────

    def _build_warning(self, permission: str, func_id: str, profile: Any) -> FailureWarning:
        """Build a FailureWarning for a specific permission + function pair."""
        func_name = profile.function_name or func_id
        usage_count = self._count_usage(permission, func_id)
        resources = sorted(profile.resources_accessed)[:5]
        last_used = profile.last_execution

        severity = self._assess_severity(permission, func_id, profile, usage_count)
        message, detail, remediation = self._build_messages(
            permission, func_name, severity, usage_count, resources
        )

        return FailureWarning(
            permission=permission,
            function_id=func_id,
            function_name=func_name,
            severity=severity,
            message=message,
            detail=detail,
            usage_count=usage_count,
            last_used=last_used,
            resources_affected=resources,
            remediation=remediation,
        )

    def _assess_severity(
        self, permission: str, func_id: str, profile: Any, usage_count: int
    ) -> FailureSeverity:
        """Determine how bad removal of this permission would be."""
        if permission in self._ALWAYS_CRITICAL:
            return FailureSeverity.CRITICAL

        if permission in profile.critical_permissions:
            return FailureSeverity.CRITICAL

        if permission in profile.permissions_required:
            # High usage = definitely required
            if usage_count >= 10:
                return FailureSeverity.CRITICAL
            return FailureSeverity.HIGH

        if permission in profile.optional_permissions:
            if usage_count >= 5:
                return FailureSeverity.MEDIUM
            return FailureSeverity.LOW

        # Permission is in the profile.permissions_used but not classified
        if usage_count > 0:
            return FailureSeverity.LOW

        return FailureSeverity.NONE

    def _build_messages(
        self,
        permission: str,
        func_name: str,
        severity: FailureSeverity,
        usage_count: int,
        resources: List[str],
    ):
        """Return (message, detail, remediation) strings."""
        res_str = ", ".join(resources[:3]) if resources else "unknown resources"

        if severity == FailureSeverity.CRITICAL:
            message = (
                f"Removing {permission} WILL break function {func_name}"
            )
            detail = (
                f"The function '{func_name}' invoked {permission} {usage_count} time(s) "
                f"against {res_str}. This permission is classified as REQUIRED/CRITICAL — "
                f"removing it will cause immediate execution failures."
            )
            remediation = (
                f"Do NOT remove {permission}. If you must reduce scope, restrict the "
                f"resource ARN instead of removing the action entirely."
            )

        elif severity == FailureSeverity.HIGH:
            message = (
                f"Removing {permission} will almost certainly break function {func_name}"
            )
            detail = (
                f"'{func_name}' used {permission} {usage_count} time(s) on {res_str}. "
                f"It is marked as a required permission for this function."
            )
            remediation = (
                f"Review whether {permission} can be scoped to a narrower resource ARN "
                f"before considering removal."
            )

        elif severity == FailureSeverity.MEDIUM:
            message = (
                f"Removing {permission} may break function {func_name} under some conditions"
            )
            detail = (
                f"'{func_name}' used {permission} {usage_count} time(s) on {res_str}. "
                f"It was classified as optional but has non-trivial usage."
            )
            remediation = (
                f"Test {func_name} thoroughly in staging before removing {permission} "
                f"in production."
            )

        elif severity == FailureSeverity.LOW:
            message = (
                f"Removing {permission} might affect function {func_name} in edge cases"
            )
            detail = (
                f"'{func_name}' used {permission} only {usage_count} time(s). "
                f"Low-frequency usage suggests it may be an optional feature path."
            )
            remediation = (
                f"Monitor {func_name} closely after removing {permission}. "
                f"Consider canary deployment."
            )

        else:
            message = f"{permission} appears safe to remove from {func_name}"
            detail = "No usage detected in runtime logs."
            remediation = "Verify logs cover a sufficient observation window."

        return message, detail, remediation

    def _count_usage(self, permission: str, func_id: str) -> int:
        """Count how many times a function used a specific permission in logs."""
        return sum(
            1
            for event in self.analyzer.events
            if event.function_id == func_id and event.permission == permission
        )
