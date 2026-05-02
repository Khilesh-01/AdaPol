"""
Simulation Module

Policy drift detection and permission simulation engine for AdaPol.

Components:
- drift_detector: Historical policy tracking and change detection
- simulator: Permission removal simulation and failure prediction
"""

from .drift_detector import (
    PolicyDriftDetector,
    PolicySnapshot,
    DriftReport,
    PermissionChange,
    ChangeType,
    RiskCategory
)

from .simulator import (
    PermissionSimulator,
    PermissionUsageAnalyzer,
    PermissionUsageEvent,
    FunctionExecutionProfile,
    SimulationResult,
    SafetyLevel,
    PermissionUsagePattern
)

__all__ = [
    # Drift Detection
    "PolicyDriftDetector",
    "PolicySnapshot",
    "DriftReport",
    "PermissionChange",
    "ChangeType",
    "RiskCategory",
    # Simulation
    "PermissionSimulator",
    "PermissionUsageAnalyzer",
    "PermissionUsageEvent",
    "FunctionExecutionProfile",
    "SimulationResult",
    "SafetyLevel",
    "PermissionUsagePattern",
]
