"""
Simulation Module

Policy drift detection, permission simulation engine, and failure
prediction for AdaPol.

Components:
- drift_detector  : Historical policy tracking and change detection
- simulator       : Permission removal simulation with confidence scoring
- failure_predictor: Human-readable failure warnings per function
"""

from .drift_detector import (
    PolicyDriftDetector,
    PolicySnapshot,
    DriftReport,
    PermissionChange,
    ChangeType,
    RiskCategory,
)

from .simulator import (
    PermissionSimulator,
    PermissionUsageAnalyzer,
    PermissionUsageEvent,
    FunctionExecutionProfile,
    SimulationResult,
    SafetyLevel,
    PermissionUsagePattern,
)

from .failure_predictor import (
    FailurePredictor,
    FailureWarning,
    FailurePredictionReport,
    FailureSeverity,
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
    # Failure Prediction
    "FailurePredictor",
    "FailureWarning",
    "FailurePredictionReport",
    "FailureSeverity",
]
