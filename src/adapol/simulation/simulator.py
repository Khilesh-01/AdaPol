"""
Permission Simulation Engine

Simulates permission removal scenarios using runtime logs to predict:
- Whether removal would break execution
- Confidence scores
- Specific failure points

Uses runtime data to determine:
- If permission was actually used
- Which functions depend on it
- Safe removal candidates
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


class SafetyLevel(Enum):
    """Safety classification for permission removal."""
    SAFE_TO_REMOVE = "safe_to_remove"
    POTENTIALLY_UNSAFE = "potentially_unsafe"
    UNSAFE_TO_REMOVE = "unsafe_to_remove"
    UNKNOWN = "unknown"


class PermissionUsagePattern(Enum):
    """Patterns of permission usage."""
    FREQUENTLY_USED = "frequently_used"
    OCCASIONALLY_USED = "occasionally_used"
    RARELY_USED = "rarely_used"
    NEVER_USED = "never_used"
    CRITICAL_PATH = "critical_path"


@dataclass
class PermissionUsageEvent:
    """Single event of permission usage in logs."""
    timestamp: str
    function_id: str
    permission: str
    resource: str
    action_type: str  # read, write, admin
    api_call: str
    status: str  # success, denied, error
    principal_arn: str
    source_ip: str
    session_id: str
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "function_id": self.function_id,
            "permission": self.permission,
            "resource": self.resource,
            "action_type": self.action_type,
            "api_call": self.api_call,
            "status": self.status,
            "principal_arn": self.principal_arn,
            "source_ip": self.source_ip,
            "session_id": self.session_id,
            "context": self.context
        }


@dataclass
class FunctionExecutionProfile:
    """Profile of function execution and permission usage."""
    function_id: str
    function_name: str
    role_arn: str
    total_invocations: int = 0
    successful_invocations: int = 0
    failed_invocations: int = 0
    permissions_used: Set[str] = field(default_factory=set)
    permissions_required: Set[str] = field(default_factory=set)
    optional_permissions: Set[str] = field(default_factory=set)
    critical_permissions: Set[str] = field(default_factory=set)
    resources_accessed: Set[str] = field(default_factory=set)
    error_messages: List[str] = field(default_factory=list)
    last_execution: Optional[str] = None
    execution_times: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "function_id": self.function_id,
            "function_name": self.function_name,
            "role_arn": self.role_arn,
            "total_invocations": self.total_invocations,
            "successful_invocations": self.successful_invocations,
            "failed_invocations": self.failed_invocations,
            "permissions_used": list(self.permissions_used),
            "permissions_required": list(self.permissions_required),
            "optional_permissions": list(self.optional_permissions),
            "critical_permissions": list(self.critical_permissions),
            "resources_accessed": list(self.resources_accessed),
            "error_messages": self.error_messages[:10],  # Last 10
            "last_execution": self.last_execution,
            "execution_times": self.execution_times[-100:] if self.execution_times else []
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'FunctionExecutionProfile':
        """Create from dictionary."""
        data_copy = data.copy()
        for key in ["permissions_used", "permissions_required", "optional_permissions",
                    "critical_permissions", "resources_accessed"]:
            if key in data_copy:
                data_copy[key] = set(data_copy[key])
        return FunctionExecutionProfile(**data_copy)


@dataclass
class SimulationResult:
    """Result of simulating permission removal."""
    simulation_id: str
    timestamp: str
    permission: str
    functions_affected: List[str]
    safety_level: SafetyLevel
    confidence_score: float  # 0.0 to 1.0
    functions_would_break: List[str]
    functions_possibly_break: List[str]
    functions_safe: List[str]
    failure_predictions: Dict[str, str]  # function_id -> reason
    usage_pattern: PermissionUsagePattern
    total_functions_checked: int
    warning_messages: List[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "simulation_id": self.simulation_id,
            "timestamp": self.timestamp,
            "permission": self.permission,
            "functions_affected": self.functions_affected,
            "safety_level": self.safety_level.value,
            "confidence_score": self.confidence_score,
            "functions_would_break": self.functions_would_break,
            "functions_possibly_break": self.functions_possibly_break,
            "functions_safe": self.functions_safe,
            "failure_predictions": self.failure_predictions,
            "usage_pattern": self.usage_pattern.value,
            "total_functions_checked": self.total_functions_checked,
            "warning_messages": self.warning_messages,
            "recommendation": self.recommendation
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'SimulationResult':
        """Create from dictionary."""
        data_copy = data.copy()
        if "safety_level" in data_copy:
            data_copy["safety_level"] = SafetyLevel(data_copy["safety_level"])
        if "usage_pattern" in data_copy:
            data_copy["usage_pattern"] = PermissionUsagePattern(data_copy["usage_pattern"])
        return SimulationResult(**data_copy)


class PermissionUsageAnalyzer:
    """Analyzes runtime logs to extract permission usage patterns."""

    def __init__(self):
        """Initialize analyzer."""
        self.events: List[PermissionUsageEvent] = []
        self.function_profiles: Dict[str, FunctionExecutionProfile] = {}
        self.permission_functions: Dict[str, Set[str]] = defaultdict(set)
        logger.info("PermissionUsageAnalyzer initialized")

    def load_events(self, filepath: Path) -> int:
        """Load runtime events from JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # Handle both array and object formats
        events_data = data if isinstance(data, list) else data.get("events", [])
        
        count = 0
        for event_data in events_data:
            event = PermissionUsageEvent(**event_data)
            self.events.append(event)
            count += 1
        
        logger.info(f"Loaded {count} events from {filepath}")
        return count

    def analyze_events(self) -> Dict[str, FunctionExecutionProfile]:
        """
        Analyze all events and build function execution profiles.
        
        Returns:
            Dictionary mapping function ID to execution profile
        """
        for event in self.events:
            # Get or create profile
            if event.function_id not in self.function_profiles:
                self.function_profiles[event.function_id] = FunctionExecutionProfile(
                    function_id=event.function_id,
                    function_name=event.function_id,
                    role_arn=""
                )
            
            profile = self.function_profiles[event.function_id]
            profile.total_invocations += 1
            profile.permissions_used.add(event.permission)
            profile.resources_accessed.add(event.resource)
            profile.last_execution = event.timestamp
            
            # Track success/failure
            if event.status == "success":
                profile.successful_invocations += 1
            else:
                profile.failed_invocations += 1
                profile.error_messages.append(f"{event.api_call}: {event.status}")
            
            # Track permission usage
            self.permission_functions[event.permission].add(event.function_id)
        
        # Classify permissions
        self._classify_permissions()
        
        logger.info(f"Analyzed {len(self.function_profiles)} functions from {len(self.events)} events")
        return self.function_profiles

    def _classify_permissions(self) -> None:
        """Classify permissions as required, critical, or optional."""
        for func_id, profile in self.function_profiles.items():
            for perm in profile.permissions_used:
                # Count usage frequency
                usage_count = sum(
                    1 for event in self.events
                    if event.function_id == func_id and event.permission == perm
                )
                
                if usage_count > 10:
                    # Frequently used - likely required
                    profile.permissions_required.add(perm)
                elif usage_count > 3:
                    # Occasionally used - possibly required
                    profile.permissions_required.add(perm)
                elif usage_count > 0:
                    # Rarely used - optional
                    profile.optional_permissions.add(perm)
                
                # Mark critical permissions
                if perm.startswith("iam:") or perm.endswith(":*"):
                    profile.critical_permissions.add(perm)

    def get_functions_using_permission(self, permission: str) -> Set[str]:
        """Get all functions that use a specific permission."""
        return self.permission_functions.get(permission, set())

    def get_usage_pattern(self, permission: str) -> PermissionUsagePattern:
        """Determine usage pattern for a permission."""
        usage_count = len(self.permission_functions.get(permission, set()))
        total_events = sum(
            1 for event in self.events if event.permission == permission
        )
        
        if total_events == 0:
            return PermissionUsagePattern.NEVER_USED
        elif total_events > 50:
            return PermissionUsagePattern.FREQUENTLY_USED
        elif total_events > 10:
            return PermissionUsagePattern.OCCASIONALLY_USED
        elif total_events > 1:
            return PermissionUsagePattern.RARELY_USED
        else:
            return PermissionUsagePattern.NEVER_USED

    def export_profiles(self, filepath: Path) -> None:
        """Export function profiles to JSON."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        profiles_dict = {
            func_id: profile.to_dict()
            for func_id, profile in self.function_profiles.items()
        }
        
        with open(filepath, 'w') as f:
            json.dump(profiles_dict, f, indent=2)
        logger.info(f"Profiles exported to {filepath}")


class PermissionSimulator:
    """
    Simulates the impact of removing permissions.
    
    Predicts:
    - Whether removal will break execution
    - Confidence scores
    - Specific failure predictions
    """

    def __init__(self, analyzer: PermissionUsageAnalyzer):
        """Initialize simulator with usage analyzer."""
        self.analyzer = analyzer
        self.simulations: Dict[str, SimulationResult] = {}
        logger.info("PermissionSimulator initialized")

    def simulate_removal(self, permission: str) -> SimulationResult:
        """
        Simulate removing a specific permission.
        
        Args:
            permission: Permission to simulate removing
            
        Returns:
            SimulationResult with safety assessment
        """
        simulation_id = f"sim_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{permission.replace(':', '_')}"
        
        affected_functions = list(self.analyzer.get_functions_using_permission(permission))
        functions_would_break = []
        functions_possibly_break = []
        functions_safe = []
        failure_predictions = {}
        warning_messages = []
        
        # Analyze each affected function
        for func_id in affected_functions:
            profile = self.analyzer.function_profiles.get(func_id)
            if not profile:
                continue
            
            if permission in profile.critical_permissions:
                functions_would_break.append(func_id)
                failure_predictions[func_id] = f"Removing {permission} will break function (critical permission)"
                warning_messages.append(f"🔴 UNSAFE: {permission} is CRITICAL for {func_id}")
            elif permission in profile.permissions_required:
                functions_would_break.append(func_id)
                failure_predictions[func_id] = f"Removing {permission} will break function (required for execution)"
                warning_messages.append(f"🔴 UNSAFE: {permission} is REQUIRED for {func_id}")
            elif permission in profile.optional_permissions:
                functions_possibly_break.append(func_id)
                failure_predictions[func_id] = f"Removing {permission} may break function (used but not critical)"
                warning_messages.append(f"🟡 CAUTION: {permission} is OPTIONAL but used by {func_id}")
            else:
                functions_safe.append(func_id)
        
        # Determine safety level and confidence
        if functions_would_break:
            safety_level = SafetyLevel.UNSAFE_TO_REMOVE
            confidence_score = 0.95
        elif functions_possibly_break:
            safety_level = SafetyLevel.POTENTIALLY_UNSAFE
            confidence_score = 0.70
        elif not affected_functions:
            safety_level = SafetyLevel.SAFE_TO_REMOVE
            confidence_score = 0.99
        else:
            safety_level = SafetyLevel.SAFE_TO_REMOVE
            confidence_score = 0.85
        
        # Determine usage pattern
        usage_pattern = self.analyzer.get_usage_pattern(permission)
        
        # Generate recommendation
        recommendation = self._generate_recommendation(
            safety_level, usage_pattern, len(affected_functions)
        )
        
        result = SimulationResult(
            simulation_id=simulation_id,
            timestamp=datetime.now().isoformat(),
            permission=permission,
            functions_affected=affected_functions,
            safety_level=safety_level,
            confidence_score=confidence_score,
            functions_would_break=functions_would_break,
            functions_possibly_break=functions_possibly_break,
            functions_safe=functions_safe,
            failure_predictions=failure_predictions,
            usage_pattern=usage_pattern,
            total_functions_checked=len(self.analyzer.function_profiles),
            warning_messages=warning_messages,
            recommendation=recommendation
        )
        
        self.simulations[simulation_id] = result
        logger.info(f"Created simulation {simulation_id} for permission {permission}")
        
        return result

    def simulate_batch_removal(self, permissions: List[str]) -> List[SimulationResult]:
        """
        Simulate removing multiple permissions.
        
        Args:
            permissions: List of permissions to simulate
            
        Returns:
            List of SimulationResults
        """
        results = []
        for perm in permissions:
            result = self.simulate_removal(perm)
            results.append(result)
        
        logger.info(f"Completed batch simulation for {len(permissions)} permissions")
        return results

    def _generate_recommendation(self, safety_level: SafetyLevel, 
                               usage_pattern: PermissionUsagePattern,
                               affected_count: int) -> str:
        """Generate human-readable recommendation."""
        if safety_level == SafetyLevel.SAFE_TO_REMOVE:
            if usage_pattern == PermissionUsagePattern.NEVER_USED:
                return "✅ SAFE: Permission never used in logs - SAFE to remove"
            else:
                return f"✅ SAFE: Permission used by {affected_count} function(s) but not critical - Can be safely removed with testing"
        
        elif safety_level == SafetyLevel.POTENTIALLY_UNSAFE:
            return f"🟡 CAUTION: Permission used by {affected_count} function(s) in optional contexts - Test thoroughly before removing"
        
        elif safety_level == SafetyLevel.UNSAFE_TO_REMOVE:
            return f"🔴 UNSAFE: Permission is REQUIRED by {len([x for x in [1] if x])} function(s) - DO NOT REMOVE without alternative implementation"
        
        else:
            return "❓ UNKNOWN: Unable to determine removal safety - Review manually"

    def analyze_permission_dependencies(self, permission: str) -> Dict[str, Any]:
        """
        Analyze dependency chain for a permission.
        
        Returns:
            Detailed dependency information
        """
        functions = self.analyzer.get_functions_using_permission(permission)
        
        dependency_graph = {}
        for func_id in functions:
            profile = self.analyzer.function_profiles.get(func_id)
            if profile:
                dependency_graph[func_id] = {
                    "permissions_required": list(profile.permissions_required),
                    "permissions_optional": list(profile.optional_permissions),
                    "critical_permissions": list(profile.critical_permissions),
                    "resources_accessed": list(profile.resources_accessed),
                    "total_invocations": profile.total_invocations
                }
        
        return {
            "permission": permission,
            "affected_functions": list(functions),
            "dependency_graph": dependency_graph,
            "total_affected": len(functions)
        }

    def find_safe_removals(self, confidence_threshold: float = 0.85) -> List[str]:
        """
        Find permissions that are safe to remove.
        
        Args:
            confidence_threshold: Minimum confidence score
            
        Returns:
            List of safely removable permissions
        """
        safe_perms = []
        
        # Test each permission used in logs
        all_permissions = set().union(
            *[profile.permissions_used 
              for profile in self.analyzer.function_profiles.values()]
        )
        
        for perm in all_permissions:
            result = self.simulate_removal(perm)
            if result.safety_level == SafetyLevel.SAFE_TO_REMOVE and \
               result.confidence_score >= confidence_threshold:
                safe_perms.append(perm)
        
        return sorted(safe_perms)

    def find_critical_permissions(self) -> List[str]:
        """Find permissions that are critical and should not be removed."""
        critical = set()
        
        for profile in self.analyzer.function_profiles.values():
            critical.update(profile.critical_permissions)
        
        return sorted(list(critical))

    def export_simulation_json(self, result: SimulationResult, filepath: Path) -> None:
        """Export simulation result to JSON."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        logger.info(f"Simulation exported to {filepath}")

    def import_simulation_json(self, filepath: Path) -> SimulationResult:
        """Import simulation result from JSON."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        result = SimulationResult.from_dict(data)
        self.simulations[result.simulation_id] = result
        logger.info(f"Simulation imported from {filepath}")
        return result

    def generate_removal_plan(self, max_removals: int = 10) -> Dict[str, Any]:
        """
        Generate a plan for safely removing permissions.
        
        Args:
            max_removals: Maximum number of permissions to recommend for removal
            
        Returns:
            Plan with phases and safety checks
        """
        safe_removals = self.find_safe_removals()[:max_removals]
        critical_perms = self.find_critical_permissions()
        
        plan = {
            "generated": datetime.now().isoformat(),
            "safe_to_remove": safe_removals,
            "critical_permissions": critical_perms,
            "removal_phases": self._generate_removal_phases(safe_removals),
            "risk_assessment": {
                "permissions_to_remove": len(safe_removals),
                "critical_permissions_count": len(critical_perms),
                "estimated_risk": "LOW" if safe_removals else "HIGH"
            }
        }
        
        return plan

    def _generate_removal_phases(self, permissions: List[str]) -> List[Dict[str, Any]]:
        """Generate phased removal plan."""
        phases = []
        
        # Phase 1: Never-used permissions
        never_used = [p for p in permissions 
                     if self.analyzer.get_usage_pattern(p) == PermissionUsagePattern.NEVER_USED]
        if never_used:
            phases.append({
                "phase": 1,
                "name": "Safe removals",
                "permissions": never_used,
                "risk": "MINIMAL",
                "testing": "Standard regression testing"
            })
        
        # Phase 2: Rarely-used permissions
        rarely_used = [p for p in permissions 
                      if self.analyzer.get_usage_pattern(p) == PermissionUsagePattern.RARELY_USED]
        if rarely_used:
            phases.append({
                "phase": 2,
                "name": "Rarely-used removals",
                "permissions": rarely_used,
                "risk": "LOW",
                "testing": "Extended testing with monitoring"
            })
        
        return phases
