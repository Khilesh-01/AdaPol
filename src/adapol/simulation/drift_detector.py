"""
Policy Drift Detection Module

Detects changes in cloud IAM policies over time, including:
- Permission creep (new permissions added)
- Newly introduced high-risk permissions
- Removed permissions
- Policy modifications

Supports comparison between snapshots and detailed change analysis.
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


class ChangeType(Enum):
    """Types of policy changes detected."""
    PERMISSION_ADDED = "permission_added"
    PERMISSION_REMOVED = "permission_removed"
    PERMISSION_MODIFIED = "permission_modified"
    RESOURCE_CHANGED = "resource_changed"
    EFFECT_CHANGED = "effect_changed"
    CONDITION_ADDED = "condition_added"
    CONDITION_REMOVED = "condition_removed"


class RiskCategory(Enum):
    """Risk classification for permissions."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


@dataclass
class PermissionChange:
    """Represents a single permission change detected between snapshots."""
    change_type: ChangeType
    permission: str
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    resource_arn: Optional[str] = None
    policy_id: str = ""
    role_name: str = ""
    risk_level: Optional[RiskCategory] = None
    is_wildcard: bool = False
    affected_principals: List[str] = field(default_factory=list)
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "change_type": self.change_type.value,
            "permission": self.permission,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "resource_arn": self.resource_arn,
            "policy_id": self.policy_id,
            "role_name": self.role_name,
            "risk_level": self.risk_level.value if self.risk_level else None,
            "is_wildcard": self.is_wildcard,
            "affected_principals": self.affected_principals,
            "timestamp": self.timestamp
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'PermissionChange':
        """Create from dictionary."""
        data_copy = data.copy()
        if "change_type" in data_copy:
            data_copy["change_type"] = ChangeType(data_copy["change_type"])
        if "risk_level" in data_copy and data_copy["risk_level"]:
            data_copy["risk_level"] = RiskCategory(data_copy["risk_level"])
        return PermissionChange(**data_copy)


@dataclass
class PolicySnapshot:
    """Represents a point-in-time snapshot of cloud IAM policies."""
    snapshot_id: str
    timestamp: str
    provider: str  # aws, azure, gcp
    policies: Dict[str, Any]
    roles: Dict[str, Any]
    permissions_by_role: Dict[str, Set[str]] = field(default_factory=dict)
    high_risk_permissions: Dict[str, List[str]] = field(default_factory=dict)
    wildcard_permissions: Dict[str, List[str]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Extract permissions by role and analyze for risks."""
        if not self.permissions_by_role:
            self._extract_permissions()
        if not self.high_risk_permissions:
            self._identify_high_risk_permissions()
        if not self.wildcard_permissions:
            self._identify_wildcard_permissions()

    def _extract_permissions(self) -> None:
        """Extract all permissions organized by role."""
        self.permissions_by_role = defaultdict(set)
        
        for role_name, role_data in self.roles.items():
            if isinstance(role_data, dict):
                policies = role_data.get("policies", [])
                if isinstance(policies, list):
                    for policy in policies:
                        if isinstance(policy, dict):
                            statements = policy.get("Statement", [])
                            for statement in statements:
                                if isinstance(statement, dict):
                                    actions = statement.get("Action", [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    self.permissions_by_role[role_name].update(actions)

    def _identify_high_risk_permissions(self) -> None:
        """Identify high-risk permissions in policies."""
        high_risk_perms = {
            "iam:*", "iam:AttachUserPolicy", "iam:AttachRolePolicy",
            "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:CreateAccessKey",
            "sts:AssumeRole", "kms:*", "kms:ScheduleKeyDeletion",
            "*:*", "iam:CreateUser", "iam:CreateRole"
        }
        
        self.high_risk_permissions = defaultdict(list)
        for role_name, permissions in self.permissions_by_role.items():
            for perm in permissions:
                if perm in high_risk_perms or perm.startswith("iam:") or perm.endswith(":*"):
                    self.high_risk_permissions[role_name].append(perm)

    def _identify_wildcard_permissions(self) -> None:
        """Identify wildcard permissions."""
        self.wildcard_permissions = defaultdict(list)
        for role_name, permissions in self.permissions_by_role.items():
            for perm in permissions:
                if "*" in perm:
                    self.wildcard_permissions[role_name].append(perm)

    def get_all_permissions(self) -> Set[str]:
        """Get all unique permissions in snapshot."""
        return set().union(*self.permissions_by_role.values())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "provider": self.provider,
            "policies": self.policies,
            "roles": self.roles,
            "permissions_by_role": {k: list(v) for k, v in self.permissions_by_role.items()},
            "high_risk_permissions": self.high_risk_permissions,
            "wildcard_permissions": self.wildcard_permissions,
            "metadata": self.metadata
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'PolicySnapshot':
        """Create snapshot from dictionary."""
        data_copy = data.copy()
        if "permissions_by_role" in data_copy:
            data_copy["permissions_by_role"] = {
                k: set(v) for k, v in data_copy["permissions_by_role"].items()
            }
        return PolicySnapshot(**data_copy)


@dataclass
class DriftReport:
    """Comprehensive drift analysis report."""
    report_id: str
    timestamp: str
    old_snapshot_id: str
    new_snapshot_id: str
    total_changes: int = 0
    permission_creep_count: int = 0
    high_risk_additions: int = 0
    high_risk_removals: int = 0
    wildcard_additions: int = 0
    wildcard_removals: int = 0
    total_permissions_added: int = 0
    total_permissions_removed: int = 0
    changes: List[PermissionChange] = field(default_factory=list)
    affected_roles: Set[str] = field(default_factory=set)
    risk_level: RiskCategory = RiskCategory.LOW
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)

    def add_change(self, change: PermissionChange) -> None:
        """Add a detected change."""
        self.changes.append(change)
        self.total_changes += 1
        
        if change.role_name:
            self.affected_roles.add(change.role_name)
        
        if change.change_type == ChangeType.PERMISSION_ADDED:
            self.total_permissions_added += 1
            if change.risk_level in [RiskCategory.CRITICAL, RiskCategory.HIGH]:
                self.high_risk_additions += 1
            if change.is_wildcard:
                self.wildcard_additions += 1
            self.permission_creep_count += 1
        
        elif change.change_type == ChangeType.PERMISSION_REMOVED:
            self.total_permissions_removed += 1
            if change.risk_level in [RiskCategory.CRITICAL, RiskCategory.HIGH]:
                self.high_risk_removals += 1
            if change.is_wildcard:
                self.wildcard_removals += 1

    def calculate_risk_level(self) -> None:
        """Calculate overall risk level for the drift."""
        if self.high_risk_additions >= 3 or self.wildcard_additions >= 2:
            self.risk_level = RiskCategory.CRITICAL
        elif self.high_risk_additions > 0 or self.wildcard_additions > 0:
            self.risk_level = RiskCategory.HIGH
        elif self.permission_creep_count > 10:
            self.risk_level = RiskCategory.MEDIUM
        elif self.permission_creep_count > 0:
            self.risk_level = RiskCategory.LOW
        else:
            self.risk_level = RiskCategory.MINIMAL

    def generate_summary(self) -> str:
        """Generate human-readable summary."""
        lines = [
            f"Policy Drift Report ({self.report_id})",
            f"Timestamp: {self.timestamp}",
            f"Risk Level: {self.risk_level.value}",
            f"",
            f"Summary Statistics:",
            f"  Total Changes: {self.total_changes}",
            f"  Permissions Added: {self.total_permissions_added}",
            f"  Permissions Removed: {self.total_permissions_removed}",
            f"  Permission Creep Events: {self.permission_creep_count}",
            f"  High-Risk Additions: {self.high_risk_additions}",
            f"  Wildcard Additions: {self.wildcard_additions}",
            f"  Affected Roles: {len(self.affected_roles)}"
        ]
        
        if self.high_risk_additions > 0:
            lines.append(f"\n⚠️  WARNING: {self.high_risk_additions} high-risk permissions added")
        if self.wildcard_additions > 0:
            lines.append(f"\n⚠️  WARNING: {self.wildcard_additions} wildcard permissions added")
        if self.permission_creep_count > 10:
            lines.append(f"\n⚠️  WARNING: Significant permission creep detected")
        
        self.summary = "\n".join(lines)
        return self.summary

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "old_snapshot_id": self.old_snapshot_id,
            "new_snapshot_id": self.new_snapshot_id,
            "total_changes": self.total_changes,
            "permission_creep_count": self.permission_creep_count,
            "high_risk_additions": self.high_risk_additions,
            "high_risk_removals": self.high_risk_removals,
            "wildcard_additions": self.wildcard_additions,
            "wildcard_removals": self.wildcard_removals,
            "total_permissions_added": self.total_permissions_added,
            "total_permissions_removed": self.total_permissions_removed,
            "changes": [c.to_dict() for c in self.changes],
            "affected_roles": list(self.affected_roles),
            "risk_level": self.risk_level.value,
            "summary": self.summary,
            "recommendations": self.recommendations
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'DriftReport':
        """Create from dictionary."""
        data_copy = data.copy()
        if "risk_level" in data_copy:
            data_copy["risk_level"] = RiskCategory(data_copy["risk_level"])
        if "changes" in data_copy:
            data_copy["changes"] = [
                PermissionChange.from_dict(c) for c in data_copy["changes"]
            ]
        if "affected_roles" in data_copy:
            data_copy["affected_roles"] = set(data_copy["affected_roles"])
        return DriftReport(**data_copy)


class PolicyDriftDetector:
    """
    Detects and analyzes policy drift between snapshots.
    
    Supports:
    - Permission creep detection
    - High-risk permission tracking
    - Wildcard permission monitoring
    - Detailed change analysis
    """

    # High-risk permissions by provider
    HIGH_RISK_PERMISSIONS = {
        "aws": {
            "iam:*", "iam:AttachUserPolicy", "iam:AttachRolePolicy",
            "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:CreateAccessKey",
            "sts:AssumeRole", "kms:*", "kms:ScheduleKeyDeletion",
            "*:*", "iam:CreateUser", "iam:CreateRole", "s3:*"
        },
        "azure": {
            "*/write", "*/delete", "Microsoft.Authorization/*",
            "Microsoft.Authorization/roleAssignments/write"
        },
        "gcp": {
            "resourcemanager.organizations.setIamPolicy",
            "iam.serviceAccounts.getAccessToken",
            "iam.serviceAccounts.actAs"
        }
    }

    def __init__(self):
        """Initialize drift detector."""
        self.snapshots: Dict[str, PolicySnapshot] = {}
        self.reports: Dict[str, DriftReport] = {}
        logger.info("PolicyDriftDetector initialized")

    def save_snapshot(self, snapshot: PolicySnapshot, filepath: Optional[Path] = None) -> str:
        """
        Save a policy snapshot.
        
        Args:
            snapshot: PolicySnapshot to save
            filepath: Optional file path to save snapshot JSON
            
        Returns:
            Snapshot ID
        """
        self.snapshots[snapshot.snapshot_id] = snapshot
        logger.info(f"Saved snapshot {snapshot.snapshot_id}")
        
        if filepath:
            filepath = Path(filepath)
            filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(snapshot.to_dict(), f, indent=2)
            logger.info(f"Snapshot saved to {filepath}")
        
        return snapshot.snapshot_id

    def load_snapshot(self, filepath: Path) -> PolicySnapshot:
        """Load a snapshot from JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        snapshot = PolicySnapshot.from_dict(data)
        self.snapshots[snapshot.snapshot_id] = snapshot
        logger.info(f"Loaded snapshot {snapshot.snapshot_id} from {filepath}")
        return snapshot

    def compare_snapshots(self, old_snapshot: PolicySnapshot, 
                         new_snapshot: PolicySnapshot) -> DriftReport:
        """
        Compare two snapshots and detect drift.
        
        Args:
            old_snapshot: Previous policy snapshot
            new_snapshot: Current policy snapshot
            
        Returns:
            DriftReport with detailed changes
        """
        report_id = f"drift_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        report = DriftReport(
            report_id=report_id,
            timestamp=datetime.now().isoformat(),
            old_snapshot_id=old_snapshot.snapshot_id,
            new_snapshot_id=new_snapshot.snapshot_id
        )

        # Compare permissions by role
        all_roles = set(old_snapshot.permissions_by_role.keys()) | \
                    set(new_snapshot.permissions_by_role.keys())
        
        for role_name in all_roles:
            old_perms = old_snapshot.permissions_by_role.get(role_name, set())
            new_perms = new_snapshot.permissions_by_role.get(role_name, set())
            
            # Detect added permissions
            for perm in new_perms - old_perms:
                change = self._create_permission_change(
                    ChangeType.PERMISSION_ADDED,
                    perm,
                    role_name,
                    new_snapshot.provider,
                    new_value=perm
                )
                report.add_change(change)
            
            # Detect removed permissions
            for perm in old_perms - new_perms:
                change = self._create_permission_change(
                    ChangeType.PERMISSION_REMOVED,
                    perm,
                    role_name,
                    new_snapshot.provider,
                    old_value=perm
                )
                report.add_change(change)

        # Calculate risk and generate recommendations
        report.calculate_risk_level()
        report.generate_summary()
        self._generate_recommendations(report)
        
        self.reports[report_id] = report
        logger.info(f"Created drift report {report_id} with {report.total_changes} changes")
        
        return report

    def _create_permission_change(self, change_type: ChangeType, permission: str,
                                 role_name: str, provider: str,
                                 old_value: Optional[str] = None,
                                 new_value: Optional[str] = None) -> PermissionChange:
        """Create a PermissionChange with risk assessment."""
        is_wildcard = "*" in permission
        risk_level = self._assess_permission_risk(permission, provider)
        
        return PermissionChange(
            change_type=change_type,
            permission=permission,
            old_value=old_value,
            new_value=new_value,
            role_name=role_name,
            risk_level=risk_level,
            is_wildcard=is_wildcard,
            timestamp=datetime.now().isoformat()
        )

    def _assess_permission_risk(self, permission: str, provider: str) -> RiskCategory:
        """Assess risk level of a permission."""
        high_risk = self.HIGH_RISK_PERMISSIONS.get(provider, set())
        
        if permission in high_risk:
            return RiskCategory.CRITICAL
        
        if permission.endswith(":*") or permission == "*":
            return RiskCategory.HIGH
        
        if "iam" in permission.lower() or "admin" in permission.lower():
            return RiskCategory.HIGH
        
        if "write" in permission.lower() or "delete" in permission.lower():
            return RiskCategory.MEDIUM
        
        if "read" in permission.lower() or "get" in permission.lower():
            return RiskCategory.LOW
        
        return RiskCategory.MINIMAL

    def _generate_recommendations(self, report: DriftReport) -> None:
        """Generate recommendations based on drift analysis."""
        recommendations = []
        
        if report.high_risk_additions > 0:
            recommendations.append(
                f"🔴 CRITICAL: Review {report.high_risk_additions} high-risk permission additions "
                "and justify business necessity"
            )
        
        if report.wildcard_additions > 0:
            recommendations.append(
                f"🟠 HIGH: Replace {report.wildcard_additions} wildcard permissions with "
                "specific, scoped permissions"
            )
        
        if report.permission_creep_count > 10:
            recommendations.append(
                "🟡 MEDIUM: Significant permission creep detected - perform least-privilege audit"
            )
        
        if report.total_permissions_removed > 0:
            recommendations.append(
                f"✅ {report.total_permissions_removed} permissions removed - "
                "verify removal didn't break functionality"
            )
        
        if report.wildcard_removals > 0:
            recommendations.append(
                f"✅ GOOD: {report.wildcard_removals} wildcard permissions removed"
            )
        
        if not recommendations:
            recommendations.append(
                "✅ No drift detected - policies remain aligned with baseline"
            )
        
        report.recommendations = recommendations

    def detect_permission_creep(self, old_snapshot: PolicySnapshot,
                               new_snapshot: PolicySnapshot) -> Dict[str, List[str]]:
        """
        Detect permission creep (new permissions added to roles).
        
        Returns:
            Dict mapping role names to newly added permissions
        """
        creep = defaultdict(list)
        
        for role_name in new_snapshot.permissions_by_role:
            old_perms = old_snapshot.permissions_by_role.get(role_name, set())
            new_perms = new_snapshot.permissions_by_role.get(role_name, set())
            
            added_perms = new_perms - old_perms
            if added_perms:
                creep[role_name] = sorted(list(added_perms))
        
        return dict(creep)

    def detect_high_risk_changes(self, report: DriftReport) -> List[PermissionChange]:
        """Get only high-risk permission changes from report."""
        return [
            change for change in report.changes
            if change.risk_level in [RiskCategory.CRITICAL, RiskCategory.HIGH]
        ]

    def detect_wildcard_changes(self, report: DriftReport) -> List[PermissionChange]:
        """Get only wildcard permission changes from report."""
        return [change for change in report.changes if change.is_wildcard]

    def export_report_json(self, report: DriftReport, filepath: Path) -> None:
        """Export drift report to JSON file."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)
        logger.info(f"Report exported to {filepath}")

    def import_report_json(self, filepath: Path) -> DriftReport:
        """Import drift report from JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        report = DriftReport.from_dict(data)
        self.reports[report.report_id] = report
        logger.info(f"Report imported from {filepath}")
        return report

    def get_role_permission_history(self, role_name: str) -> Dict[str, Set[str]]:
        """Get historical permission changes for a specific role."""
        history = {}
        for snapshot_id, snapshot in sorted(self.snapshots.items()):
            history[snapshot_id] = snapshot.permissions_by_role.get(role_name, set()).copy()
        return history

    def get_high_risk_permissions_by_role(self, snapshot: PolicySnapshot) -> Dict[str, List[str]]:
        """Get high-risk permissions organized by role."""
        return snapshot.high_risk_permissions

    def get_wildcard_permissions_by_role(self, snapshot: PolicySnapshot) -> Dict[str, List[str]]:
        """Get wildcard permissions organized by role."""
        return snapshot.wildcard_permissions
