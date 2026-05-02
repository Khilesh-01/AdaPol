"""Risk Scoring Engine - Quantifies security risk across permissions and policies"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from collections import defaultdict

from .graph_builder import PermissionGraph, NodeType, EdgeType, SensitivityLevel
from .attack_detector import AttackPathDetector, AttackPath, RiskLevel

logger = logging.getLogger(__name__)


@dataclass
class NodeRiskAssessment:
    """Risk assessment for a single node"""
    node_id: str
    node_name: str
    node_type: str
    risk_score: float  # 0.0 to 100.0
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
    wildcard_permissions: int
    sensitive_services_count: int
    reachable_admin_count: int
    incoming_attack_paths: int
    outgoing_attack_paths: int
    is_external_facing: bool
    reasoning: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "node_id": self.node_id,
            "node_name": self.node_name,
            "node_type": self.node_type,
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level,
            "wildcard_permissions": self.wildcard_permissions,
            "sensitive_services": self.sensitive_services_count,
            "reachable_admin_nodes": self.reachable_admin_count,
            "incoming_attack_paths": self.incoming_attack_paths,
            "outgoing_attack_paths": self.outgoing_attack_paths,
            "is_external_facing": self.is_external_facing,
            "reasoning": self.reasoning,
        }


@dataclass
class PolicyRiskAssessment:
    """Risk assessment for a policy or role"""
    policy_id: str
    policy_name: str
    permission_count: int
    wildcard_count: int
    has_admin_permissions: bool
    risk_score: float
    risk_level: str
    permissions_by_service: Dict[str, int]
    high_risk_permissions: List[str]
    reasoning: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "permission_count": self.permission_count,
            "wildcard_count": self.wildcard_count,
            "has_admin_permissions": self.has_admin_permissions,
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level,
            "permissions_by_service": self.permissions_by_service,
            "high_risk_permissions": self.high_risk_permissions,
            "reasoning": self.reasoning,
        }


@dataclass
class RiskAssessment:
    """Overall system risk assessment"""
    total_nodes: int
    total_edges: int
    total_attack_paths: int
    critical_attack_paths: int
    system_risk_score: float  # 0.0 to 100.0
    system_risk_level: str
    node_risk_scores: List[NodeRiskAssessment] = field(default_factory=list)
    policy_risk_scores: List[PolicyRiskAssessment] = field(default_factory=list)
    top_attack_paths: List[AttackPath] = field(default_factory=list)
    critical_nodes: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "summary": {
                "total_nodes": self.total_nodes,
                "total_edges": self.total_edges,
                "total_attack_paths": self.total_attack_paths,
                "critical_attack_paths": self.critical_attack_paths,
                "system_risk_score": round(self.system_risk_score, 2),
                "system_risk_level": self.system_risk_level,
            },
            "node_risks": [n.to_dict() for n in self.node_risk_scores],
            "policy_risks": [p.to_dict() for p in self.policy_risk_scores],
            "top_attack_paths": [p.to_dict() for p in self.top_attack_paths[:10]],
            "critical_nodes": self.critical_nodes,
            "recommendations": self.recommendations,
        }


class RiskScoringEngine:
    """Calculates risk scores for nodes, policies, and the overall system"""

    def __init__(self, graph: PermissionGraph):
        """Initialize the risk scoring engine"""
        self.graph = graph
        self.attack_detector = AttackPathDetector(graph)

    def assess_system_risk(self) -> RiskAssessment:
        """Perform comprehensive risk assessment of the system"""
        logger.info("Starting comprehensive risk assessment")

        # Detect all attack paths
        attack_paths = self.attack_detector.detect_all_attacks()

        # Assess individual nodes
        node_assessments = self._assess_all_nodes(attack_paths)

        # Assess policies
        policy_assessments = self._assess_all_policies()

        # Calculate system-level risk
        system_risk_score = self._calculate_system_risk(
            node_assessments, attack_paths
        )
        system_risk_level = self._score_to_level(system_risk_score)

        # Get critical nodes
        critical_nodes = self.graph.get_critical_nodes()

        # Generate recommendations
        recommendations = self._generate_recommendations(
            node_assessments, attack_paths, system_risk_score
        )

        assessment = RiskAssessment(
            total_nodes=self.graph.graph.number_of_nodes(),
            total_edges=self.graph.graph.number_of_edges(),
            total_attack_paths=len(attack_paths),
            critical_attack_paths=sum(
                1
                for p in attack_paths
                if p.risk_level == RiskLevel.CRITICAL
            ),
            system_risk_score=system_risk_score,
            system_risk_level=system_risk_level,
            node_risk_scores=node_assessments,
            policy_risk_scores=policy_assessments,
            top_attack_paths=sorted(
                attack_paths, key=lambda p: p.risk_score, reverse=True
            )[:10],
            critical_nodes=critical_nodes,
            recommendations=recommendations,
        )

        logger.info(
            f"Risk assessment complete. System risk: {system_risk_level} ({system_risk_score:.1f})"
        )
        return assessment

    def _assess_all_nodes(
        self, attack_paths: List[AttackPath]
    ) -> List[NodeRiskAssessment]:
        """Assess risk for all nodes in the graph"""
        assessments = []

        for node_id, node in self.graph.nodes_by_id.items():
            # Count wildcards in outgoing edges
            wildcard_count = sum(
                1
                for _, edge_data in self.graph.get_outgoing_edges(node_id)
                if edge_data.get("has_wildcards", False)
            )

            # Count sensitive services
            sensitive_services_count = len(node.sensitive_services)

            # Find reachable admin nodes
            reachable = self.graph.find_reachable_nodes(node_id, max_depth=5)
            admin_count = sum(
                1
                for r in reachable
                if self.graph.nodes_by_id[r].node_type == NodeType.ADMIN
            )

            # Count attack paths involving this node
            paths_involving_node = [p for p in attack_paths if node_id in p.nodes]
            incoming_paths = sum(1 for p in paths_involving_node if p.nodes[0] != node_id)
            outgoing_paths = sum(1 for p in paths_involving_node if p.nodes[0] == node_id)

            # Calculate risk score
            risk_score = self._calculate_node_risk(
                node,
                wildcard_count,
                sensitive_services_count,
                admin_count,
                len(paths_involving_node),
            )

            # Build reasoning
            reasoning = []
            if wildcard_count > 0:
                reasoning.append(f"Has {wildcard_count} wildcard permissions")
            if sensitive_services_count > 0:
                reasoning.append(f"Accesses {sensitive_services_count} sensitive services")
            if admin_count > 0:
                reasoning.append(f"Can reach {admin_count} admin nodes")
            if node.is_external_facing:
                reasoning.append("Externally facing resource")

            assessment = NodeRiskAssessment(
                node_id=node_id,
                node_name=node.name,
                node_type=node.node_type.value,
                risk_score=risk_score,
                risk_level=self._score_to_level(risk_score),
                wildcard_permissions=wildcard_count,
                sensitive_services_count=sensitive_services_count,
                reachable_admin_count=admin_count,
                incoming_attack_paths=incoming_paths,
                outgoing_attack_paths=outgoing_paths,
                is_external_facing=node.is_external_facing,
                reasoning=reasoning,
            )
            assessments.append(assessment)

        return sorted(assessments, key=lambda x: x.risk_score, reverse=True)

    def _assess_all_policies(self) -> List[PolicyRiskAssessment]:
        """Assess risk for all policies (IAM roles, service accounts)"""
        assessments = []

        # Find all roles
        roles = [
            node_id
            for node_id in self.graph.nodes_by_id
            if self.graph.nodes_by_id[node_id].node_type == NodeType.ROLE
        ]

        for role_id in roles:
            role = self.graph.nodes_by_id[role_id]
            outgoing_edges = self.graph.get_outgoing_edges(role_id)

            # Aggregate permissions
            all_permissions: Set[str] = set()
            wildcard_count = 0
            permissions_by_service: Dict[str, int] = defaultdict(int)

            for target, edge_data in outgoing_edges:
                perms = edge_data.get("permissions", set())
                all_permissions.update(perms)

                if edge_data.get("has_wildcards", False):
                    wildcard_count += 1

                # Categorize by service
                target_node = self.graph.get_node(target)
                if target_node and target_node.sensitive_services:
                    for service in target_node.sensitive_services:
                        permissions_by_service[service] += len(perms)

            # Identify high-risk permissions
            high_risk_permissions = [
                p
                for p in all_permissions
                if "*" in p
                or any(
                    keyword in p.lower()
                    for keyword in ["admin", "root", "iam", "sts", "kms"]
                )
            ]

            has_admin = any("*" in p or "admin" in p.lower() for p in all_permissions)

            # Calculate policy risk
            risk_score = self._calculate_policy_risk(
                len(all_permissions),
                wildcard_count,
                has_admin,
                len(high_risk_permissions),
            )

            reasoning = [
                f"Total permissions: {len(all_permissions)}",
                f"Wildcard permissions: {wildcard_count}",
            ]
            if high_risk_permissions:
                reasoning.append(f"High-risk permissions: {len(high_risk_permissions)}")
            if has_admin:
                reasoning.append("Has admin/root permissions")

            assessment = PolicyRiskAssessment(
                policy_id=role_id,
                policy_name=role.name,
                permission_count=len(all_permissions),
                wildcard_count=wildcard_count,
                has_admin_permissions=has_admin,
                risk_score=risk_score,
                risk_level=self._score_to_level(risk_score),
                permissions_by_service=dict(permissions_by_service),
                high_risk_permissions=high_risk_permissions,
                reasoning=reasoning,
            )
            assessments.append(assessment)

        return sorted(assessments, key=lambda x: x.risk_score, reverse=True)

    def _calculate_node_risk(
        self,
        node,
        wildcard_count: int,
        sensitive_services_count: int,
        admin_reachable_count: int,
        attack_path_count: int,
    ) -> float:
        """Calculate risk score for a single node"""
        risk = 10.0  # Base risk

        # Add risk for node type
        if node.node_type == NodeType.FUNCTION:
            risk += 20.0
        elif node.node_type == NodeType.ROLE:
            risk += 30.0
        elif node.node_type == NodeType.ADMIN:
            risk += 50.0

        # Add risk for wildcards
        risk += wildcard_count * 15.0

        # Add risk for sensitive services
        risk += sensitive_services_count * 10.0

        # Add risk for reachable admin nodes
        risk += admin_reachable_count * 25.0

        # Add risk for attack paths
        risk += min(attack_path_count * 5.0, 20.0)

        # Bonus for external exposure
        if node.is_external_facing:
            risk += 15.0

        return min(100.0, risk)

    def _calculate_policy_risk(
        self,
        permission_count: int,
        wildcard_count: int,
        has_admin: bool,
        high_risk_permission_count: int,
    ) -> float:
        """Calculate risk score for a policy"""
        risk = 5.0  # Base risk

        # Risk scales with permission count (but sublinearly)
        import math
        risk += math.log10(max(1, permission_count)) * 10.0

        # Significant risk from wildcards
        risk += wildcard_count * 20.0

        # Major risk from admin permissions
        if has_admin:
            risk += 40.0

        # Risk from high-risk permissions
        risk += high_risk_permission_count * 8.0

        return min(100.0, risk)

    def _calculate_system_risk(
        self,
        node_assessments: List[NodeRiskAssessment],
        attack_paths: List[AttackPath],
    ) -> float:
        """Calculate overall system risk"""
        if not node_assessments:
            return 0.0

        # Average node risk
        avg_node_risk = sum(n.risk_score for n in node_assessments) / len(
            node_assessments
        )

        # Weight critical attack paths heavily
        critical_path_count = sum(
            1 for p in attack_paths if p.risk_level == RiskLevel.CRITICAL
        )
        path_risk = min(50.0, critical_path_count * 5.0)

        # High connectivity increases risk
        max_degree = max(
            (
                self.graph.graph.in_degree(node_id) +
                self.graph.graph.out_degree(node_id)
            )
            for node_id in self.graph.graph.nodes()
        )
        connectivity_risk = min(20.0, (max_degree / 10.0) * 20.0)

        # Weighted average
        system_risk = (avg_node_risk * 0.4) + (path_risk * 0.35) + (
            connectivity_risk * 0.25
        )

        return min(100.0, system_risk)

    def _score_to_level(self, score: float) -> str:
        """Convert score to risk level"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "MINIMAL"

    def _generate_recommendations(
        self,
        node_assessments: List[NodeRiskAssessment],
        attack_paths: List[AttackPath],
        system_risk_score: float,
    ) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        # System-level recommendations
        if system_risk_score >= 80:
            recommendations.append(
                "CRITICAL: System has significant privilege escalation risks. Implement immediate mitigations."
            )
        elif system_risk_score >= 60:
            recommendations.append(
                "HIGH: System has multiple attack paths. Prioritize least-privilege enforcement."
            )

        # Node-level recommendations
        critical_nodes = [n for n in node_assessments if n.risk_score >= 80]
        if critical_nodes:
            recommendations.append(
                f"Review and restrict permissions for {len(critical_nodes)} critical nodes: "
                + ", ".join([n.node_name for n in critical_nodes[:3]])
            )

        # Wildcard recommendations
        wildcard_nodes = [n for n in node_assessments if n.wildcard_permissions > 0]
        if wildcard_nodes:
            recommendations.append(
                f"Eliminate {len(wildcard_nodes)} instances of wildcard permissions. "
                "Replace with specific, minimal permissions."
            )

        # Attack path recommendations
        escalation_paths = [
            p
            for p in attack_paths
            if p.path_type.value == "privilege_escalation"
        ]
        if escalation_paths:
            recommendations.append(
                f"Found {len(escalation_paths)} privilege escalation paths. "
                "Implement role boundaries and constrain role assumption."
            )

        # External exposure recommendations
        external_paths = [
            p for p in attack_paths if p.path_type.value == "external_exposure"
        ]
        if external_paths:
            recommendations.append(
                "Review network exposure of resources. Consider limiting external access or adding API authentication."
            )

        return recommendations

    # Alias for compatibility
    RiskLevel = RiskLevel
