"""Attack Path Detection - Identifies privilege escalation and lateral movement paths"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Set, Dict, Optional, Tuple, Any
from collections import deque

from .graph_builder import (
    PermissionGraph,
    NodeType,
    EdgeType,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)


class AttackPathType(Enum):
    """Types of attack paths detected"""
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    WILDCARD_CHAIN = "wildcard_chain"
    SENSITIVE_SERVICE_ACCESS = "sensitive_service_access"
    EXTERNAL_EXPOSURE = "external_exposure"


class RiskLevel(Enum):
    """Risk levels for attack paths"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    MINIMAL = 1


@dataclass
class AttackPath:
    """Represents a detected attack path"""
    path_id: str
    path_type: AttackPathType
    nodes: List[str]  # Ordered list of node IDs in the path
    edges: List[Tuple[str, str]]  # Ordered list of (source, target) edges
    risk_level: RiskLevel
    risk_score: float  # 0.0 to 100.0
    explanation: str
    wildcard_count: int = 0
    sensitive_services_accessed: List[str] = field(default_factory=list)
    path_length: int = field(default=0)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "path_id": self.path_id,
            "type": self.path_type.value,
            "nodes": self.nodes,
            "edges": self.edges,
            "risk_level": self.risk_level.name,
            "risk_score": self.risk_score,
            "explanation": self.explanation,
            "wildcard_count": self.wildcard_count,
            "sensitive_services": self.sensitive_services_accessed,
            "path_length": self.path_length,
        }


class AttackPathDetector:
    """Detects attack paths in permission graphs"""

    def __init__(self, graph: PermissionGraph):
        """Initialize detector with a permission graph"""
        self.graph = graph
        self.detected_paths: List[AttackPath] = []
        self.path_counter = 0

    def detect_all_attacks(
        self,
        include_external_only: bool = False,
    ) -> List[AttackPath]:
        """Run all attack detection algorithms"""
        logger.info("Starting comprehensive attack path detection")
        self.detected_paths = []

        # Run detection algorithms
        self._detect_privilege_escalation()
        self._detect_lateral_movement()
        self._detect_wildcard_chains()
        self._detect_sensitive_service_access()
        self._detect_external_exposure()

        logger.info(f"Detected {len(self.detected_paths)} attack paths")
        return self.detected_paths

    def _detect_privilege_escalation(self) -> None:
        """Detect privilege escalation paths (Function → Role → Admin)"""
        logger.info("Detecting privilege escalation paths")

        # Find all functions
        functions = [
            node_id
            for node_id in self.graph.nodes_by_id
            if self.graph.nodes_by_id[node_id].node_type == NodeType.FUNCTION
        ]

        # Find admin nodes
        admin_nodes = [
            node_id
            for node_id in self.graph.nodes_by_id
            if self.graph.nodes_by_id[node_id].node_type == NodeType.ADMIN
        ]

        if not admin_nodes:
            logger.debug("No admin nodes found")
            return

        # For each function, check if it can reach admin
        for func_id in functions:
            for admin_id in admin_nodes:
                paths = self.graph.find_all_paths(func_id, admin_id, max_length=8)

                for path in paths:
                    # Skip single-hop direct access (less interesting)
                    if len(path) <= 2:
                        continue

                    edges = [(path[i], path[i + 1]) for i in range(len(path) - 1)]
                    wildcard_count = self._count_wildcards_in_path(path)
                    risk_score = self._calculate_privilege_escalation_risk(
                        path, wildcard_count
                    )

                    attack_path = AttackPath(
                        path_id=f"esc_{self.path_counter}",
                        path_type=AttackPathType.PRIVILEGE_ESCALATION,
                        nodes=path,
                        edges=edges,
                        risk_level=self._score_to_risk_level(risk_score),
                        risk_score=risk_score,
                        explanation=self._generate_escalation_explanation(path),
                        wildcard_count=wildcard_count,
                        path_length=len(path),
                        evidence={
                            "start_type": NodeType.FUNCTION.value,
                            "end_type": NodeType.ADMIN.value,
                        },
                    )
                    self.detected_paths.append(attack_path)
                    self.path_counter += 1

                    if self.path_counter > 100:  # Limit total paths
                        break

    def _detect_lateral_movement(self) -> None:
        """Detect lateral movement paths (Function A → Resource → Function B)"""
        logger.info("Detecting lateral movement paths")

        # Find all functions and resources
        functions = [
            node_id
            for node_id in self.graph.nodes_by_id
            if self.graph.nodes_by_id[node_id].node_type == NodeType.FUNCTION
        ]

        resources = [
            node_id
            for node_id in self.graph.nodes_by_id
            if self.graph.nodes_by_id[node_id].node_type == NodeType.RESOURCE
        ]

        # For each pair of functions, check if they can reach each other via resources
        for i, func_a in enumerate(functions):
            for func_b in functions[i + 1 :]:
                paths = self.graph.find_all_paths(func_a, func_b, max_length=6)

                for path in paths:
                    # Must go through at least one resource
                    if not any(
                        n in resources for n in path
                    ):
                        continue

                    edges = [(path[j], path[j + 1]) for j in range(len(path) - 1)]
                    wildcard_count = self._count_wildcards_in_path(path)
                    risk_score = self._calculate_lateral_movement_risk(
                        path, wildcard_count
                    )

                    attack_path = AttackPath(
                        path_id=f"lateral_{self.path_counter}",
                        path_type=AttackPathType.LATERAL_MOVEMENT,
                        nodes=path,
                        edges=edges,
                        risk_level=self._score_to_risk_level(risk_score),
                        risk_score=risk_score,
                        explanation=self._generate_lateral_movement_explanation(path),
                        wildcard_count=wildcard_count,
                        path_length=len(path),
                        evidence={
                            "source_function": func_a,
                            "target_function": func_b,
                        },
                    )
                    self.detected_paths.append(attack_path)
                    self.path_counter += 1

    def _detect_wildcard_chains(self) -> None:
        """Detect high-risk wildcard permission chains"""
        logger.info("Detecting wildcard permission chains")

        for node_id in self.graph.graph.nodes():
            outgoing = self.graph.get_outgoing_edges(node_id)

            wildcard_edges = [
                (target, edge_data)
                for target, edge_data in outgoing
                if edge_data.get("has_wildcards", False)
            ]

            if not wildcard_edges:
                continue

            # For each wildcard edge, find downstream paths
            for target, edge_data in wildcard_edges:
                # Get downstream nodes reachable from target
                reachable = self.graph.find_reachable_nodes(target, max_depth=5)
                reachable.discard(node_id)

                if not reachable:
                    continue

                # Shortest path to most sensitive reachable node
                for downstream in reachable:
                    paths = self.graph.find_all_paths(node_id, downstream, max_length=8)
                    if not paths:
                        continue

                    path = min(paths, key=len)  # Shortest path
                    edges = [(path[j], path[j + 1]) for j in range(len(path) - 1)]

                    # Count total wildcards in chain
                    total_wildcards = sum(
                        1
                        for src, tgt in edges
                        if self.graph.graph.edges[src, tgt].get(
                            "has_wildcards", False
                        )
                    )

                    risk_score = min(
                        100.0, 30.0 + (total_wildcards * 15.0)
                    )  # Base 30 + 15 per wildcard

                    attack_path = AttackPath(
                        path_id=f"wildcard_{self.path_counter}",
                        path_type=AttackPathType.WILDCARD_CHAIN,
                        nodes=path,
                        edges=edges,
                        risk_level=self._score_to_risk_level(risk_score),
                        risk_score=risk_score,
                        explanation=f"Wildcard permission chain with {total_wildcards} wildcard edges leading to sensitive resource",
                        wildcard_count=total_wildcards,
                        path_length=len(path),
                    )
                    self.detected_paths.append(attack_path)
                    self.path_counter += 1

    def _detect_sensitive_service_access(self) -> None:
        """Detect access paths to sensitive services (IAM, KMS, etc.)"""
        logger.info("Detecting sensitive service access paths")

        # Find resources associated with sensitive services
        sensitive_resources = []
        for node_id, node in self.graph.nodes_by_id.items():
            if node.node_type == NodeType.RESOURCE:
                if node.sensitive_services:
                    for service in node.sensitive_services:
                        sensitivity = self.graph.get_service_sensitivity(service)
                        if sensitivity.value >= SensitivityLevel.HIGH.value:
                            sensitive_resources.append((node_id, service, sensitivity))

        # Find functions that can reach sensitive resources
        functions = [
            node_id
            for node_id in self.graph.nodes_by_id
            if self.graph.nodes_by_id[node_id].node_type == NodeType.FUNCTION
        ]

        for func_id in functions:
            for res_id, service, sensitivity in sensitive_resources:
                paths = self.graph.find_all_paths(func_id, res_id, max_length=5)
                if not paths:
                    continue

                path = min(paths, key=len)
                edges = [(path[j], path[j + 1]) for j in range(len(path) - 1)]

                # Risk increases with sensitivity level
                base_risk = sensitivity.value * 15.0
                wildcard_count = self._count_wildcards_in_path(path)
                risk_score = min(100.0, base_risk + (wildcard_count * 10.0))

                attack_path = AttackPath(
                    path_id=f"sensitive_{self.path_counter}",
                    path_type=AttackPathType.SENSITIVE_SERVICE_ACCESS,
                    nodes=path,
                    edges=edges,
                    risk_level=self._score_to_risk_level(risk_score),
                    risk_score=risk_score,
                    explanation=f"Function has access to sensitive service '{service}' ({sensitivity.name} sensitivity)",
                    wildcard_count=wildcard_count,
                    sensitive_services_accessed=[service],
                    path_length=len(path),
                )
                self.detected_paths.append(attack_path)
                self.path_counter += 1

    def _detect_external_exposure(self) -> None:
        """Detect paths involving externally exposed resources"""
        logger.info("Detecting external exposure paths")

        external_resources = [
            node_id
            for node_id in self.graph.nodes_by_id
            if self.graph.nodes_by_id[node_id].is_external_facing
        ]

        if not external_resources:
            return

        # Find functions connected to external resources
        functions = [
            node_id
            for node_id in self.graph.nodes_by_id
            if self.graph.nodes_by_id[node_id].node_type == NodeType.FUNCTION
        ]

        for ext_res in external_resources:
            for func_id in functions:
                paths = self.graph.find_all_paths(func_id, ext_res, max_length=6)
                if not paths:
                    continue

                # Use shortest path
                path = min(paths, key=len)
                edges = [(path[j], path[j + 1]) for j in range(len(path) - 1)]

                risk_score = 60.0  # Base risk for external exposure
                wildcard_count = self._count_wildcards_in_path(path)
                if wildcard_count > 0:
                    risk_score = min(100.0, risk_score + (wildcard_count * 15.0))

                attack_path = AttackPath(
                    path_id=f"external_{self.path_counter}",
                    path_type=AttackPathType.EXTERNAL_EXPOSURE,
                    nodes=path,
                    edges=edges,
                    risk_level=self._score_to_risk_level(risk_score),
                    risk_score=risk_score,
                    explanation="Externally exposed resource accessible from internal function, creating internet-facing attack surface",
                    wildcard_count=wildcard_count,
                    path_length=len(path),
                )
                self.detected_paths.append(attack_path)
                self.path_counter += 1

    def _count_wildcards_in_path(self, path: List[str]) -> int:
        """Count wildcard permissions in a path"""
        count = 0
        for i in range(len(path) - 1):
            src, tgt = path[i], path[i + 1]
            if self.graph.graph.edges[src, tgt].get("has_wildcards", False):
                count += 1
        return count

    def _calculate_privilege_escalation_risk(
        self, path: List[str], wildcard_count: int
    ) -> float:
        """Calculate risk score for privilege escalation path"""
        base_risk = 80.0  # Privilege escalation is high risk
        path_length_penalty = (len(path) - 2) * 2.0  # Shorter paths are riskier
        wildcard_bonus = wildcard_count * 10.0
        return min(100.0, base_risk + wildcard_bonus - path_length_penalty)

    def _calculate_lateral_movement_risk(
        self, path: List[str], wildcard_count: int
    ) -> float:
        """Calculate risk score for lateral movement path"""
        base_risk = 65.0
        path_length_penalty = (len(path) - 2) * 1.5
        wildcard_bonus = wildcard_count * 8.0
        return min(100.0, base_risk + wildcard_bonus - path_length_penalty)

    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert numerical risk score to RiskLevel"""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    def _generate_escalation_explanation(self, path: List[str]) -> str:
        """Generate human-readable explanation for privilege escalation"""
        node_names = []
        for node_id in path:
            node = self.graph.get_node(node_id)
            if node:
                node_names.append(node.name)
            else:
                node_names.append(node_id)

        return f"Privilege escalation chain: {' → '.join(node_names)}"

    def _generate_lateral_movement_explanation(self, path: List[str]) -> str:
        """Generate human-readable explanation for lateral movement"""
        node_names = []
        for node_id in path:
            node = self.graph.get_node(node_id)
            if node:
                node_names.append(f"{node.name}({node.node_type.value})")
            else:
                node_names.append(node_id)

        return f"Lateral movement: {' → '.join(node_names)}"

    def get_attack_paths_by_type(
        self, path_type: AttackPathType
    ) -> List[AttackPath]:
        """Get all attack paths of a specific type"""
        return [p for p in self.detected_paths if p.path_type == path_type]

    def get_critical_paths(self) -> List[AttackPath]:
        """Get only CRITICAL risk paths"""
        return [
            p
            for p in self.detected_paths
            if p.risk_level == RiskLevel.CRITICAL
        ]

    def get_paths_involving_node(self, node_id: str) -> List[AttackPath]:
        """Get all attack paths that involve a specific node"""
        return [p for p in self.detected_paths if node_id in p.nodes]
