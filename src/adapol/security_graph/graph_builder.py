"""Graph Builder - Constructs permission graphs for attack path detection"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Optional, Tuple, Any
import networkx as nx

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of nodes in the permission graph"""
    FUNCTION = "function"  # Lambda, Azure Function, Cloud Function
    ROLE = "role"  # IAM Role, Service Account
    RESOURCE = "resource"  # S3 bucket, DB, storage account
    ADMIN = "admin"  # Admin/Root principal


class EdgeType(Enum):
    """Types of edges in the permission graph"""
    CAN_ACCESS = "can_access"  # Function/Role can access resource
    CAN_ASSUME_ROLE = "can_assume_role"  # Can assume another role
    CAN_INVOKE = "can_invoke"  # Can invoke another function
    CAN_MODIFY = "can_modify"  # Can modify resource or role
    CAN_DELETE = "can_delete"  # Can delete resource
    CAN_CREATE = "can_create"  # Can create resource
    TRUSTS = "trusts"  # Role trusts another entity


class SensitivityLevel(Enum):
    """Sensitivity levels for resources and services"""
    CRITICAL = 5  # IAM, KMS, root access
    HIGH = 4  # Compute, networking, databases
    MEDIUM = 3  # Storage, logging
    LOW = 2  # Non-sensitive services
    MINIMAL = 1  # Logging, monitoring only


@dataclass
class GraphNode:
    """Represents a node in the permission graph"""
    node_id: str
    name: str
    node_type: NodeType
    cloud_provider: str  # 'aws', 'azure', 'gcp'
    principal_arn: Optional[str] = None  # IAM ARN or service account path
    resource_arn: Optional[str] = None  # Resource ARN
    sensitive_services: Set[str] = field(default_factory=set)
    has_wildcards: bool = False
    is_external_facing: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash(self.node_id)

    def __eq__(self, other):
        if not isinstance(other, GraphNode):
            return False
        return self.node_id == other.node_id


@dataclass
class PermissionEdge:
    """Represents an edge with detailed permission information"""
    source: str
    target: str
    edge_type: EdgeType
    permissions: Set[str] = field(default_factory=set)
    has_wildcards: bool = False
    confidence_score: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class PermissionGraph:
    """Builds and manages a directed graph of cloud permissions"""

    def __init__(self):
        """Initialize an empty permission graph"""
        self.graph = nx.DiGraph()
        self.nodes_by_id: Dict[str, GraphNode] = {}
        self.sensitive_services_map: Dict[str, SensitivityLevel] = {
            # AWS services
            "iam": SensitivityLevel.CRITICAL,
            "sts": SensitivityLevel.CRITICAL,
            "kms": SensitivityLevel.CRITICAL,
            "lambda": SensitivityLevel.HIGH,
            "ec2": SensitivityLevel.HIGH,
            "rds": SensitivityLevel.HIGH,
            "s3": SensitivityLevel.MEDIUM,
            "dynamodb": SensitivityLevel.MEDIUM,
            "cloudwatch": SensitivityLevel.LOW,
            # Azure services
            "authorization": SensitivityLevel.CRITICAL,
            "keyvault": SensitivityLevel.CRITICAL,
            "compute": SensitivityLevel.HIGH,
            "sql": SensitivityLevel.HIGH,
            "storage": SensitivityLevel.MEDIUM,
            "cosmosdb": SensitivityLevel.MEDIUM,
            # GCP services
            "iam": SensitivityLevel.CRITICAL,
            "kms": SensitivityLevel.CRITICAL,
            "compute": SensitivityLevel.HIGH,
            "cloudsql": SensitivityLevel.HIGH,
            "storage": SensitivityLevel.MEDIUM,
            "firestore": SensitivityLevel.MEDIUM,
        }
        logger.info("Permission graph initialized")

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph"""
        self.nodes_by_id[node.node_id] = node
        self.graph.add_node(
            node.node_id,
            type=node.node_type,
            name=node.name,
            cloud_provider=node.cloud_provider,
            principal_arn=node.principal_arn,
            resource_arn=node.resource_arn,
            has_wildcards=node.has_wildcards,
            is_external_facing=node.is_external_facing,
            sensitive_services=node.sensitive_services,
            metadata=node.metadata,
        )
        logger.debug(f"Added node: {node.node_id} ({node.node_type.value})")

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        permissions: Optional[Set[str]] = None,
        has_wildcards: bool = False,
        confidence_score: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add an edge to the graph with permission details"""
        if permissions is None:
            permissions = set()
        if metadata is None:
            metadata = {}

        edge_data = {
            "edge_type": edge_type,
            "permissions": permissions,
            "has_wildcards": has_wildcards,
            "confidence_score": confidence_score,
            "metadata": metadata,
        }

        self.graph.add_edge(source_id, target_id, **edge_data)
        logger.debug(
            f"Added edge: {source_id} --[{edge_type.value}]--> {target_id} "
            f"(permissions: {len(permissions)}, wildcards: {has_wildcards})"
        )

    def remove_node(self, node_id: str) -> None:
        """Remove a node from the graph"""
        if node_id in self.nodes_by_id:
            del self.nodes_by_id[node_id]
        if node_id in self.graph.nodes:
            self.graph.remove_node(node_id)
            logger.debug(f"Removed node: {node_id}")

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Retrieve a node by ID"""
        return self.nodes_by_id.get(node_id)

    def get_incoming_edges(self, node_id: str) -> List[Tuple[str, Dict]]:
        """Get all incoming edges to a node"""
        if node_id not in self.graph:
            return []
        return [(src, self.graph.edges[src, node_id]) for src in self.graph.predecessors(node_id)]

    def get_outgoing_edges(self, node_id: str) -> List[Tuple[str, Dict]]:
        """Get all outgoing edges from a node"""
        if node_id not in self.graph:
            return []
        return [(tgt, self.graph.edges[node_id, tgt]) for tgt in self.graph.successors(node_id)]

    def find_all_paths(
        self, source: str, target: str, max_length: int = 10
    ) -> List[List[str]]:
        """Find all paths between two nodes (limited to avoid explosion)"""
        try:
            if source not in self.graph or target not in self.graph:
                return []
            # Use simple path finding with length limit
            paths = []
            for path in nx.all_simple_paths(
                self.graph, source, target, cutoff=max_length
            ):
                paths.append(path)
                if len(paths) > 100:  # Limit number of paths returned
                    break
            return paths
        except nx.NetworkXNoPath:
            return []
        except nx.NodeNotFound:
            return []

    def find_reachable_nodes(self, source: str, max_depth: int = 5) -> Set[str]:
        """Find all nodes reachable from a source within max_depth hops"""
        if source not in self.graph:
            return set()

        reachable = set()
        visited = set()
        queue = [(source, 0)]

        while queue:
            node, depth = queue.pop(0)
            if node in visited or depth > max_depth:
                continue

            visited.add(node)
            reachable.add(node)

            for successor in self.graph.successors(node):
                if successor not in visited:
                    queue.append((successor, depth + 1))

        return reachable

    def get_critical_nodes(self) -> List[str]:
        """Identify critical nodes (high connectivity, admin access, etc.)"""
        critical = []
        for node_id, node in self.nodes_by_id.items():
            in_degree = self.graph.in_degree(node_id)
            out_degree = self.graph.out_degree(node_id)
            total_degree = in_degree + out_degree

            # Critical if: admin node, high degree, or many wildcards
            has_wildcards = any(
                edge_data.get("has_wildcards", False)
                for _, edge_data in self.graph.out_edges(node_id, data=True)
            )

            if node.node_type == NodeType.ADMIN or total_degree > 5 or has_wildcards:
                critical.append(node_id)

        return critical

    def get_service_sensitivity(self, service_name: str) -> SensitivityLevel:
        """Get sensitivity level for a service"""
        service_lower = service_name.lower()
        return self.sensitive_services_map.get(
            service_lower, SensitivityLevel.MEDIUM
        )

    def get_graph_stats(self) -> Dict[str, Any]:
        """Get statistics about the graph"""
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_types": {
                NodeType.FUNCTION.value: sum(
                    1
                    for n in self.graph.nodes(data=True)
                    if n[1].get("type") == NodeType.FUNCTION
                ),
                NodeType.ROLE.value: sum(
                    1
                    for n in self.graph.nodes(data=True)
                    if n[1].get("type") == NodeType.ROLE
                ),
                NodeType.RESOURCE.value: sum(
                    1
                    for n in self.graph.nodes(data=True)
                    if n[1].get("type") == NodeType.RESOURCE
                ),
            },
            "average_degree": (
                2 * self.graph.number_of_edges() / self.graph.number_of_nodes()
                if self.graph.number_of_nodes() > 0
                else 0
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Export graph as dictionary for serialization"""
        return {
            "nodes": [
                {
                    "id": node_id,
                    "name": node.name,
                    "type": node.node_type.value,
                    "cloud_provider": node.cloud_provider,
                    "principal_arn": node.principal_arn,
                    "has_wildcards": node.has_wildcards,
                    "is_external_facing": node.is_external_facing,
                }
                for node_id, node in self.nodes_by_id.items()
            ],
            "edges": [
                {
                    "source": src,
                    "target": tgt,
                    "type": edge_data.get("edge_type").value,
                    "permissions": list(edge_data.get("permissions", [])),
                    "has_wildcards": edge_data.get("has_wildcards", False),
                }
                for src, tgt, edge_data in self.graph.edges(data=True)
            ],
        }
