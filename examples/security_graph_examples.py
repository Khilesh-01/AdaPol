#!/usr/bin/env python3
"""
Example: Using AdaPol Security Graph Module Programmatically

This script demonstrates how to:
1. Build a permission graph from infrastructure
2. Detect attack paths
3. Calculate risk scores
4. Generate recommendations
"""

import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from adapol.security_graph import (
    PermissionGraph,
    GraphNode,
    NodeType,
    EdgeType,
    SensitivityLevel,
    AttackPathDetector,
    AttackPathType,
    RiskLevel,
    RiskScoringEngine,
)


def example_1_basic_graph():
    """Example 1: Build and inspect a basic permission graph"""
    print("=" * 70)
    print("EXAMPLE 1: Building a Basic Permission Graph")
    print("=" * 70)

    # Create graph
    graph = PermissionGraph()

    # Add nodes
    nodes = [
        GraphNode(
            node_id="func_1",
            name="order_processor",
            node_type=NodeType.FUNCTION,
            cloud_provider="aws",
        ),
        GraphNode(
            node_id="role_1",
            name="order_processor_role",
            node_type=NodeType.ROLE,
            cloud_provider="aws",
        ),
        GraphNode(
            node_id="res_1",
            name="orders_database",
            node_type=NodeType.RESOURCE,
            cloud_provider="aws",
            sensitive_services={"dynamodb"},
        ),
    ]

    for node in nodes:
        graph.add_node(node)

    # Add edges
    graph.add_edge(
        "func_1",
        "role_1",
        EdgeType.CAN_ASSUME_ROLE,
        permissions={"sts:AssumeRole"},
    )

    graph.add_edge(
        "role_1",
        "res_1",
        EdgeType.CAN_ACCESS,
        permissions={"dynamodb:GetItem", "dynamodb:Query"},
    )

    # Get statistics
    stats = graph.get_graph_stats()
    print(f"\nGraph Statistics:")
    print(f"  Total nodes: {stats['total_nodes']}")
    print(f"  Total edges: {stats['total_edges']}")
    print(f"  Functions: {stats['node_types']['function']}")
    print(f"  Roles: {stats['node_types']['role']}")
    print(f"  Resources: {stats['node_types']['resource']}")

    # Get node details
    print(f"\nNode Details:")
    for node_id, node in graph.nodes_by_id.items():
        incoming = graph.get_incoming_edges(node_id)
        outgoing = graph.get_outgoing_edges(node_id)
        print(
            f"  {node.name} ({node.node_type.value}): {len(incoming)} in, {len(outgoing)} out"
        )


def example_2_privilege_escalation():
    """Example 2: Detect privilege escalation paths"""
    print("\n" + "=" * 70)
    print("EXAMPLE 2: Detecting Privilege Escalation")
    print("=" * 70)

    # Create graph with escalation path
    graph = PermissionGraph()

    # Nodes: Function → Role → Admin
    nodes = [
        GraphNode(
            node_id="func_untrusted",
            name="untrusted_function",
            node_type=NodeType.FUNCTION,
            cloud_provider="aws",
        ),
        GraphNode(
            node_id="role_dev",
            name="developer_role",
            node_type=NodeType.ROLE,
            cloud_provider="aws",
        ),
        GraphNode(
            node_id="role_admin",
            name="admin_role",
            node_type=NodeType.ADMIN,
            cloud_provider="aws",
        ),
    ]

    for node in nodes:
        graph.add_node(node)

    # Edges with escalation path
    graph.add_edge(
        "func_untrusted",
        "role_dev",
        EdgeType.CAN_ASSUME_ROLE,
        permissions={"sts:AssumeRole"},
    )

    graph.add_edge(
        "role_dev",
        "role_admin",
        EdgeType.CAN_ASSUME_ROLE,
        permissions={"sts:AssumeRole"},
        has_wildcards=True,  # Wildcard escalation
    )

    # Detect attacks
    detector = AttackPathDetector(graph)
    all_paths = detector.detect_all_attacks()

    print(f"\nTotal attack paths detected: {len(all_paths)}")

    # Filter for privilege escalation
    escalation_paths = detector.get_attack_paths_by_type(
        AttackPathType.PRIVILEGE_ESCALATION
    )

    print(f"Privilege escalation paths: {len(escalation_paths)}")

    for path in escalation_paths:
        print(f"\n  Path ID: {path.path_id}")
        print(f"  Risk Score: {path.risk_score:.1f}")
        print(f"  Risk Level: {path.risk_level.name}")
        print(f"  Nodes: {' → '.join(path.nodes)}")
        print(f"  Explanation: {path.explanation}")
        print(f"  Wildcard edges: {path.wildcard_count}")


def example_3_lateral_movement():
    """Example 3: Detect lateral movement between functions"""
    print("\n" + "=" * 70)
    print("EXAMPLE 3: Detecting Lateral Movement")
    print("=" * 70)

    # Create graph with lateral movement
    graph = PermissionGraph()

    # Two functions sharing a resource
    nodes = [
        GraphNode(
            node_id="func_1",
            name="payment_processor",
            node_type=NodeType.FUNCTION,
            cloud_provider="aws",
        ),
        GraphNode(
            node_id="func_2",
            name="notification_handler",
            node_type=NodeType.FUNCTION,
            cloud_provider="aws",
        ),
        GraphNode(
            node_id="res_queue",
            name="sqs_queue",
            node_type=NodeType.RESOURCE,
            cloud_provider="aws",
            sensitive_services={"sqs"},
        ),
    ]

    for node in nodes:
        graph.add_node(node)

    # Both functions access the same resource
    graph.add_edge(
        "func_1", "res_queue", EdgeType.CAN_ACCESS, permissions={"sqs:SendMessage"}
    )

    graph.add_edge(
        "res_queue",
        "func_2",
        EdgeType.CAN_INVOKE,
        permissions={"lambda:InvokeFunction"},
    )

    # Detect attacks
    detector = AttackPathDetector(graph)
    all_paths = detector.detect_all_attacks()

    lateral_paths = detector.get_attack_paths_by_type(AttackPathType.LATERAL_MOVEMENT)

    print(f"\nLateral movement paths detected: {len(lateral_paths)}")

    for path in lateral_paths[:3]:  # Show first 3
        print(f"\n  Path: {' → '.join(path.nodes)}")
        print(f"  Risk Score: {path.risk_score:.1f}")
        print(f"  Explanation: {path.explanation}")


def example_4_risk_scoring():
    """Example 4: Calculate risk scores for nodes and policies"""
    print("\n" + "=" * 70)
    print("EXAMPLE 4: Risk Scoring Engine")
    print("=" * 70)

    # Create complex graph
    graph = PermissionGraph()

    # Create diverse nodes
    nodes = [
        GraphNode(
            node_id="func_1",
            name="api_handler",
            node_type=NodeType.FUNCTION,
            cloud_provider="aws",
            is_external_facing=True,  # High risk
        ),
        GraphNode(
            node_id="role_1",
            name="api_handler_role",
            node_type=NodeType.ROLE,
            cloud_provider="aws",
        ),
        GraphNode(
            node_id="res_1",
            name="user_database",
            node_type=NodeType.RESOURCE,
            cloud_provider="aws",
            sensitive_services={"rds", "iam"},
        ),
        GraphNode(
            node_id="role_admin",
            name="admin_role",
            node_type=NodeType.ADMIN,
            cloud_provider="aws",
        ),
    ]

    for node in nodes:
        graph.add_node(node)

    # Add edges
    graph.add_edge(
        "func_1",
        "role_1",
        EdgeType.CAN_ASSUME_ROLE,
        permissions={"sts:AssumeRole"},
    )

    graph.add_edge(
        "role_1",
        "res_1",
        EdgeType.CAN_ACCESS,
        permissions={"rds:*", "iam:GetUser"},  # Wildcard on sensitive service
        has_wildcards=True,
    )

    graph.add_edge("role_1", "role_admin", EdgeType.CAN_ASSUME_ROLE, has_wildcards=True)

    # Calculate risk
    engine = RiskScoringEngine(graph)
    assessment = engine.assess_system_risk()

    print(f"\nSystem Risk Assessment:")
    print(f"  System Risk Score: {assessment.system_risk_score:.1f}/100.0")
    print(f"  System Risk Level: {assessment.system_risk_level}")
    print(f"  Total Attack Paths: {assessment.total_attack_paths}")
    print(f"  Critical Paths: {assessment.critical_attack_paths}")

    print(f"\nTop 5 High-Risk Nodes:")
    for node_risk in assessment.node_risk_scores[:5]:
        print(
            f"  {node_risk.node_name:20s} {node_risk.risk_score:6.1f}/100 [{node_risk.risk_level:8s}]"
        )
        for reason in node_risk.reasoning:
            print(f"    • {reason}")

    print(f"\nRecommendations:")
    for i, rec in enumerate(assessment.recommendations, 1):
        print(f"  {i}. {rec}")


def example_5_real_world_scenario():
    """Example 5: Realistic AWS microservices scenario"""
    print("\n" + "=" * 70)
    print("EXAMPLE 5: Real-World Microservices Architecture")
    print("=" * 70)

    graph = PermissionGraph()

    # Microservices architecture
    services = [
        ("api_gateway", NodeType.FUNCTION, False),
        ("user_service", NodeType.FUNCTION, False),
        ("payment_service", NodeType.FUNCTION, False),
        ("admin_service", NodeType.FUNCTION, True),  # External facing
    ]

    # Roles
    roles = ["api_role", "user_role", "payment_role", "admin_role"]

    # Resources
    resources = [
        ("users_db", "rds"),
        ("payments_db", "rds"),
        ("audit_logs", "s3"),
        ("secrets_vault", "secretsmanager"),
    ]

    # Add function nodes
    for func_name, node_type, is_external in services:
        node = GraphNode(
            node_id=f"func_{func_name}",
            name=func_name,
            node_type=node_type,
            cloud_provider="aws",
            is_external_facing=is_external,
        )
        graph.add_node(node)

    # Add role nodes
    for role_name in roles:
        node = GraphNode(
            node_id=f"role_{role_name}",
            name=role_name,
            node_type=NodeType.ROLE,
            cloud_provider="aws",
        )
        graph.add_node(node)

    # Add resource nodes
    for res_name, service_type in resources:
        sensitivity = (
            SensitivityLevel.CRITICAL
            if service_type == "secretsmanager"
            else SensitivityLevel.HIGH
        )
        node = GraphNode(
            node_id=f"res_{res_name}",
            name=res_name,
            node_type=NodeType.RESOURCE,
            cloud_provider="aws",
            sensitive_services={service_type},
        )
        graph.add_node(node)

    # Connect functions to roles
    graph.add_edge(
        "func_api_gateway",
        "role_api_role",
        EdgeType.CAN_ASSUME_ROLE,
        permissions={"sts:AssumeRole"},
    )

    # Connect roles to resources
    graph.add_edge(
        "role_api_role",
        "res_users_db",
        EdgeType.CAN_ACCESS,
        permissions={"rds:DescribeDBInstances", "rds:DescribeDBClusters"},
    )

    graph.add_edge(
        "role_user_role",
        "res_users_db",
        EdgeType.CAN_ACCESS,
        permissions={"rds:*"},  # Wildcard!
        has_wildcards=True,
    )

    graph.add_edge(
        "role_payment_role",
        "res_payments_db",
        EdgeType.CAN_ACCESS,
        permissions={"rds:DescribeDBInstances"},
    )

    # Admin has broad access
    graph.add_edge(
        "role_admin_role",
        "res_secrets_vault",
        EdgeType.CAN_ACCESS,
        permissions={"secretsmanager:*"},
        has_wildcards=True,
    )

    # Cross-service access (potential lateral movement)
    graph.add_edge(
        "func_api_gateway",
        "func_user_service",
        EdgeType.CAN_INVOKE,
        permissions={"lambda:InvokeFunction"},
    )

    # Run comprehensive analysis
    engine = RiskScoringEngine(graph)
    assessment = engine.assess_system_risk()

    detector = AttackPathDetector(graph)

    # Display results
    print(f"\n📊 Architecture Analysis:")
    print(f"  Services: {len(services)}")
    print(f"  Roles: {len(roles)}")
    print(f"  Resources: {len(resources)}")

    print(f"\n🔴 Risk Assessment:")
    print(f"  System Risk: {assessment.system_risk_level} ({assessment.system_risk_score:.1f}/100)")
    print(f"  Attack Paths: {assessment.total_attack_paths}")
    print(f"  Critical Paths: {assessment.critical_attack_paths}")

    print(f"\n⚠️  Critical Nodes:")
    for node in assessment.critical_nodes:
        node_obj = graph.get_node(node)
        if node_obj:
            print(f"  • {node_obj.name}")

    print(f"\n🎯 Top Risks:")
    for i, path in enumerate(assessment.top_attack_paths[:3], 1):
        print(f"  {i}. [{path.risk_score:.0f}] {path.path_type.value}")
        print(f"     {path.explanation}")

    print(f"\n💡 Recommendations:")
    for i, rec in enumerate(assessment.recommendations[:3], 1):
        print(f"  {i}. {rec}")


if __name__ == "__main__":
    try:
        # Run all examples
        example_1_basic_graph()
        example_2_privilege_escalation()
        example_3_lateral_movement()
        example_4_risk_scoring()
        example_5_real_world_scenario()

        print("\n" + "=" * 70)
        print("✅ All examples completed successfully!")
        print("=" * 70)

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
