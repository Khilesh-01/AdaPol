# Security Graph Module - Quick Reference Guide

## Installation & Setup

### Add to requirements.txt

```
networkx>=3.0
```

### Import Modules

```python
from adapol.security_graph import (
    # Graph components
    PermissionGraph,
    GraphNode,
    NodeType,
    EdgeType,
    SensitivityLevel,
    
    # Attack detection
    AttackPathDetector,
    AttackPath,
    AttackPathType,
    RiskLevel,
    
    # Risk scoring
    RiskScoringEngine,
    RiskAssessment,
    NodeRiskAssessment,
    PolicyRiskAssessment,
)
```

---

## 1. Building Permission Graphs

### Create Graph

```python
graph = PermissionGraph()
```

### Add Nodes

```python
# Function node
func = GraphNode(
    node_id="func_1",
    name="my_function",
    node_type=NodeType.FUNCTION,
    cloud_provider="aws",
    principal_arn="arn:aws:iam::123456789012:role/my-role"
)
graph.add_node(func)

# Role node
role = GraphNode(
    node_id="role_1",
    name="my_role",
    node_type=NodeType.ROLE,
    cloud_provider="aws"
)
graph.add_node(role)

# Resource node with sensitivity
resource = GraphNode(
    node_id="res_1",
    name="my_database",
    node_type=NodeType.RESOURCE,
    cloud_provider="aws",
    resource_arn="arn:aws:rds:us-east-1:123456789012:db:prod",
    sensitive_services={"rds", "iam"},
    is_external_facing=False
)
graph.add_node(resource)

# Admin node
admin = GraphNode(
    node_id="admin_1",
    name="admin",
    node_type=NodeType.ADMIN,
    cloud_provider="aws"
)
graph.add_node(admin)
```

### Add Edges

```python
# Basic edge
graph.add_edge(
    "func_1",
    "role_1",
    EdgeType.CAN_ASSUME_ROLE,
    permissions={"sts:AssumeRole"}
)

# Edge with wildcards and metadata
graph.add_edge(
    "role_1",
    "res_1",
    EdgeType.CAN_ACCESS,
    permissions={"rds:*", "rds:DescribeDBInstances"},
    has_wildcards=True,
    confidence_score=0.95,
    metadata={"source": "cloudtrail", "frequency": 15}
)
```

### Query Graph

```python
# Get node
node = graph.get_node("func_1")

# Get edges
incoming = graph.get_incoming_edges("res_1")
outgoing = graph.get_outgoing_edges("func_1")

# Find paths
paths = graph.find_all_paths("func_1", "admin_1", max_length=8)

# Find reachable nodes
reachable = graph.find_reachable_nodes("func_1", max_depth=5)

# Get statistics
stats = graph.get_graph_stats()
print(f"Nodes: {stats['total_nodes']}, Edges: {stats['total_edges']}")
```

---

## 2. Attack Path Detection

### Basic Detection

```python
detector = AttackPathDetector(graph)

# Detect all attack types
all_paths = detector.detect_all_attacks()

# Filter by type
escalation = detector.get_attack_paths_by_type(AttackPathType.PRIVILEGE_ESCALATION)
lateral = detector.get_attack_paths_by_type(AttackPathType.LATERAL_MOVEMENT)
wildcard = detector.get_attack_paths_by_type(AttackPathType.WILDCARD_CHAIN)
external = detector.get_attack_paths_by_type(AttackPathType.EXTERNAL_EXPOSURE)
sensitive = detector.get_attack_paths_by_type(AttackPathType.SENSITIVE_SERVICE_ACCESS)

# Get critical paths only
critical = detector.get_critical_paths()

# Find paths involving a node
node_paths = detector.get_paths_involving_node("func_1")
```

### Attack Path Properties

```python
for path in all_paths:
    print(f"ID: {path.path_id}")
    print(f"Type: {path.path_type.value}")
    print(f"Risk Score: {path.risk_score:.1f}")
    print(f"Risk Level: {path.risk_level.name}")
    print(f"Nodes: {path.nodes}")
    print(f"Path Length: {path.path_length}")
    print(f"Wildcard Edges: {path.wildcard_count}")
    print(f"Sensitive Services: {path.sensitive_services_accessed}")
    print(f"Explanation: {path.explanation}")
```

### Serialize Paths

```python
path_dict = path.to_dict()
json_str = json.dumps([p.to_dict() for p in all_paths])
```

---

## 3. Risk Scoring Engine

### Calculate System Risk

```python
engine = RiskScoringEngine(graph)
assessment = engine.assess_system_risk()

# System-level scores
print(f"System Risk: {assessment.system_risk_level}")
print(f"Risk Score: {assessment.system_risk_score:.1f}/100")
print(f"Total Paths: {assessment.total_attack_paths}")
print(f"Critical Paths: {assessment.critical_attack_paths}")
```

### Node Risk Scores

```python
for node_risk in assessment.node_risk_scores:
    print(f"{node_risk.node_name}: {node_risk.risk_score:.1f}")
    print(f"  Type: {node_risk.node_type}")
    print(f"  Level: {node_risk.risk_level}")
    print(f"  Wildcards: {node_risk.wildcard_permissions}")
    print(f"  Sensitive Services: {node_risk.sensitive_services_count}")
    print(f"  Reachable Admin: {node_risk.reachable_admin_count}")
    for reason in node_risk.reasoning:
        print(f"  • {reason}")
```

### Policy Risk Scores

```python
for policy_risk in assessment.policy_risk_scores:
    print(f"{policy_risk.policy_name}: {policy_risk.risk_score:.1f}")
    print(f"  Permissions: {policy_risk.permission_count}")
    print(f"  Wildcards: {policy_risk.wildcard_count}")
    print(f"  Admin Perms: {policy_risk.has_admin_permissions}")
    print(f"  High-Risk: {policy_risk.high_risk_permissions}")
```

### Top Attack Paths

```python
for path in assessment.top_attack_paths[:10]:
    print(f"{path.path_type.value}: {path.risk_score:.1f}")
    print(f"  {path.explanation}")
```

### Get Recommendations

```python
for rec in assessment.recommendations:
    print(f"• {rec}")
```

### Serialize Assessment

```python
assessment_dict = assessment.to_dict()
json_str = json.dumps(assessment_dict, indent=2)
```

---

## 4. Sensitivity Levels

### Available Levels

```python
SensitivityLevel.CRITICAL   # IAM, KMS, STS
SensitivityLevel.HIGH       # Lambda, EC2, RDS, Compute
SensitivityLevel.MEDIUM     # S3, DynamoDB, Storage
SensitivityLevel.LOW        # CloudWatch, Logging
SensitivityLevel.MINIMAL    # Non-sensitive services
```

### Get Service Sensitivity

```python
sensitivity = graph.get_service_sensitivity("iam")
print(sensitivity.name)  # CRITICAL
print(sensitivity.value) # 5
```

---

## 5. Edge Types

### Supported Edge Types

```python
EdgeType.CAN_ACCESS         # Can access resource
EdgeType.CAN_ASSUME_ROLE   # Can assume IAM role
EdgeType.CAN_INVOKE        # Can invoke function
EdgeType.CAN_MODIFY        # Can modify resource
EdgeType.CAN_DELETE        # Can delete resource
EdgeType.CAN_CREATE        # Can create resource
EdgeType.TRUSTS            # Role trusts entity
```

---

## 6. Risk Levels

### Risk Level Scale

```python
RiskLevel.CRITICAL   # >= 80
RiskLevel.HIGH       # >= 60
RiskLevel.MEDIUM     # >= 40
RiskLevel.LOW        # >= 20
RiskLevel.MINIMAL    # < 20
```

---

## 7. CLI Commands

### Detect Attack Paths

```bash
adapol analyze-attack-paths \
  --terraform infrastructure.tf \
  --events events.json \
  --provider aws \
  --format table \
  --output attack_paths.json \
  --max-paths 50
```

### Generate Risk Report

```bash
adapol show-risk-report \
  --terraform infrastructure.tf \
  --events events.json \
  --provider aws \
  --format both \
  --output risk_report.json
```

---

## 8. Performance Tips

### Optimize Large Graphs

```python
# Limit path detection to critical nodes
critical = graph.get_critical_nodes()
for node in critical:
    reachable = graph.find_reachable_nodes(node, max_depth=3)
    # Process specific paths only

# Use smaller max_length and max_depth
paths = graph.find_all_paths("func_1", "admin_1", max_length=6)
```

### Batch Processing

```python
# Process in smaller batches
functions = [n for n in graph.nodes_by_id.values() if n.node_type == NodeType.FUNCTION]

for batch in [functions[i:i+10] for i in range(0, len(functions), 10)]:
    detector = AttackPathDetector(graph)
    # Process batch
```

---

## 9. Common Patterns

### Check for Privilege Escalation Risk

```python
detector = AttackPathDetector(graph)
detector.detect_all_attacks()

escalation_paths = detector.get_attack_paths_by_type(
    AttackPathType.PRIVILEGE_ESCALATION
)

if any(p.risk_level == RiskLevel.CRITICAL for p in escalation_paths):
    print("⚠️  CRITICAL: Privilege escalation risk detected!")
```

### Find External Exposure

```python
external_paths = detector.get_attack_paths_by_type(
    AttackPathType.EXTERNAL_EXPOSURE
)

for path in external_paths:
    print(f"External exposure via: {' → '.join(path.nodes)}")
```

### Audit Wildcard Permissions

```python
wildcard_paths = detector.get_attack_paths_by_type(
    AttackPathType.WILDCARD_CHAIN
)

for path in wildcard_paths:
    print(f"Wildcard chain: {path.wildcard_count} wildcards")
```

### Generate Compliance Report

```python
engine = RiskScoringEngine(graph)
assessment = engine.assess_system_risk()

print(f"Compliance Status: {'PASS' if assessment.system_risk_score < 50 else 'FAIL'}")
print(f"Critical Findings: {assessment.critical_attack_paths}")
print(f"Remediation Steps: {len(assessment.recommendations)}")
```

---

## 10. Troubleshooting

### No Paths Detected

```python
# Check graph has nodes
print(graph.graph.number_of_nodes())

# Check connectivity
reachable = graph.find_reachable_nodes("func_1")
if not reachable:
    print("Function has no outgoing edges")

# Increase max_length
paths = graph.find_all_paths("func_1", "admin_1", max_length=15)
```

### High Memory Usage

```python
# Reduce graph size
graph.remove_node("unused_node")

# Limit path detection
detector = AttackPathDetector(graph)
detector.path_counter = 100  # Max paths

# Use depth limits
reachable = graph.find_reachable_nodes("func_1", max_depth=3)
```

---

## References

- [Graph Builder API](SECURITY_GRAPH.md#graph-builder)
- [Attack Detector API](SECURITY_GRAPH.md#attack-path-detector)
- [Risk Engine API](SECURITY_GRAPH.md#risk-scoring-engine)
- [Example Code](../examples/security_graph_examples.py)
- [Test Suite](../tests/integration/test_security_graph.py)
