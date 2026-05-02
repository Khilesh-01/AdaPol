# Security Graph Module - Attack Path Detection & Risk Scoring

## Overview

The **Security Graph Module** extends AdaPol with advanced attack path detection and risk scoring capabilities. It analyzes cloud IAM policies to identify:

1. **Privilege Escalation Paths** - How attackers can escalate from low-privilege to admin access
2. **Lateral Movement** - Cross-function access through shared resources
3. **Wildcard Permission Chains** - High-risk sequences of wildcard permissions
4. **Sensitive Service Access** - Dangerous access to critical services (IAM, KMS, etc.)
5. **External Exposure** - Externally-facing resources with internal access

## Architecture

### Module Structure

```
security_graph/
├── __init__.py                 # Module exports
├── graph_builder.py            # Permission graph construction
├── attack_detector.py          # Attack path detection algorithms
└── risk_engine.py              # Risk scoring and assessment
```

### Key Components

#### 1. Graph Builder (`graph_builder.py`)

Constructs a directed graph representing cloud permissions:

- **Nodes**: Functions, Roles, Resources, Admin principals
- **Edges**: Permission relationships (can_access, can_assume_role, can_invoke, can_modify)
- **Attributes**: Wildcards, sensitivity levels, external exposure

```python
from adapol.security_graph import PermissionGraph, GraphNode, NodeType, EdgeType

# Create graph
graph = PermissionGraph()

# Add nodes
func_node = GraphNode(
    node_id="func_1",
    name="user_processor",
    node_type=NodeType.FUNCTION,
    cloud_provider="aws"
)
graph.add_node(func_node)

# Add edges
graph.add_edge(
    "func_1",
    "role_1",
    EdgeType.CAN_ASSUME_ROLE,
    permissions={"sts:AssumeRole"},
    has_wildcards=False
)
```

#### 2. Attack Path Detector (`attack_detector.py`)

Implements graph traversal algorithms to detect attack paths:

- **Privilege Escalation**: BFS/DFS from functions to admin nodes
- **Lateral Movement**: Path finding between function pairs through resources
- **Wildcard Chains**: Identifies sequences of wildcard permissions
- **Sensitive Service Access**: Tracks paths to critical services
- **External Exposure**: Detects internet-facing resource exposure

```python
from adapol.security_graph import AttackPathDetector

detector = AttackPathDetector(graph)
attack_paths = detector.detect_all_attacks()

for path in attack_paths:
    print(f"Type: {path.path_type.value}")
    print(f"Risk Score: {path.risk_score}")
    print(f"Path: {' → '.join(path.nodes)}")
    print(f"Explanation: {path.explanation}")
```

#### 3. Risk Scoring Engine (`risk_engine.py`)

Calculates risk scores using multiple factors:

**Per-Node Scoring:**
- Node type (Function, Role, Admin)
- Wildcard permissions count
- Sensitive services accessible
- Reachable admin nodes
- Attack paths involving the node

**Per-Policy Scoring:**
- Total permission count
- Wildcard usage
- Admin/root permissions
- High-risk permission types

**System-Level Scoring:**
- Average node risk
- Critical attack path count
- Network connectivity

```python
from adapol.security_graph import RiskScoringEngine

engine = RiskScoringEngine(graph)
assessment = engine.assess_system_risk()

print(f"System Risk Level: {assessment.system_risk_level}")
print(f"System Risk Score: {assessment.system_risk_score:.1f}/100.0")
print(f"Critical Attack Paths: {assessment.critical_attack_paths}")

for node_risk in assessment.node_risk_scores:
    print(f"{node_risk.node_name}: {node_risk.risk_score:.1f} ({node_risk.risk_level})")
```

## CLI Commands

### 1. Detect Attack Paths

```bash
adapol analyze-attack-paths \
  --terraform examples/aws/vulnerable_infrastructure.tf \
  --events examples/aws/vulnerable_events.json \
  --provider aws \
  --format table \
  --output attack_paths.json
```

**Options:**
- `--terraform, -t`: Terraform configuration file (required)
- `--events, -e`: Cloud events JSON file (required)
- `--provider, -p`: Cloud provider (aws|azure|gcp, default: aws)
- `--format, -f`: Output format (json|table|both, default: table)
- `--output, -o`: Output file (default: attack_paths.json)
- `--max-paths, -m`: Maximum paths to report (default: 50)

**Output Example:**
```
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ID            ┃ Type                ┃ Risk ┃ Length ┃ Path              ┃ Explanation           ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ esc_0         │ privilege_escalati… │ 92.0 │ 3      │ user_processor…  │ Privilege escalation… │
│ lateral_1     │ lateral_movement    │ 75.0 │ 3      │ order_processor… │ Lateral movement: …  │
│ wildcard_2    │ wildcard_chain      │ 85.0 │ 2      │ admin_role → s3… │ Wildcard permission… │
└───────────────┴───────────────────────┴──────┴────────┴───────────────────┴───────────────────────┘
```

### 2. Generate Risk Report

```bash
adapol show-risk-report \
  --terraform examples/aws/vulnerable_infrastructure.tf \
  --events examples/aws/vulnerable_events.json \
  --provider aws \
  --format both \
  --output risk_report.json
```

**Output:**
```
╭─────────────────────────────── System Risk Summary ───────────────────────────────╮
│ System Risk Score: 72.5/100.0                                                    │
│ System Risk Level: HIGH                                                           │
│ Total Attack Paths: 8                                                             │
│ Critical Paths: 2                                                                 │
╰────────────────────────────────────────────────────────────────────────────────────╯

┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Node             ┃ Type          ┃ Risk Score ┃ Risk Level ┃ Wildcard ┃ Sensitive… ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ admin_role       │ admin         │ 95.3       │ CRITICAL   │ 1        │ 2           │
│ order_processor… │ function      │ 82.1       │ HIGH       │ 2        │ 3           │
│ user_processor   │ function      │ 65.4       │ HIGH       │ 0        │ 1           │
└──────────────────┴───────────────┴────────────┴────────────┴──────────┴─────────────┘

📋 Recommendations:
  1. CRITICAL: System has significant privilege escalation risks. Implement immediate mitigations.
  2. Review and restrict permissions for 2 critical nodes: admin_role, order_processor_role
  3. Eliminate 2 instances of wildcard permissions. Replace with specific, minimal permissions.
  4. Found 3 privilege escalation paths. Implement role boundaries and constrain role assumption.
```

## Data Models

### Attack Path

```python
@dataclass
class AttackPath:
    path_id: str                        # Unique identifier
    path_type: AttackPathType          # privilege_escalation | lateral_movement | wildcard_chain | ...
    nodes: List[str]                   # Ordered node IDs in path
    edges: List[Tuple[str, str]]       # Ordered edges
    risk_level: RiskLevel              # CRITICAL | HIGH | MEDIUM | LOW | MINIMAL
    risk_score: float                  # 0.0 to 100.0
    explanation: str                   # Human-readable description
    wildcard_count: int                # Number of wildcard edges
    sensitive_services_accessed: List[str]  # Services with high sensitivity
    path_length: int                   # Number of hops
    evidence: Dict[str, Any]           # Additional context
```

### Risk Assessment

```python
@dataclass
class RiskAssessment:
    total_nodes: int
    total_edges: int
    total_attack_paths: int
    critical_attack_paths: int
    system_risk_score: float           # 0.0 to 100.0
    system_risk_level: str             # CRITICAL | HIGH | MEDIUM | LOW | MINIMAL
    node_risk_scores: List[NodeRiskAssessment]
    policy_risk_scores: List[PolicyRiskAssessment]
    top_attack_paths: List[AttackPath]
    critical_nodes: List[str]
    recommendations: List[str]
```

## Integration with Existing Pipeline

The security graph module integrates seamlessly into AdaPol's existing pipeline:

```
Input (Terraform + Events)
    ↓
[Existing] Static IaC Analysis
    ↓
[Existing] Telemetry Collection
    ↓
[NEW] Permission Graph Construction
    ↓
[NEW] Attack Path Detection
    ↓
[NEW] Risk Scoring Engine
    ↓
[Existing] Policy Optimization
    ↓
Output (Policies + Risk Report)
```

## Example Use Cases

### 1. Pre-Deployment Security Review

```bash
# Analyze infrastructure before deployment
adapol analyze-attack-paths \
  --terraform infrastructure.tf \
  --events sample_events.json \
  --provider aws \
  --format json \
  --output pre_deployment_risk.json

# If critical paths detected, remediate before deployment
```

### 2. Continuous Compliance Monitoring

```bash
# Run risk assessment periodically
while true; do
  adapol show-risk-report \
    --terraform current_infrastructure.tf \
    --events collected_events.json \
    --provider aws
  
  sleep 3600  # Run hourly
done
```

### 3. Incident Response

```bash
# When compromise suspected, trace possible attack paths
adapol analyze-attack-paths \
  --terraform infrastructure.tf \
  --events incident_timeline_events.json \
  --provider aws \
  --max-paths 100  # Get all paths for forensics
```

## Testing

Run the comprehensive test suite:

```bash
# Run all security graph tests
pytest tests/integration/test_security_graph.py -v

# Run specific test class
pytest tests/integration/test_security_graph.py::TestAttackPathDetection -v

# Generate coverage report
pytest tests/integration/test_security_graph.py --cov=adapol.security_graph
```

## Sample Data

Included examples demonstrate common vulnerabilities:

- **vulnerable_infrastructure.tf**: Realistic AWS setup with privilege escalation
- **vulnerable_events.json**: Runtime events showing suspicious access patterns

Run demo:

```bash
adapol analyze-attack-paths \
  --terraform examples/aws/vulnerable_infrastructure.tf \
  --events examples/aws/vulnerable_events.json \
  --provider aws \
  --format both
```

## Performance Characteristics

| Graph Size | Avg Detection Time | Memory Usage |
|------------|-------------------|--------------|
| 10 nodes   | < 100ms          | ~ 5MB       |
| 50 nodes   | ~ 500ms          | ~ 15MB      |
| 100 nodes  | ~ 2s             | ~ 30MB      |
| 500 nodes  | ~ 15s            | ~ 100MB     |

*Note: Path limits (100 paths, 10 depth cutoff) prevent exponential explosion*

## Limitations & Future Enhancements

### Current Limitations

1. Simplified Terraform parsing (regex-based, not full AST)
2. Path limit of 100 to prevent memory explosion
3. Depth cutoff of 10 for reachability analysis
4. No temporal analysis of attack paths

### Planned Enhancements

- [ ] Full HCL/Terraform parser integration
- [ ] Time-series attack path correlation
- [ ] ML-based anomaly detection
- [ ] Automatic remediation recommendations
- [ ] Multi-cloud cross-account analysis
- [ ] Integration with SIEM systems

## References

- [NIST Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-207.pdf)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [Lateral Movement Techniques](https://attack.mitre.org/tactics/TA0008/)
