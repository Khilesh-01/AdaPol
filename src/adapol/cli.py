import click
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Optional, List
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.syntax import Syntax

# Import AdaPol system
try:
    from .adapol import AdaPolSystem, SampleDataGenerator
except ImportError:
    # Fallback for direct execution
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from adapol.adapol import AdaPolSystem, SampleDataGenerator

# Import security graph modules
from .security_graph import (
    PermissionGraph,
    GraphNode,
    NodeType,
    EdgeType,
    AttackPathDetector,
    RiskScoringEngine,
)

# Import simulation modules
from .simulation import (
    PolicyDriftDetector,
    PolicySnapshot,
    PermissionSimulator,
    PermissionUsageAnalyzer,
    PermissionUsageEvent,
)

console = Console()

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """AdaPol: Adaptive Multi-Cloud Least-Privilege Policy Generator"""
    pass

@cli.command()
@click.option('--output', '-o', default='adapol_output', help='Output directory')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def demo(output: str, verbose: bool):
    """Run AdaPol demonstration with sample data"""
    console.print(Panel.fit("🚀 AdaPol Demo Mode", style="bold blue"))
    
    async def run_demo():
        adapol = AdaPolSystem()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            # Load sample data
            task1 = progress.add_task("Loading sample data...", total=None)
            adapol.load_sample_data()
            progress.update(task1, completed=True)
            
            # Run analysis
            task2 = progress.add_task("Analyzing policies...", total=None)
            policies = await adapol.run_full_analysis()
            progress.update(task2, completed=True)
            
            # Export results
            task3 = progress.add_task("Exporting results...", total=None)
            adapol.export_policies(output)
            progress.update(task3, completed=True)
        
        # Display results
        _display_results(policies, adapol.generate_report(), verbose)
        
        console.print(f"\n✅ Demo complete! Results saved to [bold green]{output}[/bold green]")
        
        # Offer continuous monitoring
        if click.confirm("\n🔄 Start continuous monitoring?", default=False):
            console.print("🔄 Starting continuous monitoring... (Press Ctrl+C to stop)")
            try:
                await adapol.start_continuous_monitoring()
            except KeyboardInterrupt:
                console.print("\n🛑 Monitoring stopped.")
    
    asyncio.run(run_demo())

@cli.command()
@click.option('--terraform', '-t', type=click.Path(exists=True), help='Terraform configuration file')
@click.option('--events', '-e', type=click.Path(exists=True), help='JSON file with cloud events')
@click.option('--provider', '-p', type=click.Choice(['aws', 'azure', 'gcp']), default='aws', help='Cloud provider')
@click.option('--output', '-o', default='adapol_output', help='Output directory')
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file')
@click.option('--monitor', '-m', is_flag=True, help='Start continuous monitoring')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def analyze(terraform: Optional[str], events: Optional[str], provider: str, 
           output: str, config: Optional[str], monitor: bool, verbose: bool):
    """Analyze infrastructure and generate policies"""
    
    console.print(Panel.fit("🔍 AdaPol Analysis Mode", style="bold green"))
    
    async def run_analysis():
        adapol = AdaPolSystem()
        
        # Load configuration if provided
        if config and os.path.exists(config):
            console.print(f"📋 Loading configuration from {config}")
            # In a full implementation, load YAML config here
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            # Load Terraform
            if terraform:
                task1 = progress.add_task("Parsing Terraform configuration...", total=None)
                with open(terraform, 'r') as f:
                    terraform_content = f.read()
                
                functions = adapol.analyzer.parse_terraform(terraform_content)
                adapol.analyzer.function_manifests = functions
                progress.update(task1, description=f"Found {len(functions)} functions")
                progress.update(task1, completed=True)
            
            # Load events
            if events:
                task2 = progress.add_task("Processing cloud events...", total=None)
                with open(events, 'r') as f:
                    events_data = json.load(f)
                
                if isinstance(events_data, list):
                    count = adapol.collector.collect_events(events_data, provider)
                    progress.update(task2, description=f"Processed {count} events")
                    progress.update(task2, completed=True)
                else:
                    console.print("[red]❌ Events file must contain a JSON array[/red]")
                    return
            
            # Build workflow graph
            if hasattr(adapol.analyzer, 'function_manifests'):
                task3 = progress.add_task("Building workflow graph...", total=None)
                adapol.analyzer.workflow_graph = adapol.analyzer.build_workflow_graph(
                    adapol.analyzer.function_manifests, adapol.collector.events
                )
                progress.update(task3, completed=True)
            
            # Run analysis
            task4 = progress.add_task("Generating policies...", total=None)
            policies = await adapol.run_full_analysis()
            progress.update(task4, completed=True)
            
            if policies:
                # Export results
                task5 = progress.add_task("Exporting results...", total=None)
                adapol.export_policies(output)
                progress.update(task5, completed=True)
                
                # Display results
                _display_results(policies, adapol.generate_report(), verbose)
                
                console.print(f"\n✅ Analysis complete! Results saved to [bold green]{output}[/bold green]")
                
                # Start monitoring if requested
                if monitor:
                    console.print("🔄 Starting continuous monitoring... (Press Ctrl+C to stop)")
                    try:
                        await adapol.start_continuous_monitoring()
                    except KeyboardInterrupt:
                        console.print("\n🛑 Monitoring stopped.")
            else:
                console.print("[red]❌ No policies generated. Check your input data.[/red]")
    
    if not terraform and not events:
        console.print("[yellow]⚠️  No input files specified. Use --terraform and/or --events[/yellow]")
        return
    
    asyncio.run(run_analysis())

@cli.command()
@click.option('--provider', '-p', type=click.Choice(['aws', 'azure', 'gcp']), default='aws')
@click.option('--events', '-e', type=int, default=50, help='Number of events to generate')
@click.option('--output', '-o', default='sample_data', help='Output directory')
def generate_sample(provider: str, events: int, output: str):
    """Generate sample data for testing"""
    
    console.print(Panel.fit("🎲 Sample Data Generator", style="bold magenta"))
    
    Path(output).mkdir(exist_ok=True)
    
    # Generate sample events
    sample_events = SampleDataGenerator.generate_sample_events(events, provider)
    events_file = Path(output) / f"{provider}_events.json"
    with open(events_file, 'w') as f:
        json.dump(sample_events, f, indent=2, default=str)
    
    # Generate sample Terraform
    sample_terraform = SampleDataGenerator.generate_sample_terraform(provider)
    tf_file = Path(output) / f"{provider}_infrastructure.tf"
    with open(tf_file, 'w') as f:
        f.write(sample_terraform)
    
    console.print(f"✅ Generated sample data for [bold]{provider}[/bold]:")
    console.print(f"  • Events: [green]{events_file}[/green] ({events} events)")
    console.print(f"  • Terraform: [green]{tf_file}[/green]")
    console.print(f"\nTo analyze: [bold]adapol analyze -t {tf_file} -e {events_file} -p {provider}[/bold]")

@cli.command()
@click.argument('policy_file', type=click.Path(exists=True))
def validate(policy_file: str):
    """Validate a generated policy file"""
    
    console.print(Panel.fit("✅ Policy Validator", style="bold cyan"))
    
    try:
        with open(policy_file, 'r') as f:
            policy_data = json.load(f)
        
        # Basic validation
        required_fields = ['function_id', 'cloud_provider', 'rules']
        missing_fields = [field for field in required_fields if field not in policy_data]
        
        if missing_fields:
            console.print(f"[red]❌ Missing required fields: {missing_fields}[/red]")
            return
        
        # Validate rules
        rules = policy_data.get('rules', [])
        if not rules:
            console.print("[yellow]⚠️  No policy rules found[/yellow]")
            return
        
        # Display policy summary
        table = Table(title="Policy Validation Results")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Function ID", policy_data['function_id'])
        table.add_row("Cloud Provider", policy_data['cloud_provider'])
        table.add_row("Number of Rules", str(len(rules)))
        table.add_row("Risk Reduction", f"{policy_data.get('risk_reduction', 0):.1f}%")
        
        console.print(table)
        
        # Display rules
        if len(rules) <= 10:  # Only show if reasonable number
            rules_table = Table(title="Policy Rules")
            rules_table.add_column("Action", style="green")
            rules_table.add_column("Resource", style="blue")
            rules_table.add_column("Effect", style="yellow")
            
            for rule in rules:
                rules_table.add_row(
                    rule.get('action', 'N/A'),
                    rule.get('resource', 'N/A')[:60] + ('...' if len(rule.get('resource', '')) > 60 else ''),
                    rule.get('effect', 'Allow')
                )
            
            console.print(rules_table)
        
        console.print("[green]✅ Policy validation passed[/green]")
        
    except json.JSONDecodeError:
        console.print("[red]❌ Invalid JSON format[/red]")
    except Exception as e:
        console.print(f"[red]❌ Validation error: {e}[/red]")

@cli.command()
@click.argument('report_file', type=click.Path(exists=True))
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'summary']), default='summary')
def report(report_file: str, format: str):
    """Display analysis report"""
    
    console.print(Panel.fit("📊 Analysis Report", style="bold yellow"))
    
    try:
        with open(report_file, 'r') as f:
            report_data = json.load(f)
        
        if format == 'json':
            syntax = Syntax(json.dumps(report_data, indent=2), "json", theme="monokai")
            console.print(syntax)
            
        elif format == 'table':
            _display_detailed_report(report_data)
            
        else:  # summary
            _display_summary_report(report_data)
            
    except json.JSONDecodeError:
        console.print("[red]❌ Invalid JSON format[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error reading report: {e}[/red]")

@cli.command()
@click.option('--terraform', '-t', type=click.Path(exists=True), required=True, help='Terraform configuration file')
@click.option('--events', '-e', type=click.Path(exists=True), required=True, help='JSON file with cloud events')
@click.option('--provider', '-p', type=click.Choice(['aws', 'azure', 'gcp']), default='aws', help='Cloud provider')
@click.option('--output', '-o', default='attack_paths.json', help='Output file for attack paths')
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'both']), default='table', help='Output format')
@click.option('--max-paths', '-m', type=int, default=50, help='Maximum paths to report')
def analyze_attack_paths(terraform: str, events: str, provider: str, output: str, format: str, max_paths: int):
    """Detect attack paths in cloud infrastructure"""
    
    console.print(Panel.fit("🗺️  Attack Path Detection", style="bold red"))
    
    try:
        # Load Terraform and events
        with open(terraform, 'r') as f:
            terraform_content = f.read()
        
        with open(events, 'r') as f:
            events_data = json.load(f)
        
        if not isinstance(events_data, list):
            console.print("[red]❌ Events file must contain a JSON array[/red]")
            return
        
        # Build permission graph from Terraform
        graph = _build_graph_from_terraform(terraform_content, events_data, provider)
        
        if graph.graph.number_of_nodes() == 0:
            console.print("[yellow]⚠️  No resources found in input[/yellow]")
            return
        
        # Display graph stats
        stats = graph.get_graph_stats()
        console.print(f"\n[bold]Graph Statistics:[/bold]")
        console.print(f"  • Total nodes: {stats['total_nodes']}")
        console.print(f"  • Total edges: {stats['total_edges']}")
        console.print(f"  • Functions: {stats['node_types']['function']}")
        console.print(f"  • Roles: {stats['node_types']['role']}")
        console.print(f"  • Resources: {stats['node_types']['resource']}")
        
        # Detect attack paths
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Detecting attack paths...", total=None)
            detector = AttackPathDetector(graph)
            attack_paths = detector.detect_all_attacks()
            progress.update(task, completed=True)
        
        if not attack_paths:
            console.print("[green]✅ No attack paths detected[/green]")
            return
        
        # Sort by risk score
        attack_paths_sorted = sorted(attack_paths, key=lambda p: p.risk_score, reverse=True)
        top_paths = attack_paths_sorted[:max_paths]
        
        # Display results
        if format in ['table', 'both']:
            _display_attack_paths_table(top_paths, graph)
        
        if format in ['json', 'both']:
            output_data = {
                "timestamp": str(datetime.now()),
                "graph_stats": stats,
                "total_paths_detected": len(attack_paths),
                "top_paths": [p.to_dict() for p in top_paths],
            }
            
            with open(output, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            console.print(f"\n[green]✅ Results saved to {output}[/green]")
    
    except json.JSONDecodeError:
        console.print("[red]❌ Invalid JSON format[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        import traceback
        traceback.print_exc()

@cli.command()
@click.option('--terraform', '-t', type=click.Path(exists=True), required=True, help='Terraform configuration file')
@click.option('--events', '-e', type=click.Path(exists=True), required=True, help='JSON file with cloud events')
@click.option('--provider', '-p', type=click.Choice(['aws', 'azure', 'gcp']), default='aws', help='Cloud provider')
@click.option('--output', '-o', default='risk_report.json', help='Output file for risk report')
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'both']), default='table', help='Output format')
def show_risk_report(terraform: str, events: str, provider: str, output: str, format: str):
    """Generate comprehensive risk assessment report"""
    
    console.print(Panel.fit("📊 Risk Assessment Report", style="bold magenta"))
    
    try:
        # Load Terraform and events
        with open(terraform, 'r') as f:
            terraform_content = f.read()
        
        with open(events, 'r') as f:
            events_data = json.load(f)
        
        if not isinstance(events_data, list):
            console.print("[red]❌ Events file must contain a JSON array[/red]")
            return
        
        # Build permission graph
        graph = _build_graph_from_terraform(terraform_content, events_data, provider)
        
        if graph.graph.number_of_nodes() == 0:
            console.print("[yellow]⚠️  No resources found in input[/yellow]")
            return
        
        # Calculate risk scores
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Calculating risk scores...", total=None)
            engine = RiskScoringEngine(graph)
            assessment = engine.assess_system_risk()
            progress.update(task, completed=True)
        
        # Display results
        if format in ['table', 'both']:
            _display_risk_report_table(assessment)
        
        if format in ['json', 'both']:
            with open(output, 'w') as f:
                json.dump(assessment.to_dict(), f, indent=2)
            
            console.print(f"\n[green]✅ Results saved to {output}[/green]")
    
    except json.JSONDecodeError:
        console.print("[red]❌ Invalid JSON format[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        import traceback
        traceback.print_exc()

def _display_results(policies, report, verbose=False):
    """Display analysis results in a formatted way"""
    
    # Summary table
    summary_table = Table(title="Analysis Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")
    
    summary = report.get('summary', {})
    summary_table.add_row("Functions Analyzed", str(summary.get('total_functions', 0)))
    summary_table.add_row("Policies Generated", str(summary.get('policies_generated', 0)))
    summary_table.add_row("Events Processed", str(summary.get('total_events_processed', 0)))
    summary_table.add_row("Avg Risk Reduction", f"{summary.get('average_risk_reduction', 0):.1f}%")
    
    console.print(summary_table)
    
    if verbose and policies:
        console.print("\n")
        # Detailed function table
        func_table = Table(title="Function Details")
        func_table.add_column("Function", style="cyan")
        func_table.add_column("Provider", style="green")
        func_table.add_column("Rules", style="white")
        func_table.add_column("Risk Reduction", style="yellow")
        func_table.add_column("Actions", style="blue")
        func_table.add_column("Resources", style="magenta")
        
        for function_id, policy in policies.items():
            func_details = report.get('function_details', {}).get(function_id, {})
            func_table.add_row(
                function_id,
                policy.cloud_provider,
                str(len(policy.rules)),
                f"{policy.risk_reduction:.1f}%",
                str(func_details.get('actions_observed', 0)),
                str(func_details.get('resources_accessed', 0))
            )
        
        console.print(func_table)

def _display_summary_report(report_data):
    """Display summary report"""
    summary = report_data.get('summary', {})
    
    # Create summary panel
    summary_text = f"""
[bold cyan]Total Functions:[/bold cyan] {summary.get('total_functions', 0)}
[bold green]Policies Generated:[/bold green] {summary.get('policies_generated', 0)}
[bold yellow]Events Processed:[/bold yellow] {summary.get('total_events_processed', 0)}
[bold red]Average Risk Reduction:[/bold red] {summary.get('average_risk_reduction', 0):.1f}%
"""
    
    console.print(Panel(summary_text, title="Summary", border_style="blue"))
    
    # Top functions by risk reduction
    function_details = report_data.get('function_details', {})
    if function_details:
        sorted_functions = sorted(
            function_details.items(), 
            key=lambda x: x[1].get('risk_reduction_percent', 0), 
            reverse=True
        )
        
        top_table = Table(title="Top Functions by Risk Reduction")
        top_table.add_column("Function", style="cyan")
        top_table.add_column("Risk Reduction", style="green")
        top_table.add_column("Rules", style="white")
        
        for func_id, details in sorted_functions[:5]:  # Top 5
            top_table.add_row(
                func_id,
                f"{details.get('risk_reduction_percent', 0):.1f}%",
                str(details.get('policy_rules_count', 0))
            )
        
        console.print(top_table)

def _display_detailed_report(report_data):
    """Display detailed tabular report"""
    function_details = report_data.get('function_details', {})
    
    if not function_details:
        console.print("[yellow]No function details available[/yellow]")
        return
    
    table = Table(title="Detailed Analysis Report")
    table.add_column("Function", style="cyan", no_wrap=True)
    table.add_column("Provider", style="green")
    table.add_column("Actions", style="white")
    table.add_column("Resources", style="blue")
    table.add_column("Risk Score", style="red")
    table.add_column("Risk Reduction", style="yellow")
    table.add_column("Rules", style="magenta")
    table.add_column("Outliers", style="orange")
    
    for func_id, details in function_details.items():
        table.add_row(
            func_id,
            details.get('cloud_provider', 'N/A'),
            str(details.get('actions_observed', 0)),
            str(details.get('resources_accessed', 0)),
            f"{details.get('risk_score', 0):.1f}",
            f"{details.get('risk_reduction_percent', 0):.1f}%",
            str(details.get('policy_rules_count', 0)),
            str(details.get('outlier_accesses', 0))
        )
    
    console.print(table)

def _build_graph_from_terraform(terraform_content: str, events_data: list, provider: str) -> 'PermissionGraph':
    """Build a permission graph from Terraform and events"""
    graph = PermissionGraph()
    
    # Parse terraform to extract functions, roles, and resources
    # This is a simplified parser - in production, use proper terraform parser
    import re
    
    # Extract Lambda/functions
    func_pattern = r'(resource\s+"aws_lambda_function"\s+"(\w+)".*?{|resource\s+"azurerm_function_app"\s+"(\w+)".*?{|resource\s+"google_cloudfunctions_function"\s+"(\w+)".*?{)'
    for match in re.finditer(func_pattern, terraform_content, re.DOTALL):
        func_id = match.group(2) or match.group(3) or match.group(4)
        if func_id:
            node = GraphNode(
                node_id=f"func_{func_id}",
                name=func_id,
                node_type=NodeType.FUNCTION,
                cloud_provider=provider,
                principal_arn=None,
            )
            graph.add_node(node)
    
    # Extract IAM roles
    role_pattern = r'resource\s+"aws_iam_role"\s+"(\w+)".*?{|resource\s+"azurerm_role_definition"\s+"(\w+)".*?{|resource\s+"google_service_account"\s+"(\w+)".*?{'
    for match in re.finditer(role_pattern, terraform_content, re.DOTALL):
        role_id = match.group(1) or match.group(2) or match.group(3)
        if role_id:
            node = GraphNode(
                node_id=f"role_{role_id}",
                name=role_id,
                node_type=NodeType.ROLE,
                cloud_provider=provider,
                principal_arn=None,
            )
            graph.add_node(node)
    
    # Extract resources (S3, storage, databases)
    resource_types = [
        (r'resource\s+"aws_s3_bucket"\s+"(\w+)"', "S3"),
        (r'resource\s+"aws_dynamodb_table"\s+"(\w+)"', "DynamoDB"),
        (r'resource\s+"aws_rds_instance"\s+"(\w+)"', "RDS"),
        (r'resource\s+"azurerm_storage_account"\s+"(\w+)"', "Storage"),
        (r'resource\s+"google_storage_bucket"\s+"(\w+)"', "Storage"),
    ]
    
    for pattern, service_type in resource_types:
        for match in re.finditer(pattern, terraform_content):
            res_id = match.group(1)
            if res_id:
                node = GraphNode(
                    node_id=f"res_{res_id}",
                    name=res_id,
                    node_type=NodeType.RESOURCE,
                    cloud_provider=provider,
                    resource_arn=None,
                    sensitive_services={service_type.lower()},
                )
                graph.add_node(node)
    
    # Add edges from events
    for event in events_data[:20]:  # Limit to avoid explosion
        caller = event.get('caller_principal', '')
        action = event.get('api_action', '')
        resource = event.get('resource_accessed', '')
        
        if not caller or not resource:
            continue
        
        # Find matching nodes
        source_nodes = [
            n for n in graph.nodes_by_id.keys()
            if caller.lower() in n.lower() or n.lower() in caller.lower()
        ]
        target_nodes = [
            n for n in graph.nodes_by_id.keys()
            if resource.lower() in n.lower() or n.lower() in resource.lower()
        ]
        
        for src in source_nodes[:3]:
            for tgt in target_nodes[:3]:
                if src != tgt:
                    has_wildcards = '*' in action
                    graph.add_edge(
                        src,
                        tgt,
                        EdgeType.CAN_ACCESS,
                        permissions={action},
                        has_wildcards=has_wildcards,
                    )
    
    # If graph is still empty, add some synthetic nodes for demo
    if graph.graph.number_of_nodes() == 0:
        for i in range(3):
            node = GraphNode(
                node_id=f"func_{i}",
                name=f"function_{i}",
                node_type=NodeType.FUNCTION,
                cloud_provider=provider,
            )
            graph.add_node(node)
        
        for i in range(2):
            node = GraphNode(
                node_id=f"role_{i}",
                name=f"role_{i}",
                node_type=NodeType.ROLE,
                cloud_provider=provider,
            )
            graph.add_node(node)
        
        admin_node = GraphNode(
            node_id="admin",
            name="admin_role",
            node_type=NodeType.ADMIN,
            cloud_provider=provider,
        )
        graph.add_node(admin_node)
        
        # Add some edges
        graph.add_edge("func_0", "role_0", EdgeType.CAN_ASSUME_ROLE)
        graph.add_edge("role_0", "admin", EdgeType.CAN_ASSUME_ROLE, has_wildcards=True)
    
    return graph

def _display_attack_paths_table(attack_paths: list, graph: 'PermissionGraph'):
    """Display attack paths in a formatted table"""
    
    table = Table(title="Detected Attack Paths")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Type", style="green")
    table.add_column("Risk", style="red")
    table.add_column("Length", style="white")
    table.add_column("Path", style="blue")
    table.add_column("Explanation", style="yellow")
    
    for path in attack_paths[:30]:
        node_names = []
        for node_id in path.nodes:
            node = graph.get_node(node_id)
            if node:
                node_names.append(node.name[:15])
            else:
                node_names.append(node_id[:15])
        
        path_str = " → ".join(node_names)
        if len(path_str) > 50:
            path_str = path_str[:47] + "..."
        
        table.add_row(
            path.path_id,
            path.path_type.value[:15],
            f"{path.risk_score:.0f}",
            str(path.path_length),
            path_str,
            path.explanation[:40] + ("..." if len(path.explanation) > 40 else ""),
        )
    
    console.print(table)
    console.print(f"\n[bold]Total paths detected:[/bold] {len(attack_paths)}")

def _display_risk_report_table(assessment: 'RiskAssessment'):
    """Display risk assessment in formatted tables"""
    
    # System summary
    summary_panel = f"""
[bold cyan]System Risk Score:[/bold cyan] {assessment.system_risk_score:.1f}/100.0
[bold red]System Risk Level:[/bold red] {assessment.system_risk_level}
[bold yellow]Total Attack Paths:[/bold yellow] {assessment.total_attack_paths}
[bold]Critical Paths:[/bold] {assessment.critical_attack_paths}
"""
    console.print(Panel(summary_panel, title="System Risk Summary", border_style="red"))
    
    # Node risk table
    if assessment.node_risk_scores:
        node_table = Table(title="Top 10 High-Risk Nodes")
        node_table.add_column("Node", style="cyan")
        node_table.add_column("Type", style="green")
        node_table.add_column("Risk Score", style="red", no_wrap=True)
        node_table.add_column("Risk Level", style="white")
        node_table.add_column("Wildcards", style="yellow")
        node_table.add_column("Sensitive Services", style="blue")
        
        for node_risk in assessment.node_risk_scores[:10]:
            node_table.add_row(
                node_risk.node_name[:20],
                node_risk.node_type,
                f"{node_risk.risk_score:.1f}",
                node_risk.risk_level,
                str(node_risk.wildcard_permissions),
                str(node_risk.sensitive_services_count),
            )
        
        console.print(node_table)
    
    # Policy risk table
    if assessment.policy_risk_scores:
        policy_table = Table(title="Policy Risk Assessment")
        policy_table.add_column("Policy", style="cyan")
        policy_table.add_column("Risk Score", style="red")
        policy_table.add_column("Risk Level", style="white")
        policy_table.add_column("Permissions", style="green")
        policy_table.add_column("Wildcards", style="yellow")
        policy_table.add_column("Admin", style="magenta")
        
        for policy_risk in assessment.policy_risk_scores[:10]:
            policy_table.add_row(
                policy_risk.policy_name[:25],
                f"{policy_risk.risk_score:.1f}",
                policy_risk.risk_level,
                str(policy_risk.permission_count),
                str(policy_risk.wildcard_count),
                "Yes" if policy_risk.has_admin_permissions else "No",
            )
        
        console.print(policy_table)
    
    # Attack paths summary
    if assessment.top_attack_paths:
        path_table = Table(title="Top Attack Paths")
        path_table.add_column("Type", style="cyan")
        path_table.add_column("Risk Score", style="red")
        path_table.add_column("Path Length", style="white")
        path_table.add_column("Explanation", style="yellow")
        
        for path in assessment.top_attack_paths[:5]:
            path_table.add_row(
                path.path_type.value,
                f"{path.risk_score:.1f}",
                str(path.path_length),
                path.explanation[:50] + ("..." if len(path.explanation) > 50 else ""),
            )
        
        console.print(path_table)
    
    # Recommendations
    if assessment.recommendations:
        console.print("\n[bold]📋 Recommendations:[/bold]")
        for i, rec in enumerate(assessment.recommendations, 1):
            console.print(f"  {i}. {rec}")

    """Main entry point for CLI"""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[red]Operation cancelled by user[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()