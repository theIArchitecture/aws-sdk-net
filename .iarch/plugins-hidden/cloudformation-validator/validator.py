#!/usr/bin/env python3
"""
AWS CloudFormation Architecture Validator

Validates architectural decisions in CloudFormation templates including:
- Load balancer sticky session requirements
- Multi-AZ deployment patterns
- RDS read replica strategies
- Auto-scaling configurations

This plugin demonstrates infrastructure-as-code validation capabilities.
"""

import sys
import json
import re
from typing import Dict, List, Any, Optional


def validate_cloudformation(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate CloudFormation template for architectural violations.

    Args:
        input_data: PluginInput with filePath, fileContent, language, config

    Returns:
        PluginOutput with violations, fixes, and error
    """
    file_content = input_data.get('fileContent', '')
    config = input_data.get('config', {})

    violations = []

    try:
        # Parse CloudFormation template (YAML or JSON)
        template = parse_template(file_content)

        if not template:
            # Silently skip non-CloudFormation files (same as unsupported file extensions)
            return {
                'violations': [],
                'fixes': [],
                'error': None
            }

        # Validate it's a dict (CloudFormation templates are always dicts, not lists/strings)
        if not isinstance(template, dict):
            # Silently skip non-CloudFormation files (YAML/JSON that aren't CloudFormation)
            return {
                'violations': [],
                'fixes': [],
                'error': None
            }

        # Extract resources section
        resources = template.get('Resources', {})

        if not resources:
            # Not a violation - might be a parameters-only template
            return {
                'violations': [],
                'fixes': [],
                'error': None
            }

        # Run architectural validations based on config
        # If 'check' is specified, run only that check
        # If no 'check' specified, run all checks
        check = config.get('check', 'all')

        # Get severity from config (defaults to Error if not specified)
        severity = config.get('severity', 'Error')

        if check == 'all' or check == 'load_balancer_sticky_sessions':
            violations.extend(validate_load_balancer_sticky_sessions(resources, file_content, severity))

        if check == 'all' or check == 'rds_multi_az':
            violations.extend(validate_multi_az_deployment(resources, file_content, severity))

        if check == 'all' or check == 'rds_read_replicas':
            violations.extend(validate_rds_read_replicas(resources, file_content))

        if check == 'all' or check == 'auto_scaling':
            violations.extend(validate_auto_scaling(resources, file_content))

        return {
            'violations': violations,
            'fixes': [],
            'error': None
        }

    except Exception as e:
        return {
            'violations': [],
            'fixes': [],
            'error': f'Validation error: {str(e)}'
        }


def parse_template(content: str) -> Optional[Dict[str, Any]]:
    """Parse CloudFormation template as YAML or JSON."""
    try:
        # Try YAML first (more common for CloudFormation)
        import yaml

        # Add CloudFormation-specific YAML constructors
        # These intrinsic functions are represented as dictionaries
        def ref_constructor(loader, node):
            return {'Ref': loader.construct_scalar(node)}

        def getatt_constructor(loader, node):
            # !GetAtt can be either a sequence or scalar (dot notation)
            if node.id == 'scalar':
                # Handle dot notation: Resource.Property
                value = loader.construct_scalar(node)
                parts = value.split('.', 1)
                return {'Fn::GetAtt': parts if len(parts) == 2 else [value]}
            else:
                return {'Fn::GetAtt': loader.construct_sequence(node)}

        def sub_constructor(loader, node):
            # !Sub can be either a string or a sequence [string, {vars}]
            if node.id == 'scalar':
                return {'Fn::Sub': loader.construct_scalar(node)}
            else:
                return {'Fn::Sub': loader.construct_sequence(node)}

        def join_constructor(loader, node):
            return {'Fn::Join': loader.construct_sequence(node)}

        def select_constructor(loader, node):
            return {'Fn::Select': loader.construct_sequence(node)}

        # Register constructors for CloudFormation intrinsic functions
        yaml.SafeLoader.add_constructor('!Ref', ref_constructor)
        yaml.SafeLoader.add_constructor('!GetAtt', getatt_constructor)
        yaml.SafeLoader.add_constructor('!Sub', sub_constructor)
        yaml.SafeLoader.add_constructor('!Join', join_constructor)
        yaml.SafeLoader.add_constructor('!Select', select_constructor)
        yaml.SafeLoader.add_constructor('!FindInMap', lambda l, n: {'Fn::FindInMap': l.construct_sequence(n)})
        yaml.SafeLoader.add_constructor('!GetAZs', lambda l, n: {'Fn::GetAZs': l.construct_scalar(n)})
        yaml.SafeLoader.add_constructor('!ImportValue', lambda l, n: {'Fn::ImportValue': l.construct_scalar(n)})
        yaml.SafeLoader.add_constructor('!Split', lambda l, n: {'Fn::Split': l.construct_sequence(n)})
        yaml.SafeLoader.add_constructor('!Base64', lambda l, n: {'Fn::Base64': l.construct_scalar(n)})
        yaml.SafeLoader.add_constructor('!Cidr', lambda l, n: {'Fn::Cidr': l.construct_sequence(n)})
        yaml.SafeLoader.add_constructor('!Equals', lambda l, n: {'Fn::Equals': l.construct_sequence(n)})
        yaml.SafeLoader.add_constructor('!If', lambda l, n: {'Fn::If': l.construct_sequence(n)})
        yaml.SafeLoader.add_constructor('!Not', lambda l, n: {'Fn::Not': l.construct_sequence(n)})
        yaml.SafeLoader.add_constructor('!And', lambda l, n: {'Fn::And': l.construct_sequence(n)})
        yaml.SafeLoader.add_constructor('!Or', lambda l, n: {'Fn::Or': l.construct_sequence(n)})

        return yaml.safe_load(content)
    except:
        pass

    try:
        # Try JSON
        return json.loads(content)
    except:
        pass

    return None


def validate_load_balancer_sticky_sessions(
    resources: Dict[str, Any],
    file_content: str,
    severity: str = 'Error'
) -> List[Dict[str, Any]]:
    """
    AWS-ARCH-LB-001: Load balancers must use sticky sessions.

    Validates that Application Load Balancers have corresponding Target Groups
    with sticky session configuration enabled.
    """
    violations = []

    # Find all load balancers
    load_balancers = {}
    for name, resource in resources.items():
        resource_type = resource.get('Type', '')
        if resource_type == 'AWS::ElasticLoadBalancingV2::LoadBalancer':
            load_balancers[name] = resource

    # Find all target groups with stickiness enabled
    sticky_target_groups = set()
    for name, resource in resources.items():
        resource_type = resource.get('Type', '')
        if resource_type == 'AWS::ElasticLoadBalancingV2::TargetGroup':
            props = resource.get('Properties', {})
            attrs = props.get('TargetGroupAttributes', [])

            # Check if stickiness is enabled
            for attr in attrs:
                if isinstance(attr, dict):
                    if attr.get('Key') == 'stickiness.enabled' and attr.get('Value') in ['true', True]:
                        sticky_target_groups.add(name)
                        break

    # Report load balancers without sticky target groups
    if load_balancers and not sticky_target_groups:
        for lb_name in load_balancers.keys():
            line_num = find_line_number(file_content, lb_name)
            violations.append({
                'id': 'AWS-ARCH-LB-001',
                'message': f'Load balancer "{lb_name}" must have a Target Group with sticky sessions enabled for session affinity',
                'line': line_num,
                'column': 1,
                'severity': severity,
                'snippet': f'LoadBalancer: {lb_name}'
            })

    return violations


def validate_multi_az_deployment(
    resources: Dict[str, Any],
    file_content: str,
    severity: str = 'Error'
) -> List[Dict[str, Any]]:
    """
    AWS-ARCH-HA-001: Resources must deploy across multiple availability zones.

    Validates that critical resources like RDS, ECS services, and ASGs are
    configured for multi-AZ deployment.
    """
    violations = []

    # Check RDS instances for MultiAZ
    for name, resource in resources.items():
        resource_type = resource.get('Type', '')

        if resource_type == 'AWS::RDS::DBInstance':
            props = resource.get('Properties', {})
            multi_az = props.get('MultiAZ', False)

            if not multi_az:
                line_num = find_line_number(file_content, name)
                violations.append({
                    'id': 'AWS-ARCH-HA-001',
                    'message': f'RDS instance "{name}" must enable MultiAZ for high availability',
                    'line': line_num,
                    'column': 1,
                    'severity': severity,
                    'snippet': f'DBInstance: {name} (MultiAZ: false)'
                })

        # Check ECS services for multi-subnet deployment
        elif resource_type == 'AWS::ECS::Service':
            props = resource.get('Properties', {})
            network_config = props.get('NetworkConfiguration', {})
            awsvpc_config = network_config.get('AwsvpcConfiguration', {})
            subnets = awsvpc_config.get('Subnets', [])

            if len(subnets) < 2:
                line_num = find_line_number(file_content, name)
                violations.append({
                    'id': 'AWS-ARCH-HA-001',
                    'message': f'ECS service "{name}" must deploy to at least 2 subnets (different AZs) for high availability',
                    'line': line_num,
                    'column': 1,
                    'severity': 'Warning',  # ECS multi-subnet is Warning, not Fatal
                    'snippet': f'ECS Service: {name} (Subnets: {len(subnets)})'
                })

    return violations


def validate_rds_read_replicas(
    resources: Dict[str, Any],
    file_content: str
) -> List[Dict[str, Any]]:
    """
    AWS-ARCH-DB-001: RDS instances should have read replicas for production.

    Validates that production databases have read replicas to handle read traffic.
    """
    violations = []

    # Find primary RDS instances
    primary_instances = {}
    read_replicas = {}

    for name, resource in resources.items():
        resource_type = resource.get('Type', '')

        if resource_type == 'AWS::RDS::DBInstance':
            props = resource.get('Properties', {})
            source_db = props.get('SourceDBInstanceIdentifier')

            if source_db:
                # This is a read replica
                read_replicas[name] = source_db
            else:
                # This is a primary instance
                primary_instances[name] = resource

    # Check if primary instances have read replicas
    for primary_name in primary_instances.keys():
        has_replica = any(
            source == primary_name or source.get('Ref') == primary_name
            for source in read_replicas.values()
        )

        if not has_replica:
            line_num = find_line_number(file_content, primary_name)
            violations.append({
                'id': 'AWS-ARCH-DB-001',
                'message': f'RDS instance "{primary_name}" should have at least one read replica for read-heavy workloads',
                'line': line_num,
                'column': 1,
                'severity': 'Warning',
                'snippet': f'DBInstance: {primary_name} (no read replicas found)'
            })

    return violations


def validate_auto_scaling(
    resources: Dict[str, Any],
    file_content: str
) -> List[Dict[str, Any]]:
    """
    AWS-ARCH-SCALE-001: Auto-scaling must be configured for scalable services.

    Validates that services have auto-scaling policies configured.
    """
    violations = []

    # Find auto-scaling groups
    asg_names = set()
    for name, resource in resources.items():
        resource_type = resource.get('Type', '')
        if resource_type == 'AWS::AutoScaling::AutoScalingGroup':
            asg_names.add(name)

    # Find scaling policies
    scaling_policies = {}
    for name, resource in resources.items():
        resource_type = resource.get('Type', '')
        if resource_type == 'AWS::AutoScaling::ScalingPolicy':
            props = resource.get('Properties', {})
            asg_name = props.get('AutoScalingGroupName', {}).get('Ref', '')
            if asg_name:
                scaling_policies[asg_name] = scaling_policies.get(asg_name, 0) + 1

    # Check ASGs without scaling policies
    for asg_name in asg_names:
        if asg_name not in scaling_policies:
            line_num = find_line_number(file_content, asg_name)
            violations.append({
                'id': 'AWS-ARCH-SCALE-001',
                'message': f'Auto Scaling Group "{asg_name}" must have scaling policies configured',
                'line': line_num,
                'column': 1,
                'severity': 'Warning',
                'snippet': f'AutoScalingGroup: {asg_name} (no scaling policies)'
            })

    return violations


def find_line_number(content: str, search_text: str) -> int:
    """Find approximate line number where text appears in content."""
    lines = content.split('\n')
    for i, line in enumerate(lines, start=1):
        if search_text in line:
            return i
    return 1


if __name__ == '__main__':
    # Read input from stdin
    input_json = sys.stdin.read()
    input_data = json.loads(input_json)

    # Validate CloudFormation template
    output = validate_cloudformation(input_data)

    # Write output to stdout
    print(json.dumps(output, indent=2))
    sys.exit(0)
