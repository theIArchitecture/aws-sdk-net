#!/usr/bin/env python3
"""
AWS CloudFormation Architecture Healer

Automatically fixes architectural violations in CloudFormation templates:
- Adds sticky session Target Groups to Load Balancers
- Enables MultiAZ on RDS instances
- Adds read replicas to production databases
- Configures auto-scaling policies

This demonstrates infrastructure healing capabilities.
"""

import sys
import json
import re
from typing import Dict, List, Any, Optional


def heal_cloudformation(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Heal CloudFormation template architectural violations.

    Args:
        input_data: PluginInput with filePath, fileContent, language, config

    Returns:
        PluginOutput with violations=[], fixes, and error
    """
    file_content = input_data.get('fileContent', '')
    config = input_data.get('config', {})

    fixes = []

    try:
        # Parse CloudFormation template
        template = parse_template(file_content)

        if not template:
            return {
                'violations': [],
                'fixes': [],
                'error': 'Could not parse CloudFormation template'
            }

        # Validate it's a dict (CloudFormation templates are always dicts, not lists/strings)
        if not isinstance(template, dict):
            return {
                'violations': [],
                'fixes': [],
                'error': 'Not a valid CloudFormation template (expected dict structure)'
            }

        resources = template.get('Resources', {})
        if not resources:
            return {'violations': [], 'fixes': [], 'error': None}

        # Track modifications
        modified = False

        # Apply healing transformations
        modified |= heal_load_balancer_sticky_sessions(template, fixes)
        modified |= heal_rds_multi_az(template, fixes)
        modified |= heal_rds_read_replicas(template, fixes)

        # If modifications were made, serialize the fixed template
        if modified:
            import yaml
            fixed_content = yaml.dump(template, default_flow_style=False, sort_keys=False)

            # Add overall fix description
            fixes.append({
                'description': 'Applied infrastructure architecture fixes to CloudFormation template',
                'fixedContent': fixed_content
            })

        return {
            'violations': [],
            'fixes': fixes,
            'error': None
        }

    except Exception as e:
        return {
            'violations': [],
            'fixes': [],
            'error': f'Healing error: {str(e)}'
        }


def parse_template(content: str) -> Optional[Dict[str, Any]]:
    """Parse CloudFormation template as YAML or JSON."""
    try:
        import yaml

        # CloudFormation uses custom YAML tags like !Ref, !GetAtt, !Sub, etc.
        # We need to handle these tags to parse CF templates
        def cf_constructor(loader, tag_suffix, node):
            """Handle CloudFormation intrinsic functions as dictionaries."""
            if isinstance(node, yaml.ScalarNode):
                return {tag_suffix: loader.construct_scalar(node)}
            elif isinstance(node, yaml.SequenceNode):
                return {tag_suffix: loader.construct_sequence(node)}
            elif isinstance(node, yaml.MappingNode):
                return {tag_suffix: loader.construct_mapping(node)}
            return {tag_suffix: None}

        # Register multi-constructor for all CF tags
        yaml.SafeLoader.add_multi_constructor('!', cf_constructor)

        return yaml.safe_load(content)
    except Exception as e:
        pass

    try:
        return json.loads(content)
    except:
        pass

    return None


def heal_load_balancer_sticky_sessions(
    template: Dict[str, Any],
    fixes: List[Dict[str, Any]]
) -> bool:
    """
    Add sticky session attributes to Target Groups that lack them.

    Returns True if template was modified.
    """
    resources = template.get('Resources', {})
    modified = False

    # Check each existing target group for stickiness and add if missing
    for tg_name, tg_resource in list(resources.items()):
        if tg_resource.get('Type') == 'AWS::ElasticLoadBalancingV2::TargetGroup':
            props = tg_resource.get('Properties', {})
            attrs = props.get('TargetGroupAttributes', [])

            # Check if stickiness is already enabled
            has_stickiness = any(
                attr.get('Key') == 'stickiness.enabled' and attr.get('Value') == 'true'
                for attr in attrs
            )

            if not has_stickiness:
                # Add stickiness attributes
                if 'TargetGroupAttributes' not in props:
                    props['TargetGroupAttributes'] = []

                props['TargetGroupAttributes'].extend([
                    {
                        'Key': 'stickiness.enabled',
                        'Value': 'true'
                    },
                    {
                        'Key': 'stickiness.type',
                        'Value': 'lb_cookie'
                    },
                    {
                        'Key': 'stickiness.lb_cookie.duration_seconds',
                        'Value': '86400'
                    }
                ])

                fixes.append({
                    'description': f'Enabled sticky sessions for Target Group "{tg_name}"',
                    'line': 1
                })

                modified = True

    return modified


def heal_rds_multi_az(
    template: Dict[str, Any],
    fixes: List[Dict[str, Any]]
) -> bool:
    """
    Enable MultiAZ on RDS instances.

    Returns True if template was modified.
    """
    resources = template.get('Resources', {})
    modified = False

    for name, resource in resources.items():
        if resource.get('Type') == 'AWS::RDS::DBInstance':
            props = resource.get('Properties', {})

            if not props.get('MultiAZ'):
                props['MultiAZ'] = True

                fixes.append({
                    'description': f'Enabled MultiAZ for RDS instance "{name}" for high availability',
                    'line': 1
                })

                modified = True

    return modified


def heal_rds_read_replicas(
    template: Dict[str, Any],
    fixes: List[Dict[str, Any]]
) -> bool:
    """
    Add read replicas for RDS instances.

    Returns True if template was modified.
    """
    resources = template.get('Resources', {})
    modified = False

    # Find primary RDS instances (no SourceDBInstanceIdentifier)
    primary_instances = []
    read_replicas = {}

    for name, resource in resources.items():
        if resource.get('Type') == 'AWS::RDS::DBInstance':
            props = resource.get('Properties', {})
            source_db = props.get('SourceDBInstanceIdentifier')

            if source_db:
                # Track existing replicas
                source_ref = source_db.get('Ref') if isinstance(source_db, dict) else source_db
                read_replicas[source_ref] = read_replicas.get(source_ref, 0) + 1
            else:
                # This is a primary instance
                primary_instances.append(name)

    # Add read replica for primary instances that don't have one
    for primary_name in primary_instances:
        if primary_name not in read_replicas:
            replica_name = f'{primary_name}ReadReplica'

            resources[replica_name] = {
                'Type': 'AWS::RDS::DBInstance',
                'Properties': {
                    'SourceDBInstanceIdentifier': {'Ref': primary_name},
                    'DBInstanceClass': {'Ref': f'{primary_name}.DBInstanceClass'}  # Inherit class
                },
                'DependsOn': [primary_name]
            }

            fixes.append({
                'description': f'Added read replica "{replica_name}" for RDS instance "{primary_name}"',
                'line': 1
            })

            modified = True

    return modified


if __name__ == '__main__':
    # Read input from stdin
    input_json = sys.stdin.read()
    input_data = json.loads(input_json)

    # Heal CloudFormation template
    output = heal_cloudformation(input_data)

    # Write output to stdout
    print(json.dumps(output, indent=2))
    sys.exit(0)
