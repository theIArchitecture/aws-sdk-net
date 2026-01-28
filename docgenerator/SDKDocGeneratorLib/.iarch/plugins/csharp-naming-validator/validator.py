#!/usr/bin/env python3
"""
C# Naming Convention Validator Plugin

Detects snake_case private fields in C# code, which violates C# naming conventions.
C# private fields should use camelCase or _camelCase (with underscore prefix).
"""

import sys
import json
import re


def validate_csharp_naming(input_data):
    """
    Validates C# naming conventions.

    Detects private fields using snake_case instead of camelCase/_camelCase.
    """
    file_content = input_data.get('fileContent', '')
    file_path = input_data.get('filePath', 'unknown')

    violations = []

    # Pattern to detect private fields with snake_case
    # Matches: private <type> field_name;
    # This regex looks for:
    # - 'private' keyword
    # - Optional 'readonly', 'static', 'const' modifiers
    # - Type (any valid C# type identifier)
    # - Field name containing underscores (snake_case)
    pattern = r'^\s*private\s+(?:readonly\s+|static\s+|const\s+)?[\w<>,\[\]]+\s+([a-z][a-z0-9]*_[a-z0-9_]+)\s*[;=]'

    lines = file_content.split('\n')

    for line_number, line in enumerate(lines, start=1):
        match = re.search(pattern, line, re.IGNORECASE)

        if match:
            field_name = match.group(1)

            # Extract the problematic snippet
            snippet = line.strip()

            # Create violation
            violations.append({
                'id': 'NAMING-SNAKE-CASE-FIELD',
                'message': f'Private field "{field_name}" uses snake_case instead of camelCase or _camelCase',
                'line': line_number,
                'column': match.start(1) + 1,
                'severity': 'Warning',
                'snippet': snippet
            })

    return {
        'violations': violations,
        'fixes': [],
        'error': None
    }


def main():
    """Main entry point for the plugin."""
    try:
        # Read JSON input from stdin
        input_json = sys.stdin.read()

        if not input_json.strip():
            output = {
                'violations': [],
                'fixes': [],
                'error': 'No input received from stdin'
            }
            print(json.dumps(output))
            sys.exit(1)

        # Parse input
        input_data = json.loads(input_json)

        # Validate naming conventions
        output = validate_csharp_naming(input_data)

        # Write JSON output to stdout
        print(json.dumps(output, indent=2))
        sys.exit(0)

    except json.JSONDecodeError as e:
        output = {
            'violations': [],
            'fixes': [],
            'error': f'Failed to parse input JSON: {str(e)}'
        }
        print(json.dumps(output))
        sys.exit(1)

    except Exception as e:
        output = {
            'violations': [],
            'fixes': [],
            'error': f'Plugin execution failed: {str(e)}'
        }
        print(json.dumps(output))
        sys.exit(1)


if __name__ == '__main__':
    main()
