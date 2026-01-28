# Semgrep Validator Plugin

## Purpose
Executes Semgrep AST-based pattern matching for .iarch rules extracted from Semgrep registry.

## Type
**Validator** - Detects violations using Semgrep's pattern engine

## How It Works

1. **Reads semgrep_patterns from CONFIG** - Patterns extracted from Semgrep YAML
2. **Generates temporary Semgrep YAML** - Creates rule file with patterns
3. **Executes semgrep CLI** - Runs Semgrep against target file
4. **Parses JSON output** - Reads Semgrep results
5. **Returns violations** - Converts to PluginViolation format

## Configuration

Rules using this plugin include `semgrep_patterns` in CONFIG:

```iarch
PLUGIN:
  ID: "semgrep-validator"
  SCOPE: "file"
  CONFIG:
    semgrep_patterns: "{\"python\":[{\"Name\":\"PATTERN_1\",\"Pattern\":\"...\"}]}"
```

## Supported Languages
- Python
- JavaScript
- TypeScript
- Go
- Java
- C
- C++
- Rust
- Ruby
- PHP

## Example Rule

```iarch
RULE "Detected MD5 hash algorithm" : IValidationArchitecture

ID: "SEMGREP-SEC-MD5-5"
SEVERITY: Warning
CATEGORY: Security
APPLIES_TO: ["go"]

PLUGIN:
  ID: "semgrep-validator"
  SCOPE: "file"
  CONFIG:
    semgrep_patterns: "{\"go\":[{\"Name\":\"PATTERN_1\",\"Pattern\":\"md5.New()\"},{\"Name\":\"PATTERN_2\",\"Pattern\":\"md5.Sum(...)\"}]}"

VIOLATIONS:
  - "MD5 usage detected"

END RULE
```

## Requirements
- Semgrep CLI must be installed and available on PATH
- Patterns must be valid Semgrep syntax

## Status
- ✅ Built and ready for use
- ✅ Supports all common programming languages
- ✅ Integrates with IArchRuleExtractor for Semgrep registry extraction

---

**Last Updated**: 2026-01-12
