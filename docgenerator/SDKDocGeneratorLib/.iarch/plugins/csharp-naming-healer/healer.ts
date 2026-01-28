#!/usr/bin/env ts-node

/**
 * C# Naming Convention Healer Plugin
 *
 * Automatically converts snake_case private fields to _camelCase format.
 * Example: private string api_key; -> private string _apiKey;
 */

import * as fs from 'fs';
import * as process from 'process';

interface PluginInput {
  filePath: string;
  fileContent: string;
  language: string;
  config: { [key: string]: string };
}

interface PluginFix {
  description: string;
  line?: number;
  column?: number;
  findText?: string;
  replacementText?: string;
  fixedContent?: string;
}

interface PluginOutput {
  violations: any[];
  fixes: PluginFix[];
  error?: string;
}

/**
 * Converts snake_case to camelCase
 * Example: api_key -> apiKey
 */
function snakeToCamel(snakeCaseStr: string): string {
  return snakeCaseStr.replace(/_([a-z0-9])/g, (match, letter) => letter.toUpperCase());
}

/**
 * Heals C# naming violations by converting snake_case private fields to _camelCase
 */
function healCSharpNaming(input: PluginInput): PluginOutput {
  const fileContent = input.fileContent;
  const config = input.config || {};

  // Check if we should use underscore prefix (default: true)
  const useUnderscorePrefix = config.use_underscore_prefix !== 'false';

  const fixes: PluginFix[] = [];
  let modifiedContent = fileContent;

  // Pattern to detect private fields with snake_case
  // Matches: private <type> field_name;
  const fieldPattern = /^(\s*private\s+(?:readonly\s+|static\s+|const\s+)?[\w<>,\[\]]+\s+)([a-z][a-z0-9]*_[a-z0-9_]+)(\s*[;=])/gim;

  const lines = fileContent.split('\n');
  const replacements: { [oldName: string]: string } = {};

  // First pass: identify all fields that need renaming
  lines.forEach((line, lineIndex) => {
    const lineNumber = lineIndex + 1;
    let match;

    while ((match = fieldPattern.exec(line)) !== null) {
      const prefix = match[1];
      const oldFieldName = match[2];
      const suffix = match[3];

      // Convert to camelCase
      const camelCaseName = snakeToCamel(oldFieldName);

      // Add underscore prefix if configured
      const newFieldName = useUnderscorePrefix ? `_${camelCaseName}` : camelCaseName;

      // Store the replacement mapping
      replacements[oldFieldName] = newFieldName;

      fixes.push({
        description: `Rename field '${oldFieldName}' to '${newFieldName}' (C# naming convention)`,
        line: lineNumber,
        column: match.index + prefix.length + 1
      });
    }

    // Reset regex lastIndex for next iteration
    fieldPattern.lastIndex = 0;
  });

  // Second pass: apply all replacements
  if (Object.keys(replacements).length > 0) {
    // Replace field declarations
    for (const [oldName, newName] of Object.entries(replacements)) {
      // Match field declaration
      const declarationRegex = new RegExp(
        `(private\\s+(?:readonly\\s+|static\\s+|const\\s+)?[\\w<>,\\[\\]]+\\s+)${oldName}(\\s*[;=])`,
        'gi'
      );
      modifiedContent = modifiedContent.replace(declarationRegex, `$1${newName}$2`);

      // Match field usage (this.field_name or just field_name)
      // Be careful to match word boundaries to avoid partial replacements
      const usageRegex = new RegExp(`\\b${oldName}\\b`, 'g');
      modifiedContent = modifiedContent.replace(usageRegex, newName);
    }

    // Return the fixed content
    return {
      violations: [],
      fixes: fixes,
      error: undefined
    };
  } else {
    // No violations found, return empty fixes
    return {
      violations: [],
      fixes: [],
      error: undefined
    };
  }
}

/**
 * Main entry point
 */
async function main() {
  try {
    // Read input from stdin
    const chunks: Buffer[] = [];

    for await (const chunk of process.stdin) {
      chunks.push(chunk);
    }

    const inputJson = Buffer.concat(chunks).toString('utf-8');

    if (!inputJson.trim()) {
      const output: PluginOutput = {
        violations: [],
        fixes: [],
        error: 'No input received from stdin'
      };
      console.log(JSON.stringify(output, null, 2));
      process.exit(1);
    }

    // Parse input
    const input: PluginInput = JSON.parse(inputJson);

    // Heal naming violations
    const output = healCSharpNaming(input);

    // Output the modified content if fixes were applied
    if (output.fixes.length > 0) {
      // Read the file content again to get the modified version
      const modifiedOutput: PluginOutput = {
        violations: [],
        fixes: output.fixes.map(fix => ({
          ...fix,
          fixedContent: undefined // Will use the full fixedContent below
        })),
        error: undefined
      };

      // Re-run the healing to get the modified content
      let modifiedContent = input.fileContent;
      const replacements: { [oldName: string]: string } = {};
      const config = input.config || {};
      const useUnderscorePrefix = config.use_underscore_prefix !== 'false';

      const fieldPattern = /^(\s*private\s+(?:readonly\s+|static\s+|const\s+)?[\w<>,\[\]]+\s+)([a-z][a-z0-9]*_[a-z0-9_]+)(\s*[;=])/gim;
      const lines = input.fileContent.split('\n');

      lines.forEach(line => {
        let match;
        while ((match = fieldPattern.exec(line)) !== null) {
          const oldFieldName = match[2];
          const camelCaseName = snakeToCamel(oldFieldName);
          const newFieldName = useUnderscorePrefix ? `_${camelCaseName}` : camelCaseName;
          replacements[oldFieldName] = newFieldName;
        }
        fieldPattern.lastIndex = 0;
      });

      // Apply replacements
      for (const [oldName, newName] of Object.entries(replacements)) {
        const declarationRegex = new RegExp(
          `(private\\s+(?:readonly\\s+|static\\s+|const\\s+)?[\\w<>,\\[\\]]+\\s+)${oldName}(\\s*[;=])`,
          'gi'
        );
        modifiedContent = modifiedContent.replace(declarationRegex, `$1${newName}$2`);

        const usageRegex = new RegExp(`\\b${oldName}\\b`, 'g');
        modifiedContent = modifiedContent.replace(usageRegex, newName);
      }

      // Add the fixed content to the first fix
      if (modifiedOutput.fixes.length > 0) {
        modifiedOutput.fixes[0] = {
          ...modifiedOutput.fixes[0],
          fixedContent: modifiedContent
        };
      }

      console.log(JSON.stringify(modifiedOutput, null, 2));
    } else {
      console.log(JSON.stringify(output, null, 2));
    }

    process.exit(0);

  } catch (error) {
    const output: PluginOutput = {
      violations: [],
      fixes: [],
      error: `Plugin execution failed: ${error instanceof Error ? error.message : String(error)}`
    };
    console.log(JSON.stringify(output, null, 2));
    process.exit(1);
  }
}

main();
