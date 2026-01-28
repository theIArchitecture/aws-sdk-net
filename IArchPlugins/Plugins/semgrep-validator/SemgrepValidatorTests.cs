using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using IArchitecture.Plugin.SDK.Models;
using IArchitecture.Plugin.SDK.Plugins;
using IArchitecture.Shared.Models.RuleGeneration;
using Xunit;

namespace IArchitecture.SemgrepValidator.Tests;

/// <summary>
/// Unit tests for Semgrep FFI plugin integration.
/// Tests the SemgrepValidator plugin directly without going through the full .iarch system.
/// </summary>
public class SemgrepValidatorTests
{
    [Fact]
    public void FFI_DLLs_ShouldExist()
    {
        // Arrange
        var currentDir = Directory.GetCurrentDirectory();
        var ffiMainDll = Path.Combine(currentDir, "ffi_main.dll");
        var libstdcDll = Path.Combine(currentDir, "libstdc++-6.dll");

        // Assert
        Assert.True(File.Exists(ffiMainDll), $"ffi_main.dll should exist at {ffiMainDll}");
        Assert.True(File.Exists(libstdcDll), $"libstdc++-6.dll should exist at {libstdcDll}");
    }

    [Fact]
    public async Task Execute_WithConsoleLogPattern_ShouldDetectViolations()
    {
        // Arrange - Create test JavaScript file
        var testFile = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.js");
        var jsCode = @"// Test file for Semgrep FFI
function doSomething() {
    console.log('Debug message');  // Should be detected
    const result = calculate();
    console.log('Result:', result); // Should be detected
    return result;
}

function calculate() {
    return 42;
}
";
        File.WriteAllText(testFile, jsCode);

        try
        {
            // Create Semgrep patterns for console.log
            var patterns = new Dictionary<string, List<DetectionPattern>>
            {
                ["javascript"] = new List<DetectionPattern>
                {
                    new DetectionPattern
                    {
                        Name = "CONSOLE_LOG",
                        Type = PatternType.Pattern,
                        Pattern = "console.log(...)"
                    }
                }
            };

            // Serialize and escape JSON (simulates .iarch file format)
            var patternsJson = JsonSerializer.Serialize(patterns);
            var escapedPatternsJson = JsonSerializer.Serialize(patternsJson);
            escapedPatternsJson = escapedPatternsJson.Substring(1, escapedPatternsJson.Length - 2);

            // Create plugin input
            var input = new PluginInput
            {
                FilePath = testFile,
                FileContent = jsCode,
                Language = "javascript",
                Config = new Dictionary<string, string>
                {
                    ["semgrep_patterns"] = escapedPatternsJson
                }
            };

            // Act - Execute plugin
            var validator = new SemgrepValidator();
            var output = await validator.Execute(input);

            // Assert
            Assert.Null(output.Error);
            Assert.NotNull(output.Violations);
            Assert.NotEmpty(output.Violations);
            Assert.Equal(2, output.Violations.Count); // Should detect 2 console.log statements
            Assert.All(output.Violations, v => Assert.True(v.Line > 0));
        }
        finally
        {
            // Cleanup
            if (File.Exists(testFile))
            {
                File.Delete(testFile);
            }
        }
    }

    [Fact]
    public async Task Execute_Performance_ShouldComplete10ScansInReasonableTime()
    {
        // Arrange
        var testFile = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.js");
        var jsCode = "console.log('test');";
        File.WriteAllText(testFile, jsCode);

        try
        {
            var patterns = new Dictionary<string, List<DetectionPattern>>
            {
                ["javascript"] = new List<DetectionPattern>
                {
                    new DetectionPattern
                    {
                        Name = "CONSOLE_LOG",
                        Type = PatternType.Pattern,
                        Pattern = "console.log(...)"
                    }
                }
            };

            var patternsJson = JsonSerializer.Serialize(patterns);
            var escapedPatternsJson = JsonSerializer.Serialize(patternsJson);
            escapedPatternsJson = escapedPatternsJson.Substring(1, escapedPatternsJson.Length - 2);

            var input = new PluginInput
            {
                FilePath = testFile,
                FileContent = jsCode,
                Language = "javascript",
                Config = new Dictionary<string, string>
                {
                    ["semgrep_patterns"] = escapedPatternsJson
                }
            };

            var validator = new SemgrepValidator();

            // Act - Run 10 scans and measure time
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            for (int i = 0; i < 10; i++)
            {
                await validator.Execute(input);
            }
            stopwatch.Stop();

            // Assert - Should complete in reasonable time
            var avgMs = stopwatch.ElapsedMilliseconds / 10.0;
            Assert.True(avgMs < 500, $"Average scan time should be < 500ms, was {avgMs:F2}ms");
        }
        finally
        {
            if (File.Exists(testFile))
            {
                File.Delete(testFile);
            }
        }
    }

    [Fact]
    public async Task Execute_WithEmptyConfig_ShouldReturnError()
    {
        // Arrange - Use proper temp file path
        var testFile = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.js");
        File.WriteAllText(testFile, "console.log('test');");

        try
        {
            var input = new PluginInput
            {
                FilePath = testFile,
                FileContent = "console.log('test');",
                Language = "javascript",
                Config = new Dictionary<string, string>() // Empty config
            };

            // Act
            var validator = new SemgrepValidator();
            var output = await validator.Execute(input);

            // Assert - Should have error about missing patterns
            Assert.NotNull(output.Error);
            Assert.Contains("semgrep_patterns", output.Error);
        }
        finally
        {
            if (File.Exists(testFile))
            {
                File.Delete(testFile);
            }
        }
    }
}
