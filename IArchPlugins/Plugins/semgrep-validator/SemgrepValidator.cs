using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IArchitecture.Plugin.SDK.Models;
using IArchitecture.Plugin.SDK.Plugins;
using IArchitecture.Shared.Models.RuleGeneration;

namespace IArchitecture.SemgrepValidator;

/// <summary>
/// Plugin validator for executing Semgrep patterns against source files.
/// This plugin bridges .iarch rules with Semgrep's powerful AST-based pattern matching.
/// Now using native FFI library for significantly improved performance.
/// </summary>
public sealed class SemgrepValidator
{
    #region P/Invoke Declarations

    private const string LibName = "ffi_main";

    // Static constructor to set up library resolution
    static SemgrepValidator()
    {
        try
        {
            // Set up custom DLL resolver to find ffi_main.dll and dependencies
            System.Runtime.InteropServices.NativeLibrary.SetDllImportResolver(
                typeof(SemgrepValidator).Assembly, DllImportResolver);
        }
        catch
        {
            // If resolver setup fails, fall back to default behavior
        }
    }

    private static IntPtr DllImportResolver(string libraryName, System.Reflection.Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName == LibName)
        {
            // Try various paths
            string[] searchPaths = new[]
            {
                // Current directory (for test runner)
                Path.Combine(AppContext.BaseDirectory, "ffi_main.dll"),
                // Plugin directory (for deployed plugin)
                Path.Combine(Path.GetDirectoryName(assembly.Location) ?? "", "ffi", "ffi_main.dll"),
                // Fallback to plugin root
                Path.Combine(Path.GetDirectoryName(assembly.Location) ?? "", "ffi_main.dll")
            };

            foreach (var path in searchPaths)
            {
                if (File.Exists(path))
                {
                    if (_verbose) Console.WriteLine($"[SEMGREP-FFI] Attempting to load DLL from: {path}");
                    if (System.Runtime.InteropServices.NativeLibrary.TryLoad(path, out IntPtr handle))
                    {
                        if (_verbose) Console.WriteLine($"[SEMGREP-FFI] Successfully loaded DLL from: {path}");
                        return handle;
                    }
                }
            }

            if (_verbose) Console.WriteLine($"[SEMGREP-FFI] Failed to find ffi_main.dll in any search path");
        }

        return IntPtr.Zero;
    }

    /// <summary>
    /// Initialize the OCaml runtime. Must be called once at startup.
    /// This is idempotent - safe to call multiple times.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void semgrep_init();

    /// <summary>
    /// Scan multiple files with rules in a single batch.
    /// </summary>
    /// <param name="rules_yaml">YAML rules string</param>
    /// <param name="targets_json">JSON array of targets: {"targets": [{"path": "file.js", "language": "javascript"}]}</param>
    /// <param name="num_workers">Number of Semgrep internal workers (OCaml domains) for parallel file scanning (1-16)</param>
    /// <returns>Pointer to JSON result string</returns>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr semgrep_scan_batch(
        [MarshalAs(UnmanagedType.LPStr)] string rules_yaml,
        [MarshalAs(UnmanagedType.LPStr)] string targets_json,
        int num_workers);

    /// <summary>
    /// Get FFI wrapper version string.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr semgrep_ffi_version();

    #endregion

    #region Initialization & Thread Safety

    // Verbose logging flag - set via SEMGREP_VERBOSE environment variable
    private static readonly bool _verbose = Environment.GetEnvironmentVariable("SEMGREP_VERBOSE") == "1";

    // Thread safety lock - Serializes FFI calls to handle C# thread parallelism
    // OCaml runtime lock is acquired/released per call (caml_acquire/release_runtime_system)
    // This lock ensures only one C# thread calls into OCaml runtime at a time
    private static readonly object _semgrepLock = new object();
    private static bool _initialized = false;

    // YAML cache - stores generated YAML by (language, pattern hash) to avoid regeneration
    // Cache key format: "{language}:{sha256_hash_of_patterns_json}"
    // Uses Lazy<T> to ensure only ONE thread generates YAML when multiple threads race on same key
    private static readonly ConcurrentDictionary<string, Lazy<string>> _yamlCache = new();

    // Circuit breaker: Disable plugin after too many consecutive failures
    private static int _consecutiveFailures = 0;
    private static readonly int _maxConsecutiveFailures = 10;
    private static bool _circuitBreakerTripped = false;
    private static readonly object _circuitBreakerLock = new object();

    /// <summary>
    /// Initialize FFI library - called on first use of validator.
    /// Uses double-checked locking to avoid lock contention after initialization.
    /// </summary>
    private static void EnsureInitialized()
    {
        // Fast path - no lock needed after initialization
        if (_initialized)
            return;

        lock (_semgrepLock)
        {
            // Double-check inside lock in case another thread initialized while we waited
            if (!_initialized)
            {
                try
                {
                    if (_verbose) Console.WriteLine("[SEMGREP-FFI] Initializing Semgrep FFI library...");
                    semgrep_init();
                    _initialized = true;

                    var versionPtr = semgrep_ffi_version();
                    var version = Marshal.PtrToStringAnsi(versionPtr);
                    if (_verbose) Console.WriteLine($"[SEMGREP-FFI] Initialized successfully. Version: {version}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[SEMGREP-FFI] FATAL: Failed to initialize FFI library: {ex.Message}");
                    Console.WriteLine($"[SEMGREP-FFI] Stack trace: {ex.StackTrace}");
                    throw;
                }
            }
        }
    }

    /// <summary>
    /// Compute SHA256 hash of patterns JSON for cache key.
    /// </summary>
    private static string ComputePatternsHash(string patternsJson)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(patternsJson));
        return Convert.ToHexString(hashBytes).ToLower();
    }

    /// <summary>
    /// Call FFI with timeout protection to prevent hangs.
    /// </summary>
    private static async Task<string?> CallFFIWithTimeout(string yamlContent, string targetsJson, int numWorkers, int timeoutMs = 30000)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        try
        {
            var task = Task.Run(() =>
            {
                // NOTE: Removed C# lock - relying on OCaml's internal thread safety
                // The C code handles thread registration and locking via:
                //   caml_c_thread_register() + caml_acquire_runtime_system()
                var resultPtr = semgrep_scan_batch(yamlContent, targetsJson, numWorkers);
                return Marshal.PtrToStringAnsi(resultPtr);
            }, cts.Token);

            return await task;
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine($"[SEMGREP-FFI] ERROR: FFI call timed out after {timeoutMs}ms");
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SEMGREP-FFI] ERROR: FFI call threw exception: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Record success/failure for circuit breaker.
    /// </summary>
    private static void RecordSuccess()
    {
        lock (_circuitBreakerLock)
        {
            _consecutiveFailures = 0;
        }
    }

    /// <summary>
    /// Record failure and trip circuit breaker if threshold exceeded.
    /// </summary>
    private static void RecordFailure()
    {
        lock (_circuitBreakerLock)
        {
            _consecutiveFailures++;
            if (_consecutiveFailures >= _maxConsecutiveFailures)
            {
                _circuitBreakerTripped = true;
                Console.WriteLine($"[SEMGREP-FFI] CIRCUIT BREAKER TRIPPED after {_consecutiveFailures} failures - plugin disabled");
            }
        }
    }

    #endregion

    /// <summary>
    /// Plugin entry point for file-scoped execution - invoked by PluginExecutor via reflection.
    /// </summary>
    /// <param name="input">Plugin input containing file path, content, and semgrep patterns config</param>
    /// <returns>Plugin output with detected violations from Semgrep</returns>
    public async Task<PluginOutput> Execute(PluginInput input)
    {
        // Initialize FFI on first use
        EnsureInitialized();

        // Circuit breaker check - disable plugin if too many failures
        if (_circuitBreakerTripped)
        {
            return new PluginOutput
            {
                Error = $"Semgrep plugin disabled due to {_maxConsecutiveFailures} consecutive failures. Restart application to reset."
            };
        }

        try
        {
            // Log original source file being processed (helps identify slow files)
            if (_verbose)
            {
                Console.WriteLine($"[SEMGREP-FFI] Processing source file: {input.FilePath}");
            }

            // Skip non-production code (tests, build scripts, tooling, dependencies)
            // These files don't benefit from SAST scanning
            var lowerPath = input.FilePath.ToLowerInvariant();
            if (lowerPath.Contains("\\node_modules\\") ||
                lowerPath.Contains("\\dist\\") ||
                lowerPath.Contains("\\build\\") ||
                lowerPath.Contains("\\out\\") ||
                lowerPath.Contains("\\__tests__\\") ||
                lowerPath.Contains("\\__mocks__\\") ||
                lowerPath.Contains("\\tests\\") ||
                lowerPath.Contains("\\test\\") ||
                lowerPath.Contains("\\scripts\\") ||
                lowerPath.Contains("\\tools\\") ||
                lowerPath.Contains("\\config\\") ||
                lowerPath.Contains("\\vendor\\") ||
                lowerPath.Contains("\\third_party\\") ||
                lowerPath.Contains("\\.storybook\\") ||
                lowerPath.EndsWith(".min.js") ||
                lowerPath.EndsWith(".bundle.js") ||
                lowerPath.EndsWith(".test.js") ||
                lowerPath.EndsWith(".spec.js"))
            {
                if (_verbose) Console.WriteLine($"[SEMGREP-FFI] Skipping non-production code: {input.FilePath}");
                return new PluginOutput { Violations = new List<PluginViolation>() };
            }

            // Skip large files (>500KB - likely minified/generated)
            var fileInfo = new FileInfo(input.FilePath);
            if (fileInfo.Length > 500_000)
            {
                if (_verbose) Console.WriteLine($"[SEMGREP-FFI] Skipping large file ({fileInfo.Length} bytes): {input.FilePath}");
                return new PluginOutput { Violations = new List<PluginViolation>() };
            }

            if (!input.Config.TryGetValue("semgrep_patterns", out var patternsJson))
            {
                return new PluginOutput
                {
                    Error = "Plugin requires 'semgrep_patterns' in CONFIG. Check .iarch rule."
                };
            }

            var patterns = DeserializePatterns(patternsJson);
            if (patterns == null || patterns.Count == 0)
            {
                return new PluginOutput
                {
                    Error = "Failed to deserialize semgrep_patterns or patterns are empty."
                };
            }

            var language = DetermineLanguage(input.FilePath, patterns);
            if (language == null)
            {
                return new PluginOutput { Violations = new List<PluginViolation>() };
            }

            if (!patterns.TryGetValue(language, out var languagePatterns))
            {
                return new PluginOutput { Violations = new List<PluginViolation>() };
            }

            // Get Semgrep internal worker count from config (defaults to 1)
            var numWorkers = 1;
            if (input.Config.TryGetValue("semgrep_num_workers", out var numWorkersStr))
            {
                if (int.TryParse(numWorkersStr, out var parsed) && parsed > 0 && parsed <= 16)
                {
                    numWorkers = parsed;
                }
            }

            // Semgrep requires files to exist on disk - write FileContent buffer to temp file
            // Target.ml asserts file must be a regular file (UFile.is_reg check)
            var scanPath = Path.Combine(Path.GetTempPath(), $"semgrep_{Guid.NewGuid()}{Path.GetExtension(input.FilePath)}");
            File.WriteAllText(scanPath, input.FileContent);

            try
            {
                var violations = await ExecuteSemgrepFFI(scanPath, language, languagePatterns, patternsJson, numWorkers);

                return new PluginOutput
                {
                    Violations = violations
                };
            }
            finally
            {
                if (File.Exists(scanPath))
                {
                    File.Delete(scanPath);
                }
            }
        }
        catch (Exception ex)
        {
            return new PluginOutput
            {
                Error = $"Semgrep FFI plugin execution failed: {ex.Message}\n{ex.StackTrace}"
            };
        }
    }

    /// <summary>
    /// Plugin entry point for batch execution - processes multiple files in a single FFI call.
    /// Significantly more efficient than calling Execute() per file due to reduced FFI overhead.
    /// </summary>
    /// <param name="input">Batch input containing multiple files with shared language and config</param>
    /// <returns>Batch output with per-file results</returns>
    public async Task<BatchPluginOutput> ExecuteBatch(BatchPluginInput input)
    {
        // Initialize FFI on first use
        EnsureInitialized();

        // Circuit breaker check
        if (_circuitBreakerTripped)
        {
            return new BatchPluginOutput
            {
                Results = Array.Empty<FilePluginOutput>(),
                Error = $"Semgrep plugin disabled due to {_maxConsecutiveFailures} consecutive failures. Restart application to reset."
            };
        }

        var batchStopwatch = Stopwatch.StartNew();
        var timingStopwatch = Stopwatch.StartNew();

        try
        {
            Console.WriteLine($"[SEMGREP-FFI] Processing batch of {input.Files.Count} {input.Language} files");

            // Get rules list (new format) - contains multiple rules with IDs and patterns
            if (!input.Config.TryGetValue("semgrep_rules", out var rulesJson))
            {
                return new BatchPluginOutput
                {
                    Results = Array.Empty<FilePluginOutput>(),
                    Error = "Plugin requires 'semgrep_rules' in CONFIG (new format)."
                };
            }

            var rulesWithPatterns = JsonSerializer.Deserialize<List<Dictionary<string, string>>>(rulesJson);
            if (rulesWithPatterns == null || rulesWithPatterns.Count == 0)
            {
                Console.WriteLine($"[SEMGREP-FFI] ERROR: Failed to deserialize semgrep_rules. RulesJson length: {rulesJson?.Length ?? 0}");
                return new BatchPluginOutput
                {
                    Results = Array.Empty<FilePluginOutput>(),
                    Error = "Failed to deserialize semgrep_rules or rules are empty."
                };
            }

            Console.WriteLine($"[SEMGREP-FFI] Received {rulesWithPatterns.Count} rules from engine");

            var language = input.Language;

            // Extract and validate patterns for each rule
            var validRules = new List<(string RuleId, Dictionary<string, List<DetectionPattern>> Patterns)>();

            foreach (var ruleEntry in rulesWithPatterns)
            {
                if (!ruleEntry.TryGetValue("ruleId", out var ruleId) ||
                    !ruleEntry.TryGetValue("patterns", out var patternsJson))
                {
                    continue;
                }

                var patterns = DeserializePatterns(patternsJson);
                if (patterns != null && patterns.TryGetValue(language, out var languagePatterns))
                {
                    validRules.Add((ruleId, patterns));
                }
            }

            Console.WriteLine($"[SEMGREP-FFI] After filtering for {language}: {validRules.Count} valid rules");

            if (validRules.Count == 0)
            {
                Console.WriteLine($"[SEMGREP-FFI] No patterns for language {language} - returning empty results");
                // No patterns for this language - return empty results for all files
                return new BatchPluginOutput
                {
                    Results = input.Files.Select(f => new FilePluginOutput
                    {
                        FilePath = f.FilePath,
                        Violations = new List<PluginViolation>()
                    }).ToList()
                };
            }

            // Get Semgrep internal worker count from config
            var numWorkers = 9; // Default for batching
            if (input.Config.TryGetValue("semgrep_num_workers", out var numWorkersStr))
            {
                if (int.TryParse(numWorkersStr, out var parsed) && parsed > 0 && parsed <= 16)
                {
                    numWorkers = parsed;
                }
            }

            Console.WriteLine($"[SEMGREP-FFI] Batch execution config: numWorkers={numWorkers} (Semgrep internal parallelism)");

            // Write all files to temp directory
            var tempDir = Path.Combine(Path.GetTempPath(), $"semgrep_batch_{Guid.NewGuid()}");
            Directory.CreateDirectory(tempDir);

            var tempFilePaths = new List<(string OriginalPath, string TempPath)>();
            try
            {
                // === TIMING: File Write ===
                timingStopwatch.Restart();
                foreach (var file in input.Files)
                {
                    var tempPath = Path.Combine(tempDir, Path.GetFileName(file.FilePath));
                    File.WriteAllText(tempPath, file.FileContent);
                    tempFilePaths.Add((file.FilePath, tempPath));
                }
                var fileWriteTime = timingStopwatch.ElapsedMilliseconds;

                // === TIMING: YAML Cache Lookup/Generation ===
                timingStopwatch.Restart();
                // Cache key based on all rules' patterns
                var cacheKey = $"{language}:{ComputePatternsHash(rulesJson)}";
                var lazyYaml = _yamlCache.GetOrAdd(cacheKey, _ => new Lazy<string>(() =>
                {
                    if (_verbose) Console.WriteLine($"[SEMGREP-FFI] Cache miss - generating YAML for batch (key: {cacheKey})");
                    var yaml = GenerateSemgrepYamlMultiRule(language, validRules);
                    Console.WriteLine($"[SEMGREP-FFI] Generated YAML with {yaml.Split("- id:").Length - 1} rules");

                    // DEBUG: Write YAML to temp file for inspection
                    var yamlDebugPath = Path.Combine(Path.GetTempPath(), "semgrep_debug_batch.yaml");
                    File.WriteAllText(yamlDebugPath, yaml);
                    Console.WriteLine($"[SEMGREP-FFI] YAML written to: {yamlDebugPath}");

                    return yaml;
                }));
                var yamlContent = lazyYaml.Value;
                var yamlCacheTime = timingStopwatch.ElapsedMilliseconds;

                // === TIMING: Targets JSON Creation ===
                timingStopwatch.Restart();
                var targetsJson = JsonSerializer.Serialize(new
                {
                    targets = tempFilePaths.Select(t => new
                    {
                        path = t.TempPath,
                        language = language
                    }).ToArray()
                });
                var jsonCreateTime = timingStopwatch.ElapsedMilliseconds;

                if (_verbose)
                {
                    Console.WriteLine($"[SEMGREP-FFI] Batch targets JSON: {targetsJson}");
                }

                // === TIMING: FFI Call (includes lock wait + OCaml execution) ===
                timingStopwatch.Restart();
                var resultJson = await CallFFIWithTimeout(yamlContent, targetsJson, numWorkers, timeoutMs: 60000);
                var ffiCallTime = timingStopwatch.ElapsedMilliseconds;

                if (string.IsNullOrWhiteSpace(resultJson))
                {
                    Console.WriteLine($"[SEMGREP-FFI] ERROR: Batch FFI returned empty/null/timeout result");
                    RecordFailure();
                    return new BatchPluginOutput
                    {
                        Results = input.Files.Select(f => new FilePluginOutput
                        {
                            FilePath = f.FilePath,
                            Violations = new List<PluginViolation>()
                        }).ToList()
                    };
                }

                // === TIMING: JSON Parsing ===
                timingStopwatch.Restart();
                var options = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
                    PropertyNameCaseInsensitive = true
                };
                var results = JsonSerializer.Deserialize<SemgrepResults>(resultJson, options);
                var jsonParseTime = timingStopwatch.ElapsedMilliseconds;

                if (_verbose) Console.WriteLine($"[SEMGREP-FFI] Batch violations found: {results?.Results?.Count ?? 0}");

                // === TIMING: Violation Mapping ===
                timingStopwatch.Restart();
                var violationsByFile = new Dictionary<string, List<PluginViolation>>();
                foreach (var tempPath in tempFilePaths)
                {
                    violationsByFile[tempPath.TempPath] = new List<PluginViolation>();
                }

                if (results?.Results != null)
                {
                    foreach (var result in results.Results)
                    {
                        var filePath = result.Path;
                        if (filePath != null && violationsByFile.ContainsKey(filePath))
                        {
                            violationsByFile[filePath].Add(new PluginViolation
                            {
                                Id = result.CheckId ?? "SEMGREP-UNKNOWN",
                                Message = result.Extra?.Message ?? "Semgrep violation detected",
                                Line = result.Start?.Line ?? 0,
                                Severity = MapSeverity(result.Extra?.Severity ?? "WARNING"),
                                Snippet = result.Extra?.Lines ?? ""
                            });
                        }
                    }
                }

                // Map back to original file paths
                var fileOutputs = tempFilePaths.Select(t => new FilePluginOutput
                {
                    FilePath = t.OriginalPath,
                    Violations = violationsByFile[t.TempPath]
                }).ToList();
                var mappingTime = timingStopwatch.ElapsedMilliseconds;

                // === TIMING SUMMARY ===
                batchStopwatch.Stop();
                var totalTime = batchStopwatch.ElapsedMilliseconds;
                var avgPerFile = input.Files.Count > 0 ? (double)totalTime / input.Files.Count : 0;
                var totalViolations = fileOutputs.Sum(f => f.Violations.Count);

                Console.WriteLine($"[SEMGREP-BATCH-TIMING] {input.Language} batch ({input.Files.Count} files) | Total: {totalTime}ms | Avg: {avgPerFile:F1}ms/file | Write: {fileWriteTime}ms | YAML: {yamlCacheTime}ms | JSON: {jsonCreateTime}ms | FFI: {ffiCallTime}ms | Parse: {jsonParseTime}ms | Map: {mappingTime}ms | Violations: {totalViolations}");

                RecordSuccess();

                return new BatchPluginOutput
                {
                    Results = fileOutputs
                };
            }
            finally
            {
                // Clean up temp files
                try
                {
                    if (Directory.Exists(tempDir))
                    {
                        Directory.Delete(tempDir, recursive: true);
                    }
                }
                catch
                {
                    // Best effort cleanup
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SEMGREP-FFI] Batch execution error: {ex.Message}");
            RecordFailure();
            return new BatchPluginOutput
            {
                Results = Array.Empty<FilePluginOutput>(),
                Error = $"Semgrep batch execution failed: {ex.Message}"
            };
        }
    }

    private Dictionary<string, List<DetectionPattern>>? DeserializePatterns(string patternsJson)
    {
        try
        {
            // The JSON comes pre-escaped from the .iarch file (e.g., {\"go\":...)
            // We need to unescape it first by deserializing as a string, then deserializing the result
            var unescapedJson = JsonSerializer.Deserialize<string>($"\"{patternsJson}\"");
            if (string.IsNullOrEmpty(unescapedJson))
                return null;

            return JsonSerializer.Deserialize<Dictionary<string, List<DetectionPattern>>>(unescapedJson);
        }
        catch
        {
            return null;
        }
    }

    private string? DetermineLanguage(string filePath, Dictionary<string, List<DetectionPattern>> patterns)
    {
        var extension = Path.GetExtension(filePath).ToLower();

        var extensionMap = new Dictionary<string, string>
        {
            [".py"] = "python",
            [".js"] = "javascript",
            [".ts"] = "typescript",
            [".jsx"] = "javascript",
            [".tsx"] = "typescript",
            [".go"] = "go",
            [".java"] = "java",
            [".c"] = "c",
            [".cpp"] = "cpp",
            [".cc"] = "cpp",
            [".cxx"] = "cpp",
            [".cs"] = "csharp",
            [".csx"] = "csharp",
            [".rs"] = "rust",
            [".rb"] = "ruby",
            [".php"] = "php"
        };

        if (extensionMap.TryGetValue(extension, out var language) && patterns.ContainsKey(language))
        {
            return language;
        }

        return null;
    }

    /// <summary>
    /// Execute Semgrep scan via FFI library (native DLL).
    /// This replaces the previous CLI-based implementation for significantly better performance.
    ///
    /// Performance: ~2-5ms per file (vs 100-500ms with CLI process spawn)
    ///
    /// Parallelism: Supports both C# thread parallelism (via engine) and Semgrep internal
    /// parallelism (via num_workers). Configure via 'semgrep_num_workers' in CONFIG.
    /// </summary>
    private async Task<List<PluginViolation>> ExecuteSemgrepFFI(string filePath, string language, List<DetectionPattern> patterns, string patternsJson, int numWorkers = 1)
    {
        var violations = new List<PluginViolation>();
        var totalStopwatch = Stopwatch.StartNew();
        var sw = Stopwatch.StartNew();

        try
        {
            // === TIMING: YAML Cache Lookup/Generation ===
            sw.Restart();

            // Check YAML cache first - cache by (language, pattern hash)
            // Lazy<T> ensures only ONE thread generates YAML even when multiple threads race on same key
            var cacheKey = $"{language}:{ComputePatternsHash(patternsJson)}";
            var lazyYaml = _yamlCache.GetOrAdd(cacheKey, _ => new Lazy<string>(() =>
            {
                if (_verbose) Console.WriteLine($"[SEMGREP-FFI] Cache miss - generating YAML for cache key: {cacheKey}");
                return GenerateSemgrepYaml(language, patterns, Path.GetFileName(filePath));
            }));

            // Only one thread executes the Lazy factory, others wait for result
            var yamlContent = lazyYaml.Value;

            var yamlCacheTime = sw.ElapsedMilliseconds;

            if (_yamlCache.ContainsKey(cacheKey))
            {
                if (_verbose) Console.WriteLine($"[SEMGREP-FFI] Cache hit for {filePath} (key: {cacheKey})");
            }

            if (_verbose)
            {
                Console.WriteLine($"[SEMGREP-FFI] Using YAML for {filePath}:");
                Console.WriteLine(yamlContent);
            }

            // === TIMING: Targets JSON Creation ===
            sw.Restart();

            // Create targets JSON for FFI
            var targetsJson = JsonSerializer.Serialize(new
            {
                targets = new[]
                {
                    new
                    {
                        path = filePath,
                        language = language
                    }
                }
            });

            var jsonCreateTime = sw.ElapsedMilliseconds;

            if (_verbose) Console.WriteLine($"[SEMGREP-FFI] Targets JSON: {targetsJson}");

            // Log file being scanned (BEFORE FFI call, in case it hangs)
            // Only log every 100th file to reduce noise, but ALWAYS log if verbose
            if (_verbose || (filePath.GetHashCode() % 100 == 0))
            {
                Console.WriteLine($"[SEMGREP-FFI] Scanning: {filePath}");
            }

            // === TIMING: FFI Call (includes lock wait + OCaml execution) ===
            sw.Restart();

            // Call FFI library with timeout protection (30 second timeout)
            // OCaml runtime handles thread safety via caml_acquire/release_runtime_system
            // Multiple C# threads can call simultaneously, OCaml serializes access to its runtime
            var resultJson = await CallFFIWithTimeout(yamlContent, targetsJson, numWorkers, timeoutMs: 30000);

            var ffiCallTime = sw.ElapsedMilliseconds;
            totalStopwatch.Stop();

            // Validate FFI result before parsing
            if (string.IsNullOrWhiteSpace(resultJson))
            {
                Console.WriteLine($"[SEMGREP-FFI] ERROR: FFI returned empty/null/timeout result for {filePath}");
                Console.WriteLine($"[SEMGREP-FFI] This may indicate OCaml runtime crash, timeout, or memory corruption");
                RecordFailure(); // Circuit breaker
                return violations; // Return empty list
            }

            if (_verbose)
            {
                Console.WriteLine($"[SEMGREP-FFI] Result JSON length: {resultJson.Length}");
                Console.WriteLine($"[SEMGREP-FFI] Result JSON sample: {resultJson.Substring(0, Math.Min(500, resultJson.Length))}");
            }

            // === TIMING: JSON Parsing ===
            sw.Restart();

            // Parse results (same as before)
            var options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
                PropertyNameCaseInsensitive = true
            };
            var results = JsonSerializer.Deserialize<SemgrepResults>(resultJson, options);

            var jsonParseTime = sw.ElapsedMilliseconds;

            if (_verbose) Console.WriteLine($"[SEMGREP-FFI] Violations found: {results?.Results?.Count ?? 0} in {filePath}");

            // === TIMING: Violation Mapping ===
            sw.Restart();

            // Map to violations (same as before)
            if (results?.Results != null)
            {
                foreach (var result in results.Results)
                {
                    violations.Add(new PluginViolation
                    {
                        Id = result.CheckId ?? "SEMGREP-UNKNOWN",
                        Message = result.Extra?.Message ?? "Semgrep violation detected",
                        Line = result.Start?.Line ?? 0,
                        Severity = MapSeverity(result.Extra?.Severity ?? "WARNING"),
                        Snippet = result.Extra?.Lines ?? ""
                    });
                }
            }

            var mappingTime = sw.ElapsedMilliseconds;

            // === TIMING SUMMARY ===
            var totalTime = totalStopwatch.ElapsedMilliseconds;
            Console.WriteLine($"[SEMGREP-TIMING] {Path.GetFileName(filePath)} | Total: {totalTime}ms | YAML: {yamlCacheTime}ms | JSON: {jsonCreateTime}ms | FFI: {ffiCallTime}ms | Parse: {jsonParseTime}ms | Map: {mappingTime}ms | Violations: {violations.Count}");

            // Scan completed successfully
            RecordSuccess();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SEMGREP-FFI] Error during scan: {ex.Message}");
            Console.WriteLine($"[SEMGREP-FFI] Stack trace: {ex.StackTrace}");

            // Record failure for circuit breaker
            RecordFailure();

            // Don't throw - return empty violations and log error
            // This allows the scanner to continue with other files
        }

        return violations;
    }

    /// <summary>
    /// Generate YAML with multiple semgrep rules (one per .iarch rule) for batch processing.
    /// Each semgrep rule uses the .iarch rule ID so CheckId matches.
    /// </summary>
    private string GenerateSemgrepYamlMultiRule(string language, List<(string RuleId, Dictionary<string, List<DetectionPattern>> Patterns)> rules)
    {
        var yaml = "rules:\n";

        foreach (var (ruleId, patterns) in rules)
        {
            if (!patterns.TryGetValue(language, out var languagePatterns) || languagePatterns.Count == 0)
            {
                continue;
            }

            // Generate one semgrep rule per .iarch rule, using the .iarch rule ID
            yaml += $"  - id: {ruleId}\n";
            yaml += $"    languages: [{language}]\n";
            yaml += $"    message: Detected violation\n";
            yaml += "    severity: WARNING\n";

            // Check if we have taint mode patterns
            var hasTaintSource = languagePatterns.Any(p => p.Type == PatternType.TaintSource);
            var hasTaintSink = languagePatterns.Any(p => p.Type == PatternType.TaintSink);

            if (hasTaintSource && hasTaintSink)
            {
                // Generate taint mode YAML
                yaml += "    mode: taint\n";
                yaml += "    pattern-sources:\n";

                foreach (var pattern in languagePatterns.Where(p => p.Type == PatternType.TaintSource))
                {
                    yaml += GeneratePatternYaml(pattern, indent: 6, isTaintMode: true);
                }

                yaml += "    pattern-sinks:\n";

                foreach (var pattern in languagePatterns.Where(p => p.Type == PatternType.TaintSink))
                {
                    yaml += GeneratePatternYaml(pattern, indent: 6, isTaintMode: true);
                }
            }
            else
            {
                // Generate standard pattern YAML
                if (languagePatterns.Count == 1)
                {
                    yaml += GeneratePatternYaml(languagePatterns[0], indent: 4, isTaintMode: false, isListItem: false);
                }
                else if (languagePatterns.Count > 1)
                {
                    yaml += "    pattern-either:\n";
                    foreach (var pattern in languagePatterns)
                    {
                        yaml += GeneratePatternYaml(pattern, indent: 6, isTaintMode: false);
                    }
                }
            }
        }

        return yaml;
    }

    private string GenerateSemgrepYaml(string language, List<DetectionPattern> patterns, string fileName)
    {
        var yaml = "rules:\n";
        yaml += $"  - id: semgrep-check-{fileName}\n";
        yaml += $"    languages: [{language}]\n";
        yaml += $"    message: Detected violation\n";
        yaml += "    severity: WARNING\n";

        // Check if we have taint mode patterns
        var hasTaintSource = patterns.Any(p => p.Type == PatternType.TaintSource);
        var hasTaintSink = patterns.Any(p => p.Type == PatternType.TaintSink);

        if (hasTaintSource && hasTaintSink)
        {
            // Generate taint mode YAML
            yaml += "    mode: taint\n";
            yaml += "    pattern-sources:\n";

            foreach (var pattern in patterns.Where(p => p.Type == PatternType.TaintSource))
            {
                yaml += GeneratePatternYaml(pattern, indent: 6, isTaintMode: true);
            }

            yaml += "    pattern-sinks:\n";

            foreach (var pattern in patterns.Where(p => p.Type == PatternType.TaintSink))
            {
                yaml += GeneratePatternYaml(pattern, indent: 6, isTaintMode: true);
            }
        }
        else
        {
            // Generate standard pattern YAML
            if (patterns.Count == 1)
            {
                // CHANGE 2026-01-17: Single top-level pattern should not be a list item (no dash)
                // If this breaks existing rules, revert by changing isListItem back to true
                yaml += GeneratePatternYaml(patterns[0], indent: 4, isTaintMode: false, isListItem: false);
            }
            else if (patterns.Count > 1)
            {
                // Multiple patterns at top level - wrap in pattern-either
                yaml += "    pattern-either:\n";
                foreach (var pattern in patterns)
                {
                    yaml += GeneratePatternYaml(pattern, indent: 6, isTaintMode: false);
                }
            }
        }

        return yaml;
    }

    /// <summary>
    /// Recursively generate YAML for a DetectionPattern tree node.
    /// </summary>
    /// <param name="isListItem">ADDED 2026-01-17: Controls dash prefix. True for list items, false for single top-level patterns.</param>
    private string GeneratePatternYaml(DetectionPattern pattern, int indent, bool isTaintMode, bool isListItem = true)
    {
        var yaml = "";
        var indentStr = new string(' ', indent);

        switch (pattern.Type)
        {
            case PatternType.Pattern:
                // Simple pattern: pattern: "..."
                if (!string.IsNullOrEmpty(pattern.Pattern))
                {
                    // CHANGE 2026-01-17: Use dash prefix only for list items
                    var prefix = isListItem ? "- " : "";
                    if (pattern.Pattern.Contains('\n'))
                    {
                        yaml += $"{indentStr}{prefix}pattern: |\n";
                        foreach (var line in pattern.Pattern.Split('\n'))
                        {
                            yaml += $"{indentStr}    {line}\n";
                        }
                    }
                    else
                    {
                        yaml += $"{indentStr}{prefix}pattern: {QuoteYamlValue(pattern.Pattern)}\n";
                    }
                }
                break;

            case PatternType.PatternInside:
                // Pattern-inside: pattern-inside: "..."
                if (!string.IsNullOrEmpty(pattern.Pattern))
                {
                    // CHANGE 2026-01-17: Use dash prefix only for list items
                    var prefix = isListItem ? "- " : "";
                    if (pattern.Pattern.Contains('\n'))
                    {
                        yaml += $"{indentStr}{prefix}pattern-inside: |\n";
                        foreach (var line in pattern.Pattern.Split('\n'))
                        {
                            yaml += $"{indentStr}    {line}\n";
                        }
                    }
                    else
                    {
                        yaml += $"{indentStr}{prefix}pattern-inside: {QuoteYamlValue(pattern.Pattern)}\n";
                    }
                }
                break;

            case PatternType.PatternEither:
                // Pattern-either: list of alternatives
                if (pattern.Children != null && pattern.Children.Count > 0)
                {
                    // If we're at taint mode top level, each child is a separate entry
                    if (isTaintMode)
                    {
                        foreach (var child in pattern.Children)
                        {
                            yaml += GeneratePatternYaml(child, indent, isTaintMode: false);
                        }
                    }
                    else
                    {
                        yaml += $"{indentStr}- pattern-either:\n";
                        foreach (var child in pattern.Children)
                        {
                            yaml += GeneratePatternYaml(child, indent + 4, isTaintMode: false);
                        }
                    }
                }
                break;

            case PatternType.Patterns:
                // Patterns (AND): list where all must match
                if (pattern.Children != null && pattern.Children.Count > 0)
                {
                    // If we're at taint mode top level, unwrap and generate each child as separate entry
                    if (isTaintMode)
                    {
                        foreach (var child in pattern.Children)
                        {
                            yaml += GeneratePatternYaml(child, indent, isTaintMode: false);
                        }
                    }
                    else
                    {
                        yaml += $"{indentStr}- patterns:\n";
                        foreach (var child in pattern.Children)
                        {
                            yaml += GeneratePatternYaml(child, indent + 4, isTaintMode: false);
                        }
                    }
                }
                break;

            case PatternType.TaintSource:
            case PatternType.TaintSink:
                // Taint source/sink wrapper - unwrap and generate children
                if (pattern.Children != null && pattern.Children.Count > 0)
                {
                    foreach (var child in pattern.Children)
                    {
                        yaml += GeneratePatternYaml(child, indent, isTaintMode: true);
                    }
                }
                break;
        }

        return yaml;
    }

    /// <summary>
    /// Quote YAML values that contain special characters or need escaping.
    /// </summary>
    private string QuoteYamlValue(string value)
    {
        // Always quote if contains special YAML characters or internal quotes
        bool needsQuoting = value.Contains("%") || value.Contains("+") || value.Contains("*") ||
                           value.Contains("#") || value.Contains(":") || value.Contains("{") ||
                           value.Contains("}") || value.Contains("[") || value.Contains("]") ||
                           value.Contains("\"") || value.Contains("'") || value.Contains(".");

        if (!needsQuoting)
        {
            return value;
        }

        // Use single quotes to avoid escaping issues with double quotes in patterns
        // Escape single quotes by doubling them
        var escaped = value.Replace("'", "''");
        return $"'{escaped}'";
    }

    private string MapSeverity(string semgrepSeverity)
    {
        return semgrepSeverity.ToUpper() switch
        {
            "ERROR" => "Fatal",
            "WARNING" => "Warning",
            "INFO" => "Info",
            _ => "Warning"
        };
    }
}

// SemgrepPattern removed - now using DetectionPattern from IArchitecture.Shared.Models.RuleGeneration

public class SemgrepResults
{
    public List<SemgrepResult>? Results { get; set; }
}

public class SemgrepResult
{
    public string? Path { get; set; }
    public string? CheckId { get; set; }
    public SemgrepLocation? Start { get; set; }
    public SemgrepExtra? Extra { get; set; }
}

public class SemgrepLocation
{
    public int Line { get; set; }
}

public class SemgrepExtra
{
    public string? Message { get; set; }
    public string? Severity { get; set; }
    public string? Lines { get; set; }
}
