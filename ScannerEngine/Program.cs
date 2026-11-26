using System.Text.Json;
using System.Text.Json.Serialization;
using ScannerEngine;

try
{
    var options = ParseOptions(args);
    var sampleDirectory = Path.Combine(AppContext.BaseDirectory, "SampleScans");
    var semgrepPath = options.GetValueOrDefault("--semgrep") ?? Path.Combine(sampleDirectory, "semgrep.json");
    var gitleaksPath = options.GetValueOrDefault("--gitleaks") ?? Path.Combine(sampleDirectory, "gitleaks.json");
    var trivyPath = options.GetValueOrDefault("--trivy") ?? Path.Combine(sampleDirectory, "trivy.json");
    var outputPath = Path.GetFullPath(options.GetValueOrDefault("--output")
        ?? Path.Combine("Dashboard", "security-report.json"));
    Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? Directory.GetCurrentDirectory());

    var findings = SecurityReportParser.Parse(semgrepPath, gitleaksPath, trivyPath);
    var report = SecurityReportParser.BuildReport(findings);
    var jsonOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };
    jsonOptions.Converters.Add(new JsonStringEnumConverter());
    await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, jsonOptions));

    Console.WriteLine($"Wrote {report.TotalFindings} findings to {outputPath}");
    if (options.TryGetValue("--fail-on", out var failOn))
    {
        var severities = failOn.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(value => value.ToUpperInvariant()).ToHashSet(StringComparer.Ordinal);
        var blocking = findings.Where(f => severities.Contains(f.Severity)).ToArray();
        if (blocking.Length > 0)
        {
            Console.Error.WriteLine($"Build blocked: {blocking.Length} finding(s) at {string.Join(", ", severities)} severity.");
            return 1;
        }
    }

    return 0;
}
catch (Exception exception)
{
    Console.Error.WriteLine($"Scanner report generation failed: {exception.Message}");
    return 2;
}

static Dictionary<string, string> ParseOptions(string[] arguments)
{
    var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var index = 0; index < arguments.Length; index++)
    {
        if (arguments[index] is "-h" or "--help")
        {
            Console.WriteLine("Usage: ScannerEngine [--semgrep path] [--gitleaks path] [--trivy path] [--output path] [--fail-on HIGH,CRITICAL]");
            Environment.Exit(0);
        }

        if (!arguments[index].StartsWith("--", StringComparison.Ordinal) || index + 1 >= arguments.Length)
        {
            throw new ArgumentException($"Expected an option followed by a value, received '{arguments[index]}'.");
        }

        options[arguments[index]] = arguments[++index];
    }

    return options;
}
