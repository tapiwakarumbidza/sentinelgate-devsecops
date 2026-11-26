using System.Text.Json;

namespace ScannerEngine;

internal static class SecurityReportParser
{
    private static readonly (string Id, string Name)[] OwaspCategories =
    {
        ("A01", "Broken Access Control"),
        ("A02", "Cryptographic Failures"),
        ("A03", "Injection"),
        ("A04", "Insecure Design"),
        ("A05", "Security Misconfiguration"),
        ("A06", "Vulnerable and Outdated Components"),
        ("A07", "Identification and Authentication Failures"),
        ("A08", "Software and Data Integrity Failures"),
        ("A09", "Security Logging and Monitoring Failures"),
        ("A10", "Server-Side Request Forgery")
    };

    private static readonly (string Id, string Name)[] PopiaControls =
    {
        ("POPIA-19", "Section 19: Security safeguards"),
        ("POPIA-22", "Section 22: Security compromise notification"),
        ("POPIA-23", "Section 23: Access to personal information")
    };

    public static List<SecurityFinding> Parse(string semgrepPath, string gitleaksPath, string trivyPath)
    {
        using var semgrep = ReadJson(semgrepPath);
        using var gitleaks = ReadJson(gitleaksPath);
        using var trivy = ReadJson(trivyPath);
        var findings = new List<SecurityFinding>();
        ParseSemgrep(semgrep.RootElement, findings);
        ParseGitleaks(gitleaks.RootElement, findings);
        ParseTrivy(trivy.RootElement, findings);
        return findings;
    }

    public static SecurityReport BuildReport(IReadOnlyList<SecurityFinding> findings)
    {
        var counts = findings.GroupBy(f => f.Severity).ToDictionary(g => g.Key, g => g.Count());
        var severityCounts = new SeverityCounts(
            Count(counts, "CRITICAL"), Count(counts, "HIGH"), Count(counts, "MEDIUM"),
            Count(counts, "LOW"), Count(counts, "INFO"));

        var owasp = OwaspCategories
            .Select(category => new OwaspCategorySummary(
                category.Id, category.Name, findings.Count(f => f.OwaspCategory == category.Id)))
            .ToArray();

        var popia = PopiaControls
            .Select(control =>
            {
                var matchingFindings = findings.Count(f => f.PopiaControls.Contains(control.Id));
                return new PopiaControlSummary(
                    control.Id, control.Name,
                    matchingFindings == 0 ? "not_assessed" : "attention_required",
                    matchingFindings);
            })
            .ToArray();

        return new SecurityReport(
            "1.0", DateTimeOffset.UtcNow, findings.Count, severityCounts, findings, owasp, popia);
    }

    private static void ParseSemgrep(JsonElement root, ICollection<SecurityFinding> findings)
    {
        if (TryGet(root, "runs", out var runs) && runs.ValueKind == JsonValueKind.Array)
        {
            foreach (var run in runs.EnumerateArray())
            {
                if (TryGet(run, "results", out var sarifResults) && sarifResults.ValueKind == JsonValueKind.Array)
                {
                    ParseSemgrepResults(sarifResults, findings, isSarif: true);
                }
            }

            return;
        }

        if (TryGet(root, "results", out var results) && results.ValueKind == JsonValueKind.Array)
        {
            ParseSemgrepResults(results, findings, isSarif: false);
            return;
        }

        throw new InvalidDataException("Semgrep JSON must contain a results array or SARIF runs array.");
    }

    private static void ParseSemgrepResults(
        JsonElement results,
        ICollection<SecurityFinding> findings,
        bool isSarif)
    {
        foreach (var result in results.EnumerateArray())
        {
            var ruleId = GetString(result, isSarif ? "ruleId" : "check_id", "semgrep-finding");
            string message;
            string file;
            int? line = null;
            string level;

            if (isSarif)
            {
                var messageNode = GetPath(result, "message");
                message = GetString(messageNode, "text", ruleId);
                var physical = GetPath(result, "locations");
                if (physical.ValueKind == JsonValueKind.Array && physical.GetArrayLength() > 0)
                {
                    physical = GetPath(physical[0], "physicalLocation");
                }
                file = GetString(GetPath(physical, "artifactLocation"), "uri", "");
                var lineNode = GetPath(physical, "region");
                if (TryGet(lineNode, "startLine", out var parsedNode) && parsedNode.TryGetInt32(out var parsedLine))
                {
                    line = parsedLine;
                }
                level = GetString(result, "level", "warning");
            }
            else
            {
                var extra = GetPath(result, "extra");
                message = GetString(extra, "message", ruleId);
                file = GetString(result, "path", "");
                var start = GetPath(result, "start");
                if (TryGet(start, "line", out var parsedNode) && parsedNode.TryGetInt32(out var parsedLine))
                {
                    line = parsedLine;
                }
                level = GetString(extra, "severity", "WARNING");
            }

            var severity = NormalizeSemgrepSeverity(level);
            findings.Add(Create("Semgrep", ruleId, message, severity, message, file, line));
        }
    }

    private static void ParseGitleaks(JsonElement root, ICollection<SecurityFinding> findings)
    {
        if (root.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("Gitleaks JSON must be an array of findings.");
        }

        foreach (var leak in root.EnumerateArray())
        {
            var ruleId = GetString(leak, "RuleID", "secret-detection");
            var description = GetString(leak, "Description", "Potential secret detected");
            var file = GetString(leak, "File", "");
            var line = TryGet(leak, "StartLine", out var lineNode) && lineNode.TryGetInt32(out var parsedLine)
                ? parsedLine
                : (int?)null;

            // Deliberately never copy Gitleaks' Secret field into the report.
            findings.Add(Create("Gitleaks", ruleId, description, "HIGH", description, file, line));
        }
    }

    private static void ParseTrivy(JsonElement root, ICollection<SecurityFinding> findings)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("Trivy JSON must be an object containing a Results array.");
        }

        if (!TryGet(root, "Results", out var results) || results.ValueKind == JsonValueKind.Null)
        {
            return;
        }

        if (results.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("Trivy JSON must contain a Results array.");
        }

        foreach (var result in results.EnumerateArray())
        {
            var target = GetString(result, "Target", "");
            ParseTrivyItems(result, "Vulnerabilities", target, findings, isVulnerability: true);
            ParseTrivyItems(result, "Misconfigurations", target, findings, isVulnerability: false);
            ParseTrivyItems(result, "Secrets", target, findings, isVulnerability: false);
        }
    }

    private static void ParseTrivyItems(
        JsonElement result,
        string property,
        string target,
        ICollection<SecurityFinding> findings,
        bool isVulnerability)
    {
        if (!TryGet(result, property, out var items) || items.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var item in items.EnumerateArray())
        {
            var ruleId = GetString(item, "VulnerabilityID",
                GetString(item, "ID", GetString(item, "RuleID", property)));
            var title = GetString(item, "Title", GetString(item, "Description", ruleId));
            var severity = NormalizeSeverity(GetString(item, "Severity", "UNKNOWN"));
            var file = GetString(item, "PkgName", target);
            findings.Add(Create("Trivy", ruleId, title, severity, title, file, null,
                isVulnerability ? "component" : property));
        }
    }

    private static SecurityFinding Create(
        string scanner,
        string ruleId,
        string title,
        string severity,
        string description,
        string file,
        int? line,
        string? hint = null)
    {
        var searchable = $"{ruleId} {title} {description} {hint}".ToLowerInvariant();
        var owasp = MapOwaspCategory(searchable, scanner);
        var popia = new List<string> { "POPIA-19" };
        if (searchable.Contains("personal") || searchable.Contains("identifier") ||
            searchable.Contains("account") || searchable.Contains("privacy") ||
            searchable.Contains("data subject"))
        {
            popia.Add("POPIA-23");
        }

        if (searchable.Contains("breach") || searchable.Contains("compromise"))
        {
            popia.Add("POPIA-22");
        }

        return new SecurityFinding(scanner, ruleId, title, severity, description, file, line, owasp, popia.ToArray());
    }

    private static string MapOwaspCategory(string searchable, string scanner)
    {
        if (searchable.Contains("sql") || searchable.Contains("injection"))
            return "A03";
        if (searchable.Contains("ssrf") || searchable.Contains("server-side request forgery"))
            return "A10";
        if (searchable.Contains("secret") || searchable.Contains("credential") ||
            searchable.Contains("password") || searchable.Contains("token") ||
            searchable.Contains("api key") || searchable.Contains("apikey") ||
            searchable.Contains("authentication") || searchable.Contains("login"))
            return "A07";
        if (searchable.Contains("cryptograph") || searchable.Contains("encryption"))
            return "A02";
        if (searchable.Contains("access control") || searchable.Contains("authorization"))
            return "A01";
        if (searchable.Contains("integrity") || searchable.Contains("supply chain"))
            return "A08";
        if (searchable.Contains("logging") || searchable.Contains("monitoring"))
            return "A09";
        if (searchable.Contains("insecure design"))
            return "A04";
        if (searchable.Contains("component") || searchable.Contains("cve") ||
            scanner.Equals("Trivy", StringComparison.Ordinal))
            return "A06";

        return "A05";
    }

    private static string NormalizeSemgrepSeverity(string severity) => severity.ToUpperInvariant() switch
    {
        "CRITICAL" => "CRITICAL",
        "ERROR" or "HIGH" => "HIGH",
        "WARNING" or "MEDIUM" or "MODERATE" => "MEDIUM",
        "INFO" or "NOTE" or "LOW" => "LOW",
        _ => "INFO"
    };

    private static string NormalizeSeverity(string severity) => severity.ToUpperInvariant() switch
    {
        "CRITICAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "MEDIUM" or "MODERATE" => "MEDIUM",
        "LOW" => "LOW",
        "INFO" or "INFORMATIONAL" or "UNKNOWN" => "INFO",
        _ => "INFO"
    };

    private static int Count(IReadOnlyDictionary<string, int> counts, string key) =>
        counts.TryGetValue(key, out var count) ? count : 0;

    private static JsonDocument ReadJson(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Scanner output was not found: {path}", path);
        }

        return JsonDocument.Parse(File.ReadAllText(path));
    }

    private static bool TryGet(JsonElement element, string property, out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var candidate in element.EnumerateObject())
            {
                if (candidate.Name.Equals(property, StringComparison.OrdinalIgnoreCase))
                {
                    value = candidate.Value;
                    return true;
                }
            }
        }

        value = default;
        return false;
    }

    private static string GetString(JsonElement element, string property, string fallback)
    {
        if (!TryGet(element, property, out var value))
        {
            return fallback;
        }

        return value.ValueKind == JsonValueKind.String ? value.GetString() ?? fallback : fallback;
    }

    private static JsonElement GetPath(JsonElement element, params string[] properties)
    {
        foreach (var property in properties)
        {
            if (!TryGet(element, property, out element))
            {
                return default;
            }
        }

        return element;
    }
}
