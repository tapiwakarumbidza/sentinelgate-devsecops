namespace ScannerEngine;

internal sealed record SecurityFinding(
    string Scanner,
    string RuleId,
    string Title,
    string Severity,
    string Description,
    string File,
    int? Line,
    string OwaspCategory,
    string[] PopiaControls);

internal sealed record SeverityCounts(int Critical, int High, int Medium, int Low, int Info);

internal sealed record OwaspCategorySummary(string Id, string Name, int Count);

internal sealed record PopiaControlSummary(string Id, string Name, string Status, int FindingCount);

internal sealed record SecurityReport(
    string SchemaVersion,
    DateTimeOffset GeneratedAt,
    int TotalFindings,
    SeverityCounts SeverityCounts,
    IReadOnlyList<SecurityFinding> Findings,
    IReadOnlyList<OwaspCategorySummary> OwaspTop10,
    IReadOnlyList<PopiaControlSummary> PopiaControls);
