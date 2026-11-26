# SentinelGate: Automated DevSecOps & Compliance Gatekeeper

SentinelGate is a local portfolio/demo project that demonstrates how to collect
Semgrep, Gitleaks, and Trivy findings, map them to OWASP Top 10 and selected
POPIA controls, and enforce a severity gate in GitHub Actions.

> **Training project only.** The API is an intentionally simplified mock, not a
> payment service. It contains a nonfunctional dummy key, synthetic invalid
> identifiers, and commented insecure-code examples. Never use real credentials,
> personal data, or this demo as a production security baseline.

## Architecture

```text
                         push / pull request
                                  |
                                  v
                         GitHub Actions CI
             +--------------------+--------------------+
             |                    |                    |
          Gitleaks              Semgrep               Trivy
       secret scan             C# scan          API image scan
             +--------------------+--------------------+
                                  |
                                  v
                        ScannerEngine (.NET 8)
                  normalize -> map -> severity gate
                                  |
                                  v
                       security-report.json
                                  |
                 +----------------+----------------+
                 |                                 |
                 v                                 v
          TargetApi (.NET 8)                Dashboard (nginx)
            localhost:8080                  localhost:8081
```

## Tech stack

- **API:** C# / ASP.NET Core on .NET 8
- **Scanner:** .NET 8 console application
- **Dashboard:** static HTML, Tailwind CSS, and Chart.js served by Nginx
- **Containerization:** Docker and Docker Compose
- **CI:** GitHub Actions with Gitleaks, Semgrep, and Trivy

## Requirements

- .NET 8 SDK (for build, API, and report parser)
- Docker with the Compose plugin (for the local API and dashboard)
- Optional: Go, Semgrep, and Trivy to run the scanners locally

## Run locally

Build both .NET projects:

```powershell
dotnet build SentinelGate.sln
```

Start the API and dashboard:

```powershell
docker compose up --build
```

- Dashboard: <http://localhost:8081>
- API status: <http://localhost:8080/>
- Users: <http://localhost:8080/api/users>
- Transactions: <http://localhost:8080/api/transactions>
- Login mock: `POST http://localhost:8080/api/auth/login` with JSON
  `{"username":"demo","password":"demo"}`. This returns a nonfunctional demo token.

The dashboard loads the checked-in sample `security-report.json` so it works
immediately from `Dashboard/security-report.json`. Compose mounts that report
read-only into the dashboard container.

## Try the report parser

Sample Semgrep JSON, Gitleaks JSON, and Trivy JSON are in
`ScannerEngine/SampleScans/`. From the repository root, run:

```powershell
dotnet run --project ScannerEngine
```

The parser writes `Dashboard/security-report.json` by default, with severity
totals, individual findings, OWASP Top 10 category counts, and POPIA control
status. Sample findings are synthetic; no secret values are included in the
Gitleaks fixture.

To parse real scanner output and fail on high or critical findings:

```powershell
dotnet run --project ScannerEngine -- `
  --semgrep semgrep.json `
  --gitleaks gitleaks.json `
  --trivy trivy.json `
  --output Dashboard/security-report.json `
  --fail-on HIGH,CRITICAL
```

The dashboard displays severity totals, an OWASP category chart, POPIA review
status, and a searchable findings table. Rebuild the dashboard image after
regenerating the report if you are not using Compose's read-only report mount.

## OWASP Top 10 and POPIA mapping

Every normalized finding is assigned one OWASP Top 10 (2021) category and at
least POPIA section 19, the security safeguards control. Findings that mention
personal information, identifiers, account data, or privacy are also mapped
to section 23. Findings that indicate a breach or compromise are additionally
mapped to section 22. These are triage mappings for a demo, not legal advice or
a compliance determination.

| Mapping | Control / category | Example in this demo |
| --- | --- | --- |
| OWASP A01 | Broken Access Control | Authorization and access-control findings |
| OWASP A02 | Cryptographic Failures | Cryptographic implementation and encryption findings |
| OWASP A03 | Injection | SQL/query-injection findings |
| OWASP A04 | Insecure Design | Design-level security findings |
| OWASP A05 | Security Misconfiguration | Unclassified configuration/security findings |
| OWASP A06 | Vulnerable and Outdated Components | Trivy component/CVE findings |
| OWASP A07 | Identification and Authentication Failures | Credential and authentication findings |
| OWASP A08 | Software and Data Integrity Failures | Integrity and supply-chain findings |
| OWASP A09 | Security Logging and Monitoring Failures | Logging and monitoring findings |
| OWASP A10 | Server-Side Request Forgery | SSRF findings |
| POPIA section 19 | Security safeguards | Applied to every finding for review |
| POPIA section 22 | Security compromise notification | Added when a finding indicates a breach or compromise |
| POPIA section 23 | Access to personal information | Added for personal-information and privacy findings |

## CI security gate

`.github/workflows/devsecops.yml` runs for pushes and pull requests. It builds
the .NET solution, scans repository history with Gitleaks, scans C# with
Semgrep, builds and scans the API container with Trivy, and produces a unified
report at `Dashboard/security-report.json`. The job fails when the combined
report has HIGH/CRITICAL findings and uploads both the raw scanner JSON files
and normalized report as workflow artifacts.

## Demo security notes

- `TargetApi/appsettings.json` contains only an unmistakably fake placeholder,
  never a usable API key.
- The SQL injection example in `TargetApi/Program.cs` is inert training text;
  the API lookup uses an in-memory collection and executes no SQL. The secure
  parameterized-query example is shown next to the training pattern.
- User records contain only synthetic, invalid all-zero/all-one ID and account
  values to illustrate why personal identifiers must not be exposed.
- Scanner sample findings and the seeded Trivy CVE are fixtures, not real
  vulnerabilities in dependencies.
