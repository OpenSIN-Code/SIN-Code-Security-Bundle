# SIN-Code-Security-Bundle

SIN-Code-Security-Bundle: Unified security scanning across all SIN-Code security tools (SCA, Container, IaC, License, DAST).

## Features

- Full Security Scan: Run all 5 security tools in one command
- Compliance Dashboard: Map findings to CIS, NIST, SOC2, ISO27001, GDPR, OWASP, PCI, HIPAA
- Remediation Engine: Cross-tool fix plans with dependency-aware ordering
- Executive Reports: Business-friendly summaries for leadership
- Technical Reports: Detailed reports for development teams
- MCP Server: Integration with any MCP-compatible client (Cursor, Claude, etc.)
- Go CLI: Fast, cross-platform command-line tool

## Installation

```bash
pip install -e .
```

## Quick Start

### Python API

```python
from src.tools.bundle_scanner import BundleScanner

scanner = BundleScanner()
result = scanner.scan(project_path="./my-project", scan_type="full")

# Get executive summary
summary = scanner.generate_executive_summary(result)
print(summary)

# Get compliance report
from src.tools.compliance_dashboard import ComplianceDashboardGenerator
generator = ComplianceDashboardGenerator()
dashboard = generator.generate(
    project_path="./my-project",
    requested_frameworks=["cis", "nist"]
)
report = generator.generate_compliance_report(dashboard, format="markdown")
print(report)

# Get remediation plan
from src.tools.remediation_engine import RemediationEngine
engine = RemediationEngine()
plan = engine.generate_plan(result)
plan_json = engine.generate_remediation_report(plan, format="json")
print(plan_json)

# Generate technical report
from src.tools.report_generator import ReportGenerator
report_gen = ReportGenerator()
tech_report = report_gen.generate_technical_report(result, {
    "sca": result.tools[0].summary if result.tools else {},
    "container": {},
    "iac": {},
    "license": {},
    "dast": {}
})
print(tech_report)
```

### Go CLI

```bash
# Full scan
sin-security scan ./my-project

# Compliance report
sin-security compliance ./my-project --frameworks cis,nist

# Executive summary
sin-security summary ./my-project

# Remediation plan
sin-security remediate ./my-project
```

## Testing

```bash
make test
```

## Documentation

See `docs/index.md` for full documentation.

## License

MIT
