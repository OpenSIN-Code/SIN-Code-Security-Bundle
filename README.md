# SIN-Code-Security-Bundle

SIN-Code-Security-Bundle: Unified security scanning across all SIN-Code security tools (SAST, SCA, Container, IaC, License, DAST).

## Features

- Full Security Scan: Run all 6 security tools in one command
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

## Integration with `sin` CLI

The bundle is registered as a sub-Typer in [SIN-Code-Bundle](https://github.com/SIN-Rotator/SIN-Code-Bundle),
so every `sin-security` subcommand is also reachable as `sin security <tool>`:

```bash
# Build the binary once
go build -o ~/.local/bin/sin-security ./cmd/sin-security

# Reinstall the bundle CLI to pick up the new `sin security` group
cd ../SIN-Code-Bundle && pipx install -e . --force

# Now all 8 tools + the `full` convenience command are available
sin security --help
sin security secrets .
sin security sast ./src
sin security sca .
sin security sbom .
sin security container ./Dockerfile
sin security iac ./terraform
sin security license .
sin security dast https://example.com
sin security full .                       # runs all 8 tools
sin security full . --compliance cis,nist --skip-tools dast
```

The `sin security` group is a thin pass-through — every flag and argument is
forwarded unchanged to the `sin-security` binary, so `sin-security <tool> --help`
and `sin security <tool> --help` are equivalent.

## Documentation

See `docs/index.md` for full documentation.

## License

MIT
