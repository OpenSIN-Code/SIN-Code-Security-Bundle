# SIN-Code-Security-Bundle

> Unified security scanning bundle across SCA, Container, IaC, License, and DAST domains.

## Status

- **Version**: [v1.3.0](https://github.com/OpenSIN-Code/SIN-Code-Security-Bundle/releases/tag/v1.3.0)
- **Maturity**: Beta
- **Language**: Python (core) + Go (CLI)
- **Tests**: 3 Python test files + 2 Go test files; run `make test`
- **CI**: ✅ 1 workflow configured

## Installation

```bash
git clone https://github.com/OpenSIN-Code/SIN-Code-Security-Bundle.git
cd SIN-Code-Security-Bundle

# Python package
pip install -e .

# Go CLI
go build -o ~/.local/bin/sin-security ./cmd/sin-security
```

## Usage

```bash
# Go CLI
sin-security --help
sin-security scan ./my-project
sin-security compliance ./my-project --frameworks cis,nist
sin-security summary ./my-project
sin-security remediate ./my-project

# Python API
python - <<'PY'
from src.tools.bundle_scanner import BundleScanner
scanner = BundleScanner()
result = scanner.full_scan("./my-project", compliance=["cis", "nist"])
print(result.overall_score)
PY
```

## MCP Integration

- **MCP Server**: `src/server.py`
- **Tools**: 10 MCP tools exposed (full_scan, blast_radius, remediation_plan, compliance_report, executive_summary, technical_report, html_dashboard, list_tools, list_compliance_frameworks, and more)
- **Register**: `sin mcp register sin-security src/server.py` or add to your MCP client config.

## Development

- **CoDocs**: 8 `.doc.md` companions
- **AGENTS.md**: ❌ Missing — needs to be added to comply with the OpenSIN-Code standard
- **Tests**: `make test` (runs both Python and Go tests)
- **Lint**: `ruff check .` (Python) and `golangci-lint run` (Go)
- **Compliance**: This repository aims to follow the OpenSIN-Code CoDocs/AGENTS.md standard. AGENTS.md and LICENSE files are currently missing; the README declares MIT in line with `pyproject.toml`.

## License

MIT — see [LICENSE](LICENSE). (LICENSE file is currently missing from the repo.)
