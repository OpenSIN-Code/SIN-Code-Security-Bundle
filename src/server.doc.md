# server.doc.md

## What

MCP (Model Context Protocol) server exposing 9 security tools via FastMCP framework. Serves `sin-code-security-bundle` namespace.

## Dependencies

- `mcp.server.fastmcp.FastMCP` — FastMCP framework for tool registration
- `bundle_scanner.py`, `compliance_dashboard.py`, `remediation_engine.py` — Core tools

## Key Config

- `app = FastMCP("sin-code-security-bundle")` — Server identity
- Tools registered via `@app.tool()` decorator (async functions)
- All tools return `str` (JSON or formatted text)

## Available Tools

| Tool | Description |
|------|-------------|
| `sin_security_full_scan` | Full scan across all 5 tools |
| `sin_security_blast_radius` | Cross-tool blast radius analysis |
| `sin_security_remediation_plan` | AI-powered remediation plan |
| `sin_security_compliance_report` | Compliance report for frameworks |
| `sin_security_executive_summary` | Executive summary for management |
| `sin_security_technical_report` | Detailed technical report |
| `sin_security_html_dashboard` | Interactive HTML dashboard |
| `sin_security_list_tools` | List available security tools |
| `sin_security_list_compliance_frameworks` | List compliance frameworks |

## Usage

```python
from src.server import app
# Run server
app.run()
```

Or via CLI:
```bash
python -m src.server
```

## Caveats

- Server runs via FastMCP default transport (stdio or SSE depending on client).
- All tools are async; clients must await responses.
- Global scanner/dashbord/remediation instances are created at import time (not per-request).
- Blast radius tool returns synthetic data; integrate with `sin-context` for real SCKG analysis.
