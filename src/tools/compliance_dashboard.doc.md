# compliance_dashboard.doc.md

## What

Generates executive summaries, technical reports, and HTML dashboards from security scan results. Uses `ComplianceDashboard` class (not `ComplianceDashboardGenerator`).

## Dependencies

- `bundle_scanner.py` — Consumes `BundleScanResult` and `ToolResult` models
- No external tool dependencies; operates on scan results
- Optional: `jinja2` for custom templates; fallback HTML generation built-in

## Key Config

- `ReportConfig` Pydantic model controls report format and sections
- `templates_path`: Optional path to custom Jinja2 templates
- Supports `markdown`, `html`, `json` output formats

## Usage

```python
from src.tools.compliance_dashboard import ComplianceDashboard
from src.tools.bundle_scanner import BundleScanner

scanner = BundleScanner()
result = scanner.full_scan("./project")

dashboard = ComplianceDashboard()
exec_report = dashboard.generate_executive_summary(result)
tech_report = dashboard.generate_technical_report(result)
html = dashboard.generate_html_dashboard(result)
```

## Caveats

- Scores are synthesized based on tool status; no actual framework audit is performed.
- HTML reports use embedded CSS (no external framework required).
- PDF generation requires `weasyprint` (optional dependency).
