# report_generator.doc.md

## What

Generates executive and technical reports from security scan results in markdown, JSON, and HTML formats.

## Dependencies

- `bundle_scanner.py` — Consumes `SecurityBundleResult` model
- No external tool dependencies

## Key Config

- `templates_dir`: Path to custom report templates (optional).
- Default templates are embedded in code; no template engine required.

## Usage

```python
from src.tools.report_generator import ReportGenerator
gen = ReportGenerator()
exec_report = gen.generate_executive_report(result, format="markdown")
tech_report = gen.generate_technical_report(result, detailed_results, format="markdown")
```

## Caveats

- HTML reports are simplified (no CSS framework); production use may require custom styling.
- Technical reports require `detailed_results` dict from individual tools.
- Executive summary is one-page; truncate long recommendation lists.
