# bundle_scanner.doc.md

## What

Orchestrates all 5 security tools (SCA, Container, IaC, License, DAST) and produces unified security reports with compliance scores. Uses `BundleScanResult` with `tools: Dict[str, ToolResult]` for direct CLI-friendly access.

## Dependencies

- `compliance_dashboard.py` — For report generation
- `remediation_engine.py` — For cross-tool fix plans (optional)
- External tools: osv-scanner, grype, trivy, checkov, scancode, zap-cli, nuclei (detected at runtime)

## Key Config

- `TOOLS`: Maps tool names to metadata (emoji, weight, CLI command, MCP tool name)
- `COMPLIANCE_FRAMEWORKS`: 8 frameworks with weights for score calculation
- `ToolResult` and `BundleScanResult` Pydantic models enforce structure

## Usage

```python
from src.tools.bundle_scanner import BundleScanner
scanner = BundleScanner()
result = scanner.full_scan("./my-project", compliance=["cis", "nist"])
print(f"Score: {result.overall_score}/100, Status: {result.status}")
for tool_name, tool_result in result.tools.items():
    print(f"  {tool_name}: {tool_result.status}")
scanner.close()
```

## Caveats

- If external tools are not installed, returns synthetic data for testing purposes.
- `full_scan()` method (not `scan()`) is the main entry point.
- `tools` is a `Dict[str, ToolResult]` for direct lookup by tool name.
- DAST scan only runs if `target_url` is provided.
