# remediation_engine.doc.md

## What

Generates cross-tool remediation plans with dependency-aware ordering, rollback commands, and verification steps. Uses `RemediationAction` and `RemediationPlan` Pydantic models (not `FixStep`/`FixPlan`).

## Dependencies

- `bundle_scanner.py` — Consumes `BundleScanResult` and `ToolResult` models
- No external tool dependencies

## Key Config

- `RemediationAction` model: priority, tool, action, command, files_to_modify, effort, risk, verification_steps
- `RemediationPlan` model: actions, cross_tool_dependencies, verification_plan, estimated_total_effort
- `REMEDIATION_TEMPLATES`: Templates per tool (npm, pip, go, docker, terraform, k8s, etc.)

## Usage

```python
from src.tools.remediation_engine import RemediationEngine
from src.tools.bundle_scanner import BundleScanner

scanner = BundleScanner()
result = scanner.full_scan("./project")

engine = RemediationEngine()
plan = engine.generate_plan(result, max_actions=20, focus_areas=["critical", "high"])
guide = engine.generate_implementation_guide(plan)
print(guide)
```

## Caveats

- Commands in steps are template strings; actual execution requires manual review.
- Cross-tool dependencies are heuristic (e.g., SCA → Container → DAST verification chain).
- Effort estimates are rough classifications (low/medium/high), not precise time estimates.
