# orchestrator.go.doc.md

## What

Go orchestrator that coordinates security scans, compliance dashboard generation, and remediation plan creation.

## Dependencies

- `pkg/models` — Data structures for scan results and dashboards

## Key Methods

- `RunScan(config ScanConfig) (*ScanResult, error)` — Executes a full security scan
- `GenerateDashboard(config ComplianceConfig) (*Dashboard, error)` — Creates compliance dashboard
- `GenerateRemediationPlan(result *ScanResult) (*RemediationPlan, error)` — Generates remediation plan

## Usage

```go
import "github.com/OpenSIN-Code/SIN-Code-Security-Bundle/internal/orchestrator"

o := orchestrator.New(true)
result, err := o.RunScan(models.ScanConfig{ProjectPath: "./project"})
```

## Caveats

- Returns mock/synthetic data for tools not yet integrated via Go.
- Remediation plan estimates are heuristic; actual effort may vary.
- Cross-tool dependencies are hardcoded strings (SCA → Container → DAST).
