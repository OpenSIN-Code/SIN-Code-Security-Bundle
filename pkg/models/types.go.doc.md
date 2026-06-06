# types.go.doc.md

## What

Go data models for scan results, compliance scores, remediation plans, and dashboards. Mirrors the Python Pydantic models.

## Dependencies

- Standard Go library only (`time`)

## Key Types

- `ScanResult` — Unified output from a full security scan
- `ToolResult` — Findings from a single security tool
- `ComplianceScore` — Framework compliance score
- `FixAction` — Remediation action
- `RemediationPlan` — Complete remediation plan
- `Dashboard` / `Framework` / `Control` — Compliance dashboard structures

## Usage

Import from `github.com/OpenSIN-Code/SIN-Code-Security-Bundle/pkg/models`.

## Caveats

- JSON tags match Python Pydantic field names for cross-language compatibility.
- `omitempty` tags avoid serializing zero values.
