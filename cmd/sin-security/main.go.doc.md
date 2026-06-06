# main.go.doc.md

## What

Go CLI entrypoint for the SIN-Code Security Bundle. Provides commands for scan, compliance, summary, and remediation.

## Dependencies

- `pkg/models` — Data structures
- `internal/orchestrator` — Core orchestration logic

## Key Config

- Command-line flags: `-path`, `-type`, `-severity`, `-format`, `-output`, `-verbose`, `-version`
- Commands: `scan`, `compliance`, `summary`, `remediate`, `help`

## Usage

```bash
sin-security scan ./my-project
sin-security compliance ./my-project --frameworks cis,nist
sin-security summary ./my-project
sin-security remediate ./my-project
```

## Caveats

- Mock data is returned for tools not yet integrated via Go orchestrator.
- Output defaults to stdout; use `-output` flag to write to file.
