# SIN-Code-Security-Bundle Dokumentation

## 🎯 Übersicht

Das **SIN-Code-Security-Bundle** ist die ultimative Unified Security Platform für das SIN-Code Ökosystem. Es orchestriert alle 5 Security-Tools zu einer einzigen, leistungsstarken Lösung.

### Die 5 orchestrierten Tools

| # | Tool | Emoji | Zweck | Weight |
|---|------|-------|-------|--------|
| 1 | **SCA Tool** | 📦 | Dependencies auf CVEs scannen | 25% |
| 2 | **Container Tool** | 🐳 | Docker Images auf Vulnerabilities | 20% |
| 3 | **IaC Tool** | 🏗️ | Terraform/K8s Misconfigurations | 20% |
| 4 | **License Tool** | 📜 | License-Compliance prüfen | 15% |
| 5 | **DAST Tool** | 🎯 | Laufende Apps testen | 20% |

## 🚀 Quick Start

### Installation

```bash
chmod +x setup.sh
./setup.sh
```

### Full Security Scan

```bash
# Alle 5 Tools auf einmal
sin-security scan ./my-project --full --compliance cis,nist,soc2

# Output:
# 🎯 Starting comprehensive security scan...
# 📦 [1/5] SCA Scan: 3 high vulnerabilities
# 🐳 [2/5] Container Scan: 1 critical vulnerability
# 🏗️  [3/5] IaC Scan: 2 high misconfigurations
# 📜 [4/5] License Scan: 1 copyleft warning
# 🎯 [5/5] DAST Scan: 2 high vulnerabilities
#
# ============================================================
# ✅ Scan completed in 120.5s
# 📊 Overall Security Score: 72/100
# 🎯 Status: WARNING
# ============================================================
```

### Speziell für OpenAfD-Chat (AnythingLLM)

```bash
# Scan des OpenAfD-Chat Repos
sin-security openafd ../OpenAfD-Chat

# Mit laufender Instanz
sin-security openafd ../OpenAfD-Chat --url http://localhost:3001
```

## 📊 Features

### 🎯 Overall Security Score

Ein einheitlicher Score (0-100) der alle 5 Tools zusammenfasst:

- **🟢 80-100**: Good Security Posture
- **🟡 60-79**: Needs Attention
- **🔴 0-59**: Critical Issues Found

### 💥 Cross-Tool Blast Radius Analysis

```bash
# MCP Tool
sin_security_blast_radius("CVE-2024-1234", "./my-project")
```

Zeigt wie eine Vulnerability über alle Domänen zusammenhängt:
- 📦 SCA: Package in `package.json`
- 🐳 Container: Betroffener Docker Layer
- 🏗️  IaC: Verwendung in Terraform
- 🎯 DAST: Exposed via API Endpoint

### 📋 Multi-Framework Compliance

Unterstützt alle wichtigen Frameworks:
- **CIS Benchmarks** (AWS, Azure, GCP, K8s)
- **NIST 800-53**
- **SOC 2 Type II**
- **ISO 27001**
- **GDPR**
- **HIPAA**
- **PCI DSS**
- **OWASP Top 10**

### 🤖 AI-Powered Remediation

Automatische Fix-Vorschläge:

```bash
sin-security scan ./project --format json | jq '.top_fixes'
```

Output:
```json
[
  {
    "priority": 1,
    "tool": "container",
    "severity": "CRITICAL",
    "action": "Update openssl in Docker image"
  },
  {
    "priority": 2,
    "tool": "sca",
    "severity": "HIGH",
    "action": "Update axios to latest version"
  }
]
```

## 🛠️  CLI Commands

### Haupt-Commands

```bash
# Full scan
sin-security scan ./project --compliance cis,nist --fail-on high

# Einzelne Tools
sin-security sca ./project
sin-security container ./project
sin-security iac ./project
sin-security license ./project
sin-security dast https://app.example.com

# OpenAfD-Chat (AnythingLLM)
sin-security openafd ../OpenAfD-Chat --url http://localhost:3001

# Info
sin-security list-tools
sin-security list-frameworks
```

### Output-Formate

```bash
# JSON (für CI/CD)
sin-security scan ./project --format json > report.json

# Text (für Terminal)
sin-security scan ./project --format text

# HTML Dashboard (Python MCP)
sin_security_html_dashboard("./project", "dashboard.html")
```

## 🤖 MCP Tools

| Tool | Beschreibung |
|------|-------------|
| `sin_security_full_scan` | Vollständiger Scan über alle Tools |
| `sin_security_blast_radius` | Cross-Tool Blast-Radius-Analyse |
| `sin_security_remediation_plan` | AI-Remediation-Plan |
| `sin_security_compliance_report` | Compliance-Report |
| `sin_security_executive_summary` | Executive Summary für Management |
| `sin_security_technical_report` | Detaillierter Technical Report |
| `sin_security_html_dashboard` | Interaktives HTML-Dashboard |
| `sin_security_list_tools` | Liste aller Tools |
| `sin_security_list_compliance_frameworks` | Liste aller Frameworks |

## 📊 Reports

### Executive Summary (Markdown)

```bash
# Via Python
from src.tools.compliance_dashboard import ComplianceDashboard
dashboard = ComplianceDashboard()
report = dashboard.generate_executive_summary(scan_result)
```

### Technical Report

```bash
# Detaillierter Report mit allen Findings
report = dashboard.generate_technical_report(scan_result)
```

### HTML Dashboard

```bash
# Interaktives Dashboard
html = dashboard.generate_html_dashboard(scan_result)
```

## 🔧 Integration

### GitHub Actions

```yaml
name: Full Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install SIN-Code Security Bundle
        run: |
          git clone https://github.com/OpenSIN-Code/SIN-Code-Security-Bundle.git
          cd SIN-Code-Security-Bundle
          make setup
      
      - name: Run Full Scan
        run: |
          cd SIN-Code-Security-Bundle
          ./bin/sin-security scan ../ \
            --compliance cis,nist,soc2 \
            --fail-on high \
            --format json > ../security-report.json
      
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json
```

### Pre-Commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/OpenSIN-Code/SIN-Code-Security-Bundle
    rev: main
    hooks:
      - id: sin-security-full-scan
        args: [--compliance, cis,nist, --fail-on, high]
```

## 🇩🇪 OpenAfD-Chat Integration

Das Bundle wurde speziell für AnythingLLM-basierte Projekte wie **OpenAfD-Chat** optimiert:

### Spezielle Checks

- ✅ **API Key Exposure** (OPENAI_API_KEY, ANTHROPIC_API_KEY)
- ✅ **Telemetry Endpoints** (PostHog)
- ✅ **Vector Database Misconfigurations**
- ✅ **Workspace Access Control**
- ✅ **CORS Configuration**
- ✅ **File Upload Vulnerabilities**
- ✅ **Authentication Mechanisms**

### AnythingLLM-spezifische Nuclei Templates

Die bereits erstellten Templates aus Phase 5 werden automatisch verwendet:
- `sin-anythingllm-misconfig.yaml`
- `sin-anythingllm-telemetry-leak.yaml`
- `sin-anythingllm-no-auth-api.yaml`

### Scanning Workflow

```bash
# 1. Lokale AnythingLLM-Instanz starten
cd ../OpenAfD-Chat
docker-compose up -d

# 2. Full Security Scan
sin-security openafd . --url http://localhost:3001

# 3. Fix-Prioritäten anschauen
sin-security scan . --format json | jq '.top_fixes[:5]'

# 4. Re-Scan nach Fixes
sin-security scan . --fail-on critical
```

## 📊 Vergleich mit Snyk Platform

| Feature | Snyk Platform | SIN-Code-Security-Bundle |
|---------|---------------|--------------------------|
| **Kosten** | $222k/Jahr | **$0** |
| **Scans** | Limitiert | **Unlimited** |
| **Privacy** | Cloud | **100% Lokal** |
| **Tools** | 5 separate | **Unified** |
| **Blast Radius** | Basic | **Cross-Tool** |
| **AI Remediation** | Basic | **PoC-verifiziert** |
| **Executive Reports** | ❌ | ✅ |
| **AnythingLLM Support** | ❌ | ✅ |

## 🏗️  Architecture

```
┌──────────────────────────────────────────────────────┐
│  SIN-Code-Security-Bundle (Orchestrator)             │
│  ┌──────────────────────────────────────────────┐   │
│  │  Python MCP Server  │  Go CLI  │  Dashboard  │   │
│  └──────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
          │           │           │           │
    ┌─────┴────┬──────┴─────┬─────┴────┬──────┴────┐
    ▼          ▼            ▼          ▼            ▼
┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
│SCA     │ │Cont.   │ │IaC     │ │License │ │DAST    │
│Tool    │ │Tool    │ │Tool    │ │Tool    │ │Tool    │
└────────┘ └────────┘ └────────┘ └────────┘ └────────┘
              │
              ▼
┌──────────────────────────────────────────────────────┐
│  SCKG (Code Knowledge Graph) - Blast Radius          │
└──────────────────────────────────────────────────────┘
```

## 🔐 Security & Privacy

- ✅ **Kein Cloud-Upload**: Alle Scans laufen lokal
- ✅ **Keine Telemetrie**: Keine Daten verlassen dein System
- ✅ **Air-Gapped**: Funktioniert ohne Internet
- ✅ **Privacy-First**: Deine Security-Daten bleiben privat
- ✅ **GDPR-konform**: Keine Datenverarbeitung außerhalb der EU

## 📚 Weiterführende Dokumentation

- [SIN-Code-SCA-Tool](../SIN-Code-SCA-Tool/docs/index.md)
- [SIN-Code-Container-Tool](../SIN-Code-Container-Tool/docs/index.md)
- [SIN-Code-IaC-Tool](../SIN-Code-IaC-Tool/docs/index.md)
- [SIN-Code-License-Tool](../SIN-Code-License-Tool/docs/index.md)
- [SIN-Code-DAST-Tool](../SIN-Code-DAST-Tool/docs/index.md)

## 📝 License

MIT © 2026 Family Team Projects
