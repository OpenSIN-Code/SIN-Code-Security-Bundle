"""Compliance Dashboard: Generiert Reports und Dashboards.

Features:
- Executive Summary Reports (PDF/HTML/Markdown)
- Technical Reports
- Compliance Dashboards
- Trend Analysis

Docs: compliance_dashboard.doc.md
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

try:
    from jinja2 import Template, Environment, FileSystemLoader
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False


class ReportConfig(BaseModel):
    """Konfiguration für Report-Generierung."""
    
    title: str = "Security Report"
    format: str = "markdown"  # markdown, html, pdf, json
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_remediation_plan: bool = True
    include_compliance_status: bool = True
    language: str = "en"  # en, de


class ComplianceDashboard:
    """
    Generiert Security-Reports und Compliance-Dashboards.
    
    Usage:
        dashboard = ComplianceDashboard()
        report = dashboard.generate_executive_summary(scan_result)
        dashboard.save_report(report, "executive-summary.md")
    """
    
    def __init__(self, templates_path: Optional[str] = None):
        self.templates_path = templates_path or str(
            Path(__file__).parent.parent.parent / "templates" / "reports"
        )
        
        if JINJA_AVAILABLE and Path(self.templates_path).exists():
            self.jinja_env = Environment(
                loader=FileSystemLoader(self.templates_path),
                autoescape=True
            )
        else:
            self.jinja_env = None
    
    def generate_executive_summary(
        self,
        scan_result,
        config: Optional[ReportConfig] = None
    ) -> str:
        """
        Generiert eine Executive Summary für das Management.
        
        Args:
            scan_result: BundleScanResult
            config: Report-Konfiguration
        
        Returns:
            Report als String (Markdown/HTML)
        """
        config = config or ReportConfig(
            title="Executive Security Summary",
            format="markdown",
            language="en"
        )
        
        # Score-Emoji
        score_emoji = "🟢" if scan_result.overall_score >= 80 else \
                      "🟡" if scan_result.overall_score >= 60 else "🔴"
        
        # Status text
        status_text = {
            "passed": "✅ Good Security Posture",
            "warning": "⚠️  Needs Attention",
            "failed": "❌ Critical Issues Found"
        }.get(scan_result.status, "❓ Unknown")
        
        lines = [
            f"# {config.title}",
            "",
            f"**Generated:** {scan_result.timestamp}",
            f"**Project:** `{scan_result.path}`",
            f"**Scan Duration:** {scan_result.scan_duration_seconds:.1f}s",
            "",
            "---",
            "",
            "## 📊 Overall Security Score",
            "",
            f"### {score_emoji} **{scan_result.overall_score}/100** - {status_text}",
            "",
        ]
        
        # Tool Summary Table
        lines.extend([
            "## 🔍 Security Tool Results",
            "",
            "| Tool | Status | Critical | High | Medium | Low |",
            "|------|--------|----------|------|--------|-----|",
        ])
        
        for tool_key, result in scan_result.tools.items():
            status_emoji = {
                "passed": "✅",
                "warning": "⚠️",
                "failed": "❌",
                "skipped": "⏭️",
                "error": "🚨"
            }.get(result.status, "❓")
            
            summary = result.summary
            lines.append(
                f"| {tool_key.upper()} {status_emoji} | {result.status} | "
                f"{summary.get('critical', 0)} | {summary.get('high', 0)} | "
                f"{summary.get('medium', 0)} | {summary.get('low', 0)} |"
            )
        
        lines.append("")
        
        # Compliance Status
        if scan_result.compliance:
            lines.extend([
                "## 📋 Compliance Status",
                "",
                "| Framework | Score | Status |",
                "|-----------|-------|--------|",
            ])
            
            for framework, data in scan_result.compliance.items():
                score = data.get("score", 0)
                status = data.get("status", "unknown")
                status_emoji = "✅" if status == "pass" else "⚠️" if status == "warning" else "❌"
                name = data.get("name", framework)
                
                lines.append(f"| {name} | {score:.1f}% | {status_emoji} {status.upper()} |")
            
            lines.append("")
        
        # Top Priority Fixes
        if scan_result.top_fixes:
            lines.extend([
                "## 🎯 Top Priority Fixes",
                "",
            ])
            
            for fix in scan_result.top_fixes[:5]:
                severity_emoji = "🔴" if fix["severity"] == "CRITICAL" else "🟠"
                lines.append(
                    f"{fix['priority']}. {severity_emoji} **[{fix['tool'].upper()}]** "
                    f"{fix['action']}"
                )
            
            lines.append("")
        
        # Recommendations
        lines.extend([
            "## 💡 Recommendations",
            "",
        ])
        
        if scan_result.overall_score < 60:
            lines.append("⚠️  **Immediate action required.** Multiple critical security issues detected.")
        elif scan_result.overall_score < 80:
            lines.append("🔧 **Security improvements recommended.** Address high-severity issues within 2 weeks.")
        else:
            lines.append("✅ **Good security posture.** Continue regular security scans and monitoring.")
        
        lines.extend([
            "",
            "---",
            "",
            "*Report generated by SIN-Code-Security-Bundle*",
            f"*© {datetime.now().year} Family Team Projects*",
        ])
        
        return "\n".join(lines)
    
    def generate_technical_report(
        self,
        scan_result,
        config: Optional[ReportConfig] = None
    ) -> str:
        """
        Generiert einen detaillierten Technical Report.
        
        Args:
            scan_result: BundleScanResult
            config: Report-Konfiguration
        
        Returns:
            Technischer Report als Markdown
        """
        config = config or ReportConfig(
            title="Technical Security Report",
            format="markdown"
        )
        
        lines = [
            f"# {config.title}",
            "",
            f"**Generated:** {scan_result.timestamp}",
            f"**Project:** `{scan_result.path}`",
            f"**Overall Score:** {scan_result.overall_score}/100",
            f"**Status:** {scan_result.status.upper()}",
            "",
            "---",
            "",
        ]
        
        # Detailed Tool Results
        for tool_key, result in scan_result.tools.items():
            if result.status == "skipped":
                continue
            
            tool_info = {
                "sca": ("📦", "Software Composition Analysis"),
                "container": ("🐳", "Container Security"),
                "iac": ("🏗️", "Infrastructure as Code"),
                "license": ("📜", "License Compliance"),
                "dast": ("🎯", "Dynamic Application Security Testing")
            }.get(tool_key, ("🔍", tool_key))
            
            emoji, name = tool_info
            
            lines.extend([
                f"## {emoji} {name}",
                "",
                f"**Status:** {result.status.upper()}",
                f"**Scan Duration:** {result.scan_duration_seconds:.1f}s",
                "",
            ])
            
            if result.summary:
                lines.append("### Summary")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(result.summary, indent=2))
                lines.append("```")
                lines.append("")
            
            if result.violations:
                lines.append("### Violations")
                lines.append("")
                
                for i, violation in enumerate(result.violations[:20], 1):
                    severity = violation.get("severity", "UNKNOWN")
                    lines.append(f"{i}. **[{severity}]** {json.dumps(violation, indent=2)[:200]}...")
                
                if len(result.violations) > 20:
                    lines.append(f"")
                    lines.append(f"*... and {len(result.violations) - 20} more violations*")
                
                lines.append("")
            
            if result.error:
                lines.extend([
                    "### ⚠️  Error",
                    "",
                    f"```",
                    result.error,
                    f"```",
                    "",
                ])
        
        # Compliance Details
        if scan_result.compliance:
            lines.extend([
                "## 📋 Compliance Details",
                "",
            ])
            
            for framework, data in scan_result.compliance.items():
                lines.extend([
                    f"### {data.get('name', framework)}",
                    "",
                    f"- **Score:** {data.get('score', 0):.1f}%",
                    f"- **Status:** {data.get('status', 'unknown').upper()}",
                    f"- **Total Issues:** {data.get('total_issues', 0)}",
                    "",
                ])
        
        # Remediation Plan
        if scan_result.top_fixes:
            lines.extend([
                "## 🛠️  Remediation Plan",
                "",
                "### Priority Actions",
                "",
            ])
            
            for fix in scan_result.top_fixes:
                lines.extend([
                    f"#### {fix['priority']}. [{fix['severity']}] {fix['action']}",
                    "",
                    f"- **Tool:** {fix['tool_name']}",
                    f"- **Severity:** {fix['severity']}",
                    "",
                    "```json",
                    json.dumps(fix.get("violation", {}), indent=2),
                    "```",
                    "",
                ])
        
        lines.extend([
            "---",
            "",
            "*Report generated by SIN-Code-Security-Bundle*",
            f"*© {datetime.now().year} Family Team Projects*",
        ])
        
        return "\n".join(lines)
    
    def generate_html_dashboard(self, scan_result) -> str:
        """
        Generiert ein interaktives HTML-Dashboard.
        
        Args:
            scan_result: BundleScanResult
        
        Returns:
            HTML-Dashboard als String
        """
        # Use Jinja2 template if available
        if self.jinja_env:
            try:
                template = self.jinja_env.get_template("dashboard.html")
                return template.render(result=scan_result, json=json)
            except Exception:
                pass
        
        # Fallback: Generate simple HTML
        score_color = "#10b981" if scan_result.overall_score >= 80 else \
                      "#f59e0b" if scan_result.overall_score >= 60 else "#ef4444"
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SIN-Code Security Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #38bdf8; margin-bottom: 1rem; }}
        .score-card {{
            background: #1e293b;
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            text-align: center;
            border: 2px solid {score_color};
        }}
        .score {{
            font-size: 4rem;
            font-weight: bold;
            color: {score_color};
        }}
        .tools-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .tool-card {{
            background: #1e293b;
            border-radius: 8px;
            padding: 1.5rem;
        }}
        .tool-name {{ font-size: 1.2rem; font-weight: bold; margin-bottom: 1rem; }}
        .status-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.875rem;
            font-weight: bold;
        }}
        .status-passed {{ background: #10b981; color: white; }}
        .status-warning {{ background: #f59e0b; color: white; }}
        .status-failed {{ background: #ef4444; color: white; }}
        .status-skipped {{ background: #64748b; color: white; }}
        .metric {{ margin: 0.5rem 0; }}
        .metric-label {{ color: #94a3b8; }}
        .metric-value {{ font-weight: bold; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #1e293b;
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid #334155;
        }}
        th {{ background: #0f172a; color: #38bdf8; }}
        .fixes-list {{ list-style: none; }}
        .fix-item {{
            background: #1e293b;
            padding: 1rem;
            margin-bottom: 0.5rem;
            border-radius: 8px;
            border-left: 4px solid #ef4444;
        }}
        .fix-item.high {{ border-left-color: #f59e0b; }}
        .fix-item.critical {{ border-left-color: #ef4444; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 SIN-Code Security Dashboard</h1>
        <p>Project: <code>{scan_result.path}</code></p>
        <p>Generated: {scan_result.timestamp}</p>
        
        <div class="score-card">
            <div class="score">{scan_result.overall_score}/100</div>
            <div>Overall Security Score</div>
            <div style="margin-top: 1rem; font-size: 1.5rem;">
                {scan_result.status.upper()}
            </div>
        </div>
        
        <h2>🔍 Security Tools</h2>
        <div class="tools-grid">
"""
        
        for tool_key, result in scan_result.tools.items():
            status_class = f"status-{result.status}"
            
            html += f"""
            <div class="tool-card">
                <div class="tool-name">{tool_key.upper()}</div>
                <span class="status-badge {status_class}">{result.status.upper()}</span>
                <div class="metric">
                    <span class="metric-label">Critical:</span>
                    <span class="metric-value">{result.summary.get('critical', 0)}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">High:</span>
                    <span class="metric-value">{result.summary.get('high', 0)}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Medium:</span>
                    <span class="metric-value">{result.summary.get('medium', 0)}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Duration:</span>
                    <span class="metric-value">{result.scan_duration_seconds:.1f}s</span>
                </div>
            </div>
"""
        
        html += """
        </div>
"""
        
        # Compliance Table
        if scan_result.compliance:
            html += """
        <h2>📋 Compliance Status</h2>
        <table>
            <thead>
                <tr>
                    <th>Framework</th>
                    <th>Score</th>
                    <th>Status</th>
                    <th>Issues</th>
                </tr>
            </thead>
            <tbody>
"""
            for framework, data in scan_result.compliance.items():
                html += f"""
                <tr>
                    <td>{data.get('name', framework)}</td>
                    <td>{data.get('score', 0):.1f}%</td>
                    <td>{data.get('status', 'unknown').upper()}</td>
                    <td>{data.get('total_issues', 0)}</td>
                </tr>
"""
            html += """
            </tbody>
        </table>
"""
        
        # Top Fixes
        if scan_result.top_fixes:
            html += """
        <h2>🎯 Top Priority Fixes</h2>
        <ul class="fixes-list">
"""
            for fix in scan_result.top_fixes[:5]:
                severity_class = fix["severity"].lower()
                html += f"""
            <li class="fix-item {severity_class}">
                <strong>{fix['priority']}. [{fix['severity']}]</strong>
                {fix['action']}
                <br><small>Tool: {fix['tool_name']}</small>
            </li>
"""
            html += """
        </ul>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        return html
    
    def save_report(self, content: str, output_path: str):
        """Speichert den Report in eine Datei."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(content, encoding="utf-8")
        print(f"✅ Report saved to: {output_path}")
    
    def generate_pdf_report(self, html_content: str, output_path: str):
        """Generiert einen PDF-Report aus HTML."""
        try:
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(output_path)
            print(f"✅ PDF report saved to: {output_path}")
        except ImportError:
            print("⚠️  WeasyPrint nicht installiert. Bitte installieren: pip install weasyprint")
            # Fallback: Save as HTML
            html_path = output_path.replace(".pdf", ".html")
            self.save_report(html_content, html_path)
