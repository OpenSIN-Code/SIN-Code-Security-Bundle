"""Report generation for SIN-Code Security Bundle.

Provides executive and technical report generation from security scan results.

Docs: report_generator.doc.md
"""

from datetime import datetime
from typing import Dict, Any, List, Optional


class ReportGenerator:
    """Generates executive and technical reports from security scan results."""

    def __init__(self, templates_dir: Optional[str] = None):
        """Initialize the report generator.

        Args:
            templates_dir: Optional path to custom templates directory.
        """
        self.templates_dir = templates_dir or "templates/reports"

    def generate_executive_report(self, result: Any, report_format: str = "markdown") -> str:
        """Generate an executive-friendly report.

        Args:
            result: Security bundle result
            report_format: Output format (markdown, json, html)

        Returns:
            Formatted report as string.
        """
        if report_format == "json":
            import json
            return json.dumps(result.model_dump() if hasattr(result, "model_dump") else result, indent=2)

        if report_format == "html":
            return self._generate_html_executive_report(result)

        return self._generate_markdown_executive_report(result)

    def generate_technical_report(self, result: Any, detailed_results: Dict[str, Any], report_format: str = "markdown") -> str:
        """Generate a detailed technical report.

        Args:
            result: Security bundle result
            detailed_results: Detailed results from each tool
            report_format: Output format (markdown, json, html)

        Returns:
            Formatted report as string.
        """
        if report_format == "json":
            import json
            data = {
                "summary": result.model_dump() if hasattr(result, "model_dump") else result,
                "details": detailed_results
            }
            return json.dumps(data, indent=2)

        if report_format == "html":
            return self._generate_html_technical_report(result, detailed_results)

        return self._generate_markdown_technical_report(result, detailed_results)

    def _generate_markdown_executive_report(self, result: Any) -> str:
        """Generate markdown executive report."""
        data = result.model_dump() if hasattr(result, "model_dump") else result

        report = f"""# Security Executive Summary

**Project**: {data.get('target_path', 'Unknown')}
**Date**: {datetime.now().strftime('%Y-%m-%d')}
**Overall Score**: {data.get('overall_score', 0)}/100
**Status**: {data.get('overall_status', 'Unknown')}

## Overview

This security scan evaluated the project using 5 industry-standard security tools:

- **Software Composition Analysis (SCA)**: Dependency vulnerability scanning
- **Container Security**: Container image scanning and Dockerfile audit
- **Infrastructure as Code (IaC)**: Terraform, Kubernetes, and CloudFormation security scanning
- **License Compliance**: Open source license compliance checking
- **Dynamic Application Security Testing (DAST)**: Web application vulnerability scanning

## Scan Results Summary

| Tool | Status | Findings | Critical | High | Medium | Low |
|------|--------|----------|----------|------|--------|-----|
"""

        for tool in data.get('tools', []):
            report += f"| {tool.get('tool_name', 'N/A')} | {tool.get('status', 'N/A')} | {tool.get('findings_count', 0)} | {tool.get('critical_count', 0)} | {tool.get('high_count', 0)} | {tool.get('medium_count', 0)} | {tool.get('low_count', 0)} |\n"

        report += "\n## Compliance Status\n\n"
        for cs in data.get('compliance_scores', []):
            status = "✅" if cs.get('status') == 'pass' else "⚠️" if cs.get('status') == 'warning' else "❌"
            report += f"- {status} {cs.get('framework', 'N/A')}: {cs.get('score', 0)}% ({cs.get('checks_passed', 0)}/{cs.get('checks_total', 0)} checks passed)\n"

        report += "\n## Key Recommendations\n\n"
        for i, rec in enumerate(data.get('recommendations', []), 1):
            report += f"{i}. {rec}\n"

        report += "\n## Risk Assessment\n\n"
        total_critical = sum(t.get('critical_count', 0) for t in data.get('tools', []))
        total_high = sum(t.get('high_count', 0) for t in data.get('tools', []))
        total_medium = sum(t.get('medium_count', 0) for t in data.get('tools', []))

        if total_critical > 0:
            report += f"**Critical Risk**: {total_critical} critical issues found. Immediate action required.\n\n"
        if total_high > 0:
            report += f"**High Risk**: {total_high} high severity issues found. Address within 48 hours.\n\n"
        if total_medium > 0:
            report += f"**Medium Risk**: {total_medium} medium severity issues found. Address within 1 week.\n\n"

        report += "\n### Next Steps\n\n"
        report += "1. Review the detailed technical report for specific findings and remediation steps\n"
        report += "2. Prioritize critical and high severity issues for immediate remediation\n"
        report += "3. Implement continuous security monitoring with automated scans\n"
        report += "4. Schedule follow-up scan to verify remediation effectiveness\n"

        report += f"\n---\n*Report generated by SIN-Code Security Bundle*\n"

        return report

    def _generate_markdown_technical_report(self, result: Any, detailed_results: Dict[str, Any]) -> str:
        """Generate markdown technical report."""
        data = result.model_dump() if hasattr(result, "model_dump") else result

        report = f"""# Technical Security Report

## Project: {data.get('target_path', 'Unknown')}

**Date**: {datetime.now().strftime('%Y-%m-%d')}
**Overall Score**: {data.get('overall_score', 0)}/100
**Status**: {data.get('overall_status', 'Unknown')}
**Scan Duration**: {data.get('scan_duration_seconds', 0)} seconds

---

## 1. Software Composition Analysis (SCA)

### Dependency Vulnerabilities

"""

        sca_details = detailed_results.get('sca', {})
        if sca_details:
            report += "| Severity | Count | Details |\n|----------|-------|---------|\n"
            for severity in ['critical', 'high', 'medium', 'low']:
                issues = sca_details.get(f'{severity}_issues', [])
                count = len(issues) if isinstance(issues, list) else sca_details.get(f'{severity}_count', 0)
                report += f"| {severity.capitalize()} | {count} | See details below |\n"
            report += "\n### Recommendations\n\n"
            for rec in sca_details.get('recommendations', []):
                report += f"- {rec}\n"
        else:
            report += "No SCA details available.\n"

        report += "\n---\n\n## 2. Container Security\n\n"
        container_details = detailed_results.get('container', {})
        if container_details:
            report += "### Container Image Issues\n\n"
            for issue in container_details.get('image_issues', []):
                report += f"- **{issue.get('severity', 'N/A')}**: {issue.get('rule_id', 'N/A')} - {issue.get('description', 'N/A')}\n"
            report += "\n### Dockerfile Audit\n\n"
            for issue in container_details.get('dockerfile_issues', []):
                report += f"- **{issue.get('severity', 'N/A')}**: {issue.get('rule_id', 'N/A')} (Line {issue.get('line', 'N/A')})\n"
                report += f"  - {issue.get('description', 'N/A')}\n"
            report += "\n### Recommendations\n\n"
            for rec in container_details.get('recommendations', []):
                report += f"- {rec}\n"
        else:
            report += "No container details available.\n"

        report += "\n---\n\n## 3. Infrastructure as Code (IaC)\n\n"
        iac_details = detailed_results.get('iac', {})
        if iac_details:
            report += "### Terraform Issues\n\n"
            for issue in iac_details.get('terraform_issues', []):
                report += f"- **{issue.get('severity', 'N/A')}**: {issue.get('rule_id', 'N/A')} (Resource: {issue.get('resource', 'N/A')})\n"
            report += "\n### Kubernetes Issues\n\n"
            for issue in iac_details.get('kubernetes_issues', []):
                report += f"- **{issue.get('severity', 'N/A')}**: {issue.get('rule_id', 'N/A')} (Resource: {issue.get('resource_name', 'N/A')})\n"
            report += "\n### Recommendations\n\n"
            for rec in iac_details.get('recommendations', []):
                report += f"- {rec}\n"
        else:
            report += "No IaC details available.\n"

        report += "\n---\n\n## 4. License Compliance\n\n"
        license_details = detailed_results.get('license', {})
        if license_details:
            report += "### License Findings\n\n"
            for finding in license_details.get('findings', []):
                report += f"- **{finding.get('status', 'N/A')}**: {finding.get('package', 'N/A')} ({finding.get('license', 'N/A')})\n"
            report += "\n### Recommendations\n\n"
            for rec in license_details.get('recommendations', []):
                report += f"- {rec}\n"
        else:
            report += "No license details available.\n"

        report += "\n---\n\n## 5. Dynamic Application Security Testing (DAST)\n\n"
        dast_details = detailed_results.get('dast', {})
        if dast_details:
            report += "### Web Application Findings\n\n"
            for finding in dast_details.get('findings', []):
                report += f"- **{finding.get('severity', 'N/A')}**: {finding.get('name', 'N/A')} ({finding.get('tool', 'N/A')})\n"
            report += "\n### Recommendations\n\n"
            for rec in dast_details.get('recommendations', []):
                report += f"- {rec}\n"
        else:
            report += "No DAST details available.\n"

        report += "\n---\n\n*Report generated by SIN-Code Security Bundle*\n"

        return report

    def _generate_html_executive_report(self, result: Any) -> str:
        """Generate HTML executive report."""
        data = result.model_dump() if hasattr(result, "model_dump") else result

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Executive Summary</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .pass {{ color: green; }}
        .warning {{ color: orange; }}
        .fail {{ color: red; }}
    </style>
</head>
<body>
    <h1>Security Executive Summary</h1>
    <p><strong>Project:</strong> {data.get('target_path', 'Unknown')}</p>
    <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d')}</p>
    <p><strong>Overall Score:</strong> {data.get('overall_score', 0)}/100</p>
    <p><strong>Status:</strong> <span class="{data.get('overall_status', 'unknown')}">{data.get('overall_status', 'Unknown')}</span></p>

    <h2>Scan Results</h2>
    <table>
        <tr>
            <th>Tool</th>
            <th>Status</th>
            <th>Findings</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
        </tr>
"""
        for tool in data.get('tools', []):
            status_class = tool.get('status', 'unknown')
            html += f"""        <tr>
            <td>{tool.get('tool_name', 'N/A')}</td>
            <td class="{status_class}">{tool.get('status', 'N/A')}</td>
            <td>{tool.get('findings_count', 0)}</td>
            <td>{tool.get('critical_count', 0)}</td>
            <td>{tool.get('high_count', 0)}</td>
            <td>{tool.get('medium_count', 0)}</td>
            <td>{tool.get('low_count', 0)}</td>
        </tr>
"""

        html += """    </table>

    <h2>Compliance Status</h2>
    <ul>
"""
        for cs in data.get('compliance_scores', []):
            status = cs.get('status', 'unknown')
            html += f"        <li>{cs.get('framework', 'N/A')}: {cs.get('score', 0)}% ({cs.get('checks_passed', 0)}/{cs.get('checks_total', 0)} checks passed)</li>\n"

        html += """    </ul>

    <h2>Key Recommendations</h2>
    <ol>
"""
        for i, rec in enumerate(data.get('recommendations', []), 1):
            html += f"        <li>{rec}</li>\n"

        html += """    </ol>

    <p><em>Report generated by SIN-Code Security Bundle</em></p>
</body>
</html>
"""
        return html

    def _generate_html_technical_report(self, result: Any, detailed_results: Dict[str, Any]) -> str:
        """Generate HTML technical report."""
        data = result.model_dump() if hasattr(result, "model_dump") else result

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Technical Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; }}
        h3 {{ color: #999; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .pass {{ color: green; }}
        .warning {{ color: orange; }}
        .fail {{ color: red; }}
    </style>
</head>
<body>
    <h1>Technical Security Report</h1>
    <p><strong>Project:</strong> {data.get('target_path', 'Unknown')}</p>
    <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d')}</p>
    <p><strong>Overall Score:</strong> {data.get('overall_score', 0)}/100</p>
    <p><strong>Status:</strong> <span class="{data.get('overall_status', 'unknown')}">{data.get('overall_status', 'Unknown')}</span></p>

    <p><em>Detailed technical report generated by SIN-Code Security Bundle</em></p>
</body>
</html>
"""
        return html

    def generate_executive_summary(self, result: Any) -> str:
        """Generate a concise executive summary (one-page)."""
        data = result.model_dump() if hasattr(result, "model_dump") else result

        total_findings = data.get('total_findings', 0)
        critical = data.get('critical', 0) or sum(t.get('critical_count', 0) for t in data.get('tools', []))
        high = data.get('high', 0) or sum(t.get('high_count', 0) for t in data.get('tools', []))
        medium = data.get('medium', 0) or sum(t.get('medium_count', 0) for t in data.get('tools', []))
        low = data.get('low', 0) or sum(t.get('low_count', 0) for t in data.get('tools', []))

        summary = f"""## Security Executive Summary

**Project**: {data.get('target_path', 'Unknown')}
**Date**: {datetime.now().strftime('%Y-%m-%d')}
**Overall Score**: {data.get('overall_score', 0)}/100
**Status**: {data.get('overall_status', 'Unknown')}

### Findings Summary

- **Total Findings**: {total_findings}
- **Critical**: {critical}
- **High**: {high}
- **Medium**: {medium}
- **Low**: {low}

### Compliance Status

"""
        for cs in data.get('compliance_scores', []):
            status = "✅" if cs.get('status') == 'pass' else "⚠️" if cs.get('status') == 'warning' else "❌"
            summary += f"- {status} {cs.get('framework', 'N/A')}: {cs.get('score', 0)}%\n"

        summary += "\n### Top Recommendations\n\n"
        for i, rec in enumerate(data.get('recommendations', [])[:5], 1):
            summary += f"{i}. {rec}\n"

        return summary
