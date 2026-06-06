"""MCP Server fuer SIN-Code-Security-Bundle.

Bietet folgende Tools:
- sin_security_full_scan: Vollstaendiger Security-Scan ueber alle 5 Tools
- sin_security_blast_radius: Blast-Radius-Analyse
- sin_security_remediation_plan: Fix-Plan-Generierung
- sin_security_compliance_report: Compliance-Report
- sin_security_executive_summary: Executive Summary
- sin_security_dashboard: Interaktives Dashboard

Docs: server.doc.md
"""

import json
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).parent))

from tools.bundle_scanner import BundleScanner, BundleScanResult
from tools.compliance_dashboard import ComplianceDashboard, ReportConfig
from tools.remediation_engine import RemediationEngine


app = FastMCP("sin-code-security-bundle")
scanner = BundleScanner()
dashboard = ComplianceDashboard()
remediation = RemediationEngine()


@app.tool()
async def sin_security_full_scan(
    path: str,
    compliance: str = "",
    fail_on: str = "high",
    skip_tools: str = "",
    target_url: str = "",
    format: str = "json"
) -> str:
    """Fuehrt vollstaendigen Security-Scan ueber alle 5 Tools aus.
    
    Args:
        path: Pfad zum Projekt
        compliance: Komma-separierte Compliance-Frameworks (cis,nist,soc2,iso27001,gdpr,pci,owasp)
        fail_on: Severity-Schwelle (critical, high, medium, low)
        skip_tools: Komma-separierte Tools zum Ueberspringen (sca,container,iac,license,dast)
        target_url: URL fuer DAST-Scan (optional)
        format: Ausgabeformat (json oder text)
    
    Returns:
        Gesamt-Scan-Ergebnis mit allen Security-Tools
    """
    try:
        compliance_list = [c.strip() for c in compliance.split(",")] if compliance else None
        skip_list = [t.strip() for t in skip_tools.split(",")] if skip_tools else None
        target_url_val = target_url if target_url else None
        
        result = scanner.full_scan(
            path=path,
            compliance=compliance_list,
            fail_on=fail_on,
            skip_tools=skip_list,
            target_url=target_url_val
        )
        
        output = {
            "overall_score": result.overall_score,
            "status": result.status,
            "path": result.path,
            "timestamp": result.timestamp,
            "scan_duration_seconds": round(result.scan_duration_seconds, 2),
            "tools": {
                k: {
                    "status": v.status,
                    "summary": v.summary,
                    "violations_count": len(v.violations),
                    "duration": round(v.scan_duration_seconds, 2)
                }
                for k, v in result.tools.items()
            },
            "compliance": result.compliance,
            "top_fixes": result.top_fixes,
            "total_violations": sum(
                len(v.violations) for v in result.tools.values()
            )
        }
        
        if format == "json":
            return json.dumps(output, indent=2)
        else:
            score_emoji = "🟢" if result.overall_score >= 80 else \
                          "🟡" if result.overall_score >= 60 else "🔴"
            
            lines = [
                "🎯 SIN-Code Security Bundle Scan",
                "=" * 60,
                f"Project: {result.path}",
                f"Status: {result.status.upper()}",
                f"Overall Score: {score_emoji} {result.overall_score}/100",
                f"Duration: {result.scan_duration_seconds:.1f}s",
                "",
                "📊 Tool Results:",
            ]
            
            for tool_key, tool_result in result.tools.items():
                status_emoji = {"passed": "✅", "warning": "⚠️", "failed": "❌",
                                "skipped": "⏭️", "error": "🚨"}.get(tool_result.status, "❓")
                lines.append(f"  {status_emoji} {tool_key.upper()}: {tool_result.status}")
            
            if result.compliance:
                lines.append("")
                lines.append("📋 Compliance:")
                for fw, data in result.compliance.items():
                    emoji = "✅" if data["status"] == "pass" else "⚠️"
                    lines.append(f"  {emoji} {data['name']}: {data['score']:.1f}%")
            
            if result.top_fixes:
                lines.append("")
                lines.append("🎯 Top Fixes:")
                for fix in result.top_fixes[:5]:
                    lines.append(f"  {fix['priority']}. [{fix['severity']}] {fix['action']}")
            
            return "\n".join(lines)
    
    except Exception as e:
        return f"❌ Error: {str(e)}"
    finally:
        scanner.close()


@app.tool()
async def sin_security_blast_radius(
    vulnerability_id: str,
    project_path: str
) -> str:
    """Analysiert den Blast-Radius einer Vulnerability ueber alle Security-Domaenen.
    
    Args:
        vulnerability_id: CVE-ID oder Package-Name
        project_path: Pfad zum Projekt
    
    Returns:
        Cross-Tool Blast-Radius-Analyse
    """
    try:
        # Run scan first to get data
        result = scanner.full_scan(project_path, skip_tools=["dast"])
        
        blast_radius = {
            "vulnerability_id": vulnerability_id,
            "project_path": project_path,
            "affected_domains": {
                "sca": [],
                "container": [],
                "iac": [],
                "license": [],
                "dast": []
            },
            "impact_score": 0,
            "affected_services": [],
            "affected_endpoints": [],
            "remediation_priority": "high"
        }
        
        # Check each tool for the vulnerability
        for tool_key, tool_result in result.tools.items():
            for violation in tool_result.violations:
                pkg = violation.get("package", "")
                cve = violation.get("cve", "")
                
                if (vulnerability_id in pkg or 
                    vulnerability_id in cve or
                    vulnerability_id in str(violation)):
                    blast_radius["affected_domains"][tool_key].append(violation)
        
        # Calculate impact score
        affected_count = sum(
            len(v) for v in blast_radius["affected_domains"].values()
        )
        blast_radius["impact_score"] = min(100, affected_count * 20)
        
        if blast_radius["impact_score"] >= 80:
            blast_radius["remediation_priority"] = "critical"
        elif blast_radius["impact_score"] >= 50:
            blast_radius["remediation_priority"] = "high"
        else:
            blast_radius["remediation_priority"] = "medium"
        
        return json.dumps(blast_radius, indent=2)
    
    except Exception as e:
        return f"❌ Error: {str(e)}"
    finally:
        scanner.close()


@app.tool()
async def sin_security_remediation_plan(
    project_path: str,
    max_actions: int = 20,
    focus_areas: str = "critical,high",
    format: str = "json"
) -> str:
    """Generiert AI-gestuetzten Remediation-Plan ueber alle Security-Domaenen.
    
    Args:
        project_path: Pfad zum Projekt
        max_actions: Maximale Anzahl von Aktionen
        focus_areas: Komma-separierte Fokus-Bereiche
        format: Ausgabeformat (json oder markdown)
    
    Returns:
        Priorisierter Remediation-Plan
    """
    try:
        # Run scan first
        scan_result = scanner.full_scan(project_path)
        
        focus_list = [f.strip() for f in focus_areas.split(",")] if focus_areas else None
        plan = remediation.generate_plan(
            scan_result,
            max_actions=max_actions,
            focus_areas=focus_list
        )
        
        if format == "json":
            output = {
                "project_path": plan.project_path,
                "total_actions": plan.total_actions,
                "estimated_total_effort": plan.estimated_total_effort,
                "actions": [a.model_dump() for a in plan.actions],
                "cross_tool_dependencies": plan.cross_tool_dependencies,
                "verification_plan": plan.verification_plan
            }
            return json.dumps(output, indent=2)
        else:
            guide = remediation.generate_implementation_guide(plan)
            return guide
    
    except Exception as e:
        return f"❌ Error: {str(e)}"
    finally:
        scanner.close()


@app.tool()
async def sin_security_compliance_report(
    project_path: str,
    frameworks: str = "cis,nist,soc2",
    format: str = "markdown"
) -> str:
    """Generiert Compliance-Report fuer spezifische Frameworks.
    
    Args:
        project_path: Pfad zum Projekt
        frameworks: Komma-separierte Compliance-Frameworks
        format: Ausgabeformat (markdown, html, json)
    
    Returns:
        Compliance-Report
    """
    try:
        framework_list = [f.strip() for f in frameworks.split(",")]
        scan_result = scanner.full_scan(
            project_path,
            compliance=framework_list
        )
        
        config = ReportConfig(
            title=f"Compliance Report - {project_path}",
            format=format
        )
        
        if format == "html":
            content = dashboard.generate_html_dashboard(scan_result)
        elif format == "markdown":
            content = dashboard.generate_executive_summary(scan_result, config)
        else:
            content = json.dumps({
                "frameworks": scan_result.compliance,
                "overall_score": scan_result.overall_score,
                "status": scan_result.status
            }, indent=2)
        
        return content
    
    except Exception as e:
        return f"❌ Error: {str(e)}"
    finally:
        scanner.close()


@app.tool()
async def sin_security_executive_summary(
    project_path: str,
    format: str = "markdown"
) -> str:
    """Generiert Executive Summary fuer Management.
    
    Args:
        project_path: Pfad zum Projekt
        format: Ausgabeformat (markdown, html)
    
    Returns:
        Executive Summary Report
    """
    try:
        scan_result = scanner.full_scan(project_path)
        
        config = ReportConfig(
            title="Executive Security Summary",
            format=format,
            include_executive_summary=True,
            include_technical_details=False,
            include_remediation_plan=True,
            include_compliance_status=True
        )
        
        if format == "html":
            content = dashboard.generate_html_dashboard(scan_result)
        else:
            content = dashboard.generate_executive_summary(scan_result, config)
        
        return content
    
    except Exception as e:
        return f"❌ Error: {str(e)}"
    finally:
        scanner.close()


@app.tool()
async def sin_security_technical_report(
    project_path: str,
    output_path: str = ""
) -> str:
    """Generiert detaillierten Technical Report.
    
    Args:
        project_path: Pfad zum Projekt
        output_path: Optionaler Pfad zum Speichern
    
    Returns:
        Technical Report als Markdown
    """
    try:
        scan_result = scanner.full_scan(project_path)
        content = dashboard.generate_technical_report(scan_result)
        
        if output_path:
            dashboard.save_report(content, output_path)
        
        return content
    
    except Exception as e:
        return f"❌ Error: {str(e)}"
    finally:
        scanner.close()


@app.tool()
async def sin_security_html_dashboard(
    project_path: str,
    output_path: str = ""
) -> str:
    """Generiert interaktives HTML-Dashboard.
    
    Args:
        project_path: Pfad zum Projekt
        output_path: Optionaler Pfad zum Speichern
    
    Returns:
        HTML-Dashboard
    """
    try:
        scan_result = scanner.full_scan(project_path)
        html = dashboard.generate_html_dashboard(scan_result)
        
        if output_path:
            dashboard.save_report(html, output_path)
        
        return html
    
    except Exception as e:
        return f"❌ Error: {str(e)}"
    finally:
        scanner.close()


@app.tool()
async def sin_security_list_tools() -> str:
    """Listet alle verfuegbaren Security-Tools auf."""
    tools = []
    for key, info in scanner.TOOLS.items():
        tools.append({
            "key": key,
            "name": info["name"],
            "emoji": info["emoji"],
            "weight": info["weight"]
        })
    
    return json.dumps({"tools": tools}, indent=2)


@app.tool()
async def sin_security_list_compliance_frameworks() -> str:
    """Listet alle verfuegbaren Compliance-Frameworks auf."""
    frameworks = []
    for key, info in scanner.COMPLIANCE_FRAMEWORKS.items():
        frameworks.append({
            "key": key,
            "name": info["name"],
            "weight": info["weight"]
        })
    
    return json.dumps({"frameworks": frameworks}, indent=2)


if __name__ == "__main__":
    app.run()
