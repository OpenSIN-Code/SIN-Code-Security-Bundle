"""Tests fuer ComplianceDashboard."""

import pytest

from src.tools.bundle_scanner import BundleScanResult, ToolResult
from src.tools.compliance_dashboard import ComplianceDashboard, ReportConfig


def test_compliance_dashboard_init():
    """Test ComplianceDashboard initialization."""
    dashboard = ComplianceDashboard()
    assert dashboard is not None


def test_report_config_model():
    """Test ReportConfig Pydantic model."""
    config = ReportConfig(
        title="Test Report",
        format="markdown",
        include_executive_summary=True,
        include_technical_details=False,
        language="de"
    )
    
    assert config.title == "Test Report"
    assert config.format == "markdown"
    assert config.language == "de"


def test_generate_executive_summary():
    """Test executive summary generation."""
    dashboard = ComplianceDashboard()
    
    scan_result = BundleScanResult(
        path="./my-project",
        overall_score=72,
        status="warning",
        tools={
            "sca": ToolResult(
                tool_name="sca",
                status="warning",
                summary={"critical": 0, "high": 3, "medium": 12, "low": 45},
                scan_duration_seconds=15.0
            ),
        },
        compliance={
            "cis": {"name": "CIS Benchmarks", "score": 94.6, "status": "pass"},
            "nist": {"name": "NIST 800-53", "score": 78.3, "status": "warning"},
        },
        top_fixes=[
            {
                "priority": 1,
                "tool": "sca",
                "tool_name": "SCA",
                "severity": "HIGH",
                "action": "Update axios to latest version",
                "violation": {}
            }
        ],
        scan_duration_seconds=120.5,
        timestamp="2026-06-06T12:00:00Z"
    )
    
    summary = dashboard.generate_executive_summary(scan_result)
    
    assert "# Executive Security Summary" in summary
    assert "72/100" in summary
    assert "CIS Benchmarks" in summary
    assert "NIST 800-53" in summary
    assert "axios" in summary


def test_generate_technical_report():
    """Test technical report generation."""
    dashboard = ComplianceDashboard()
    
    scan_result = BundleScanResult(
        path="./my-project",
        overall_score=65,
        status="warning",
        tools={
            "sca": ToolResult(
                tool_name="sca",
                status="warning",
                summary={"critical": 0, "high": 2, "medium": 5, "low": 10},
                violations=[
                    {"severity": "HIGH", "package": "test-pkg", "cve": "CVE-2024-1"}
                ],
                scan_duration_seconds=15.0
            ),
        },
        compliance={},
        top_fixes=[],
        scan_duration_seconds=60.0,
        timestamp="2026-06-06T12:00:00Z"
    )
    
    report = dashboard.generate_technical_report(scan_result)
    
    assert "# Technical Security Report" in report
    assert "65/100" in report
    assert "Software Composition Analysis" in report
    assert "CVE-2024-1" in report


def test_generate_html_dashboard():
    """Test HTML dashboard generation."""
    dashboard = ComplianceDashboard()
    
    scan_result = BundleScanResult(
        path="./my-project",
        overall_score=85,
        status="passed",
        tools={
            "sca": ToolResult(
                tool_name="sca",
                status="passed",
                summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
                scan_duration_seconds=10.0
            ),
        },
        compliance={},
        top_fixes=[],
        scan_duration_seconds=10.0,
        timestamp="2026-06-06T12:00:00Z"
    )
    
    html = dashboard.generate_html_dashboard(scan_result)
    
    assert "<!DOCTYPE html>" in html
    assert "SIN-Code Security Dashboard" in html
    assert "85/100" in html
    assert "./my-project" in html


def test_score_emoji_logic():
    """Test score emoji logic."""
    dashboard = ComplianceDashboard()
    
    # High score (green)
    result_high = BundleScanResult(
        path=".", overall_score=85, status="passed", tools={},
        compliance={}, top_fixes=[], scan_duration_seconds=10.0, timestamp=""
    )
    summary = dashboard.generate_executive_summary(result_high)
    assert "🟢" in summary
    
    # Medium score (yellow)
    result_medium = BundleScanResult(
        path=".", overall_score=70, status="warning", tools={},
        compliance={}, top_fixes=[], scan_duration_seconds=10.0, timestamp=""
    )
    summary = dashboard.generate_executive_summary(result_medium)
    assert "🟡" in summary
    
    # Low score (red)
    result_low = BundleScanResult(
        path=".", overall_score=45, status="failed", tools={},
        compliance={}, top_fixes=[], scan_duration_seconds=10.0, timestamp=""
    )
    summary = dashboard.generate_executive_summary(result_low)
    assert "🔴" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
