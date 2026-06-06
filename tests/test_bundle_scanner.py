"""Tests fuer BundleScanner."""

import tempfile
from pathlib import Path

import pytest

from src.tools.bundle_scanner import BundleScanner, BundleScanResult, ToolResult


def test_bundle_scanner_init():
    """Test BundleScanner initialization."""
    scanner = BundleScanner()
    assert scanner is not None
    assert scanner.TOOLS is not None
    assert len(scanner.TOOLS) == 5
    scanner.close()


def test_tools_definition():
    """Test tools are properly defined."""
    scanner = BundleScanner()
    
    assert "sca" in scanner.TOOLS
    assert "container" in scanner.TOOLS
    assert "iac" in scanner.TOOLS
    assert "license" in scanner.TOOLS
    assert "dast" in scanner.TOOLS
    
    for tool_key, tool_info in scanner.TOOLS.items():
        assert "name" in tool_info
        assert "emoji" in tool_info
        assert "weight" in tool_info
        assert "mcp_tool" in tool_info
    
    scanner.close()


def test_compliance_frameworks():
    """Test compliance frameworks are defined."""
    scanner = BundleScanner()
    
    assert "cis" in scanner.COMPLIANCE_FRAMEWORKS
    assert "nist" in scanner.COMPLIANCE_FRAMEWORKS
    assert "soc2" in scanner.COMPLIANCE_FRAMEWORKS
    assert "gdpr" in scanner.COMPLIANCE_FRAMEWORKS
    assert "owasp" in scanner.COMPLIANCE_FRAMEWORKS
    
    for fw_key, fw_info in scanner.COMPLIANCE_FRAMEWORKS.items():
        assert "name" in fw_info
        assert "weight" in fw_info
    
    scanner.close()


def test_calculate_overall_score_passed():
    """Test overall score calculation for passed status."""
    scanner = BundleScanner()
    
    tools = {
        "sca": ToolResult(tool_name="sca", status="passed",
                          summary={"critical": 0, "high": 0, "medium": 0, "low": 0}),
        "container": ToolResult(tool_name="container", status="passed",
                                summary={"critical": 0, "high": 0, "medium": 0, "low": 0}),
    }
    
    score = scanner._calculate_overall_score(tools)
    assert score == 100
    
    scanner.close()


def test_calculate_overall_score_warning():
    """Test overall score calculation for warning status."""
    scanner = BundleScanner()
    
    tools = {
        "sca": ToolResult(
            tool_name="sca",
            status="warning",
            summary={"critical": 0, "high": 3, "medium": 5, "low": 0}
        ),
    }
    
    score = scanner._calculate_overall_score(tools)
    # 100 - (3*10) - (5*3) = 100 - 30 - 15 = 55
    assert score == 55
    
    scanner.close()


def test_calculate_overall_score_failed():
    """Test overall score calculation for failed status."""
    scanner = BundleScanner()
    
    tools = {
        "sca": ToolResult(
            tool_name="sca",
            status="failed",
            summary={"critical": 1, "high": 0, "medium": 0, "low": 0}
        ),
    }
    
    score = scanner._calculate_overall_score(tools)
    assert score == 30  # Fixed score for failed
    
    scanner.close()


def test_determine_overall_status():
    """Test overall status determination."""
    scanner = BundleScanner()
    
    # All passed
    tools_passed = {
        "sca": ToolResult(tool_name="sca", status="passed"),
        "container": ToolResult(tool_name="container", status="passed"),
    }
    assert scanner._determine_overall_status(tools_passed, "high") == "passed"
    
    # Has warning
    tools_warning = {
        "sca": ToolResult(tool_name="sca", status="passed"),
        "container": ToolResult(tool_name="container", status="warning"),
    }
    assert scanner._determine_overall_status(tools_warning, "high") == "warning"
    
    # Has failed
    tools_failed = {
        "sca": ToolResult(tool_name="sca", status="passed"),
        "container": ToolResult(tool_name="container", status="failed"),
    }
    assert scanner._determine_overall_status(tools_failed, "high") == "failed"
    
    scanner.close()


def test_generate_top_fixes():
    """Test top fixes generation."""
    scanner = BundleScanner()
    
    tools = {
        "sca": ToolResult(
            tool_name="sca",
            status="failed",
            violations=[
                {"severity": "CRITICAL", "package": "openssl", "cve": "CVE-2024-1"},
                {"severity": "HIGH", "package": "axios", "cve": "CVE-2024-2"},
            ]
        ),
    }
    
    fixes = scanner._generate_top_fixes(tools)
    
    assert len(fixes) >= 2
    assert fixes[0]["severity"] == "CRITICAL"
    assert fixes[0]["priority"] == 1
    assert "openssl" in fixes[0]["action"].lower() or "Update" in fixes[0]["action"]
    
    scanner.close()


def test_calculate_compliance_scores():
    """Test compliance score calculation."""
    scanner = BundleScanner()
    
    tools = {
        "sca": ToolResult(
            tool_name="sca",
            status="warning",
            summary={"critical": 0, "high": 2, "medium": 3, "low": 0}
        ),
    }
    
    scores = scanner._calculate_compliance_scores(tools, ["cis", "nist"])
    
    assert "cis" in scores
    assert "nist" in scores
    assert "score" in scores["cis"]
    assert "status" in scores["cis"]
    
    scanner.close()


def test_full_scan_skip_tools():
    """Test full scan with skipped tools."""
    scanner = BundleScanner()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        result = scanner.full_scan(
            tmpdir,
            skip_tools=["sca", "container", "iac", "license", "dast"]
        )
        
        assert result is not None
        assert result.overall_score == 100  # No issues when all skipped
        assert result.status == "passed"
    
    scanner.close()


def test_bundle_scan_result_model():
    """Test BundleScanResult Pydantic model."""
    result = BundleScanResult(
        path="./my-project",
        overall_score=72,
        status="warning",
        tools={},
        compliance={"cis": {"score": 94.6, "status": "pass"}},
        top_fixes=[],
        scan_duration_seconds=120.5,
        timestamp="2026-06-06T12:00:00Z"
    )
    
    assert result.overall_score == 72
    assert result.status == "warning"
    assert result.compliance["cis"]["score"] == 94.6


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
