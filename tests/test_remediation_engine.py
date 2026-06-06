"""Tests fuer RemediationEngine."""

import pytest

from src.tools.bundle_scanner import BundleScanResult, ToolResult
from src.tools.remediation_engine import (
    RemediationEngine,
    RemediationPlan,
    RemediationAction,
)


def test_remediation_engine_init():
    """Test RemediationEngine initialization."""
    engine = RemediationEngine()
    assert engine is not None
    assert engine.REMEDIATION_TEMPLATES is not None


def test_remediation_action_model():
    """Test RemediationAction Pydantic model."""
    action = RemediationAction(
        priority=1,
        tool="sca",
        action="Update axios to latest version",
        description="Fix CVE-2024-1234",
        command="npm install axios@latest",
        files_to_modify=["package.json"],
        estimated_effort="low",
        risk_level="low",
        verification_steps=["Run tests", "Re-run SCA scan"]
    )
    
    assert action.priority == 1
    assert action.tool == "sca"
    assert len(action.verification_steps) == 2


def test_generate_plan():
    """Test remediation plan generation."""
    engine = RemediationEngine()
    
    scan_result = BundleScanResult(
        path="./my-project",
        overall_score=60,
        status="warning",
        tools={
            "sca": ToolResult(
                tool_name="sca",
                status="failed",
                violations=[
                    {"severity": "CRITICAL", "package": "openssl", "cve": "CVE-2024-1"},
                    {"severity": "HIGH", "package": "axios", "cve": "CVE-2024-2"},
                ],
                scan_duration_seconds=10.0
            ),
        },
        compliance={},
        top_fixes=[],
        scan_duration_seconds=10.0,
        timestamp="2026-06-06T12:00:00Z"
    )
    
    plan = engine.generate_plan(scan_result, max_actions=10)
    
    assert plan is not None
    assert plan.total_actions >= 2
    assert plan.actions[0].priority == 1
    assert plan.estimated_total_effort in ["low (1-2 days)", "medium (3-5 days)", "high (1-2 weeks)"]


def test_generate_plan_focus_areas():
    """Test plan generation with focus areas."""
    engine = RemediationEngine()
    
    scan_result = BundleScanResult(
        path="./my-project",
        overall_score=60,
        status="warning",
        tools={
            "sca": ToolResult(
                tool_name="sca",
                status="failed",
                violations=[
                    {"severity": "CRITICAL", "package": "pkg1", "cve": "CVE-1"},
                    {"severity": "HIGH", "package": "pkg2", "cve": "CVE-2"},
                    {"severity": "MEDIUM", "package": "pkg3", "cve": "CVE-3"},
                ],
                scan_duration_seconds=10.0
            ),
        },
        compliance={},
        top_fixes=[],
        scan_duration_seconds=10.0,
        timestamp=""
    )
    
    # Only critical
    plan = engine.generate_plan(scan_result, focus_areas=["critical"])
    assert all(a.priority > 0 for a in plan.actions)
    assert plan.total_actions == 1
    
    # Critical + High
    plan2 = engine.generate_plan(scan_result, focus_areas=["critical", "high"])
    assert plan2.total_actions == 2


def test_calculate_dependencies():
    """Test cross-tool dependency calculation."""
    engine = RemediationEngine()
    
    actions = [
        RemediationAction(
            priority=1, tool="sca", action="Fix SCA",
            description="", estimated_effort="low", risk_level="low"
        ),
        RemediationAction(
            priority=2, tool="container", action="Fix Container",
            description="", estimated_effort="medium", risk_level="medium"
        ),
    ]
    
    deps = engine._calculate_dependencies(actions)
    assert isinstance(deps, dict)
    assert "container" in deps
    assert "sca" in deps["container"]


def test_estimate_total_effort():
    """Test effort estimation."""
    engine = RemediationEngine()
    
    # Low effort
    low_actions = [
        RemediationAction(
            priority=1, tool="sca", action="A", description="",
            estimated_effort="low", risk_level="low"
        )
    ]
    assert "low" in engine._estimate_total_effort(low_actions)
    
    # High effort
    high_actions = [
        RemediationAction(
            priority=1, tool="dast", action="A", description="",
            estimated_effort="high", risk_level="high"
        )
    ]
    assert "high" in engine._estimate_total_effort(high_actions)
    
    # Empty
    assert engine._estimate_total_effort([]) == "none"


def test_generate_implementation_guide():
    """Test implementation guide generation."""
    engine = RemediationEngine()
    
    plan = RemediationPlan(
        project_path="./my-project",
        total_actions=2,
        estimated_total_effort="medium (3-5 days)",
        actions=[
            RemediationAction(
                priority=1,
                tool="sca",
                action="Update axios",
                description="Fix CVE",
                command="npm install axios@latest",
                files_to_modify=["package.json"],
                estimated_effort="low",
                risk_level="low",
                verification_steps=["Run tests"]
            ),
        ],
        cross_tool_dependencies={},
        verification_plan=["Run tests", "Deploy"]
    )
    
    guide = engine.generate_implementation_guide(plan)
    
    assert "# 🛠️  Security Remediation Implementation Guide" in guide
    assert "./my-project" in guide
    assert "Update axios" in guide
    assert "npm install axios@latest" in guide


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
