"""Remediation Engine: AI-gestützte Fix-Vorschläge über alle Security-Domänen.

Features:
- Cross-Tool Remediation Plans
- Automated Fix Generation
- Blast Radius Analysis
- Fix Verification

Docs: remediation_engine.doc.md
"""

import json
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class RemediationAction(BaseModel):
    """Eine einzelne Remediation-Aktion."""
    
    priority: int
    tool: str
    action: str
    description: str
    command: Optional[str] = None
    files_to_modify: List[str] = Field(default_factory=list)
    estimated_effort: str = "unknown"  # low, medium, high
    risk_level: str = "unknown"  # low, medium, high
    verification_steps: List[str] = Field(default_factory=list)


class RemediationPlan(BaseModel):
    """Vollständiger Remediation-Plan."""
    
    project_path: str
    total_actions: int
    estimated_total_effort: str
    actions: List[RemediationAction] = Field(default_factory=list)
    cross_tool_dependencies: Dict[str, List[str]] = Field(default_factory=dict)
    verification_plan: List[str] = Field(default_factory=list)


class RemediationEngine:
    """
    AI-gestützte Remediation Engine für Security-Issues.
    
    Usage:
        engine = RemediationEngine()
        plan = engine.generate_plan(scan_result)
        for action in plan.actions:
            print(f"{action.priority}. {action.action}")
    """
    
    # Remediation Templates für verschiedene Vulnerability-Typen
    REMEDIATION_TEMPLATES = {
        "sca": {
            "npm": {
                "update": "npm install {package}@latest",
                "audit": "npm audit fix",
                "verify": "npm audit"
            },
            "pip": {
                "update": "pip install --upgrade {package}",
                "verify": "pip check"
            },
            "go": {
                "update": "go get -u {package}",
                "verify": "go mod verify"
            }
        },
        "container": {
            "update_base": "Update base image in Dockerfile: FROM {base_image}:latest",
            "rebuild": "docker build -t {image_name}:$(date +%Y%m%d) .",
            "verify": "trivy image {image_name}:$(date +%Y%m%d)"
        },
        "iac": {
            "terraform": {
                "apply": "terraform plan && terraform apply",
                "verify": "checkov -d ."
            },
            "kubernetes": {
                "apply": "kubectl apply -f {manifest}",
                "verify": "kube-score score {manifest}"
            }
        },
        "license": {
            "replace": "Replace {package} with {alternative}",
            "verify": "scancode --license ."
        },
        "dast": {
            "fix_xss": "Implement output encoding and Content Security Policy",
            "fix_sqli": "Use prepared statements and parameterized queries",
            "verify": "Re-run DAST scan to verify fix"
        }
    }
    
    def __init__(self):
        self.remediation_history: List[RemediationPlan] = []
    
    def generate_plan(
        self,
        scan_result,
        max_actions: int = 20,
        focus_areas: Optional[List[str]] = None
    ) -> RemediationPlan:
        """
        Generiert einen umfassenden Remediation-Plan.
        
        Args:
            scan_result: BundleScanResult
            max_actions: Maximale Anzahl von Aktionen
            focus_areas: Fokus-Bereiche (z.B. ["critical", "high"])
        
        Returns:
            RemediationPlan mit priorisierten Aktionen
        """
        actions: List[RemediationAction] = []
        priority = 1
        
        # Collect all violations from all tools
        for tool_key, tool_result in scan_result.tools.items():
            if tool_result.status == "skipped":
                continue
            
            for violation in tool_result.violations:
                severity = violation.get("severity", "").upper()
                
                # Filter by focus areas if specified
                if focus_areas and severity.lower() not in [f.lower() for f in focus_areas]:
                    continue
                
                action = self._generate_action(tool_key, violation, priority)
                if action:
                    actions.append(action)
                    priority += 1
                
                if len(actions) >= max_actions:
                    break
            
            if len(actions) >= max_actions:
                break
        
        # Sort by priority
        actions.sort(key=lambda x: x.priority)
        
        # Calculate cross-tool dependencies
        dependencies = self._calculate_dependencies(actions)
        
        # Generate verification plan
        verification_plan = self._generate_verification_plan(actions)
        
        # Estimate total effort
        total_effort = self._estimate_total_effort(actions)
        
        plan = RemediationPlan(
            project_path=scan_result.path,
            total_actions=len(actions),
            estimated_total_effort=total_effort,
            actions=actions,
            cross_tool_dependencies=dependencies,
            verification_plan=verification_plan
        )
        
        self.remediation_history.append(plan)
        
        return plan
    
    def _generate_action(
        self,
        tool_key: str,
        violation: Dict,
        priority: int
    ) -> Optional[RemediationAction]:
        """Generiert eine einzelne Remediation-Aktion."""
        
        severity = violation.get("severity", "UNKNOWN").upper()
        
        # Tool-spezifische Remediation
        if tool_key == "sca":
            return self._generate_sca_action(violation, priority, severity)
        elif tool_key == "container":
            return self._generate_container_action(violation, priority, severity)
        elif tool_key == "iac":
            return self._generate_iac_action(violation, priority, severity)
        elif tool_key == "license":
            return self._generate_license_action(violation, priority, severity)
        elif tool_key == "dast":
            return self._generate_dast_action(violation, priority, severity)
        
        return None
    
    def _generate_sca_action(
        self,
        violation: Dict,
        priority: int,
        severity: str
    ) -> RemediationAction:
        """Generiert SCA-spezifische Remediation."""
        package = violation.get("package", "unknown-package")
        cve = violation.get("cve", "N/A")
        
        return RemediationAction(
            priority=priority,
            tool="sca",
            action=f"Update {package} to latest version",
            description=f"Fix {cve} vulnerability in {package}",
            command=f"npm install {package}@latest",  # Assumes npm, adjust based on ecosystem
            files_to_modify=["package.json", "package-lock.json"],
            estimated_effort="low",
            risk_level="low",
            verification_steps=[
                "Run npm audit to verify fix",
                "Run tests to ensure compatibility",
                "Re-run SCA scan"
            ]
        )
    
    def _generate_container_action(
        self,
        violation: Dict,
        priority: int,
        severity: str
    ) -> RemediationAction:
        """Generiert Container-spezifische Remediation."""
        return RemediationAction(
            priority=priority,
            tool="container",
            action="Update Docker base image and rebuild",
            description="Fix container vulnerabilities by updating base image",
            command="docker build -t myapp:$(date +%Y%m%d) .",
            files_to_modify=["Dockerfile"],
            estimated_effort="medium",
            risk_level="medium",
            verification_steps=[
                "Scan new image with Trivy",
                "Test application in new container",
                "Deploy to staging environment"
            ]
        )
    
    def _generate_iac_action(
        self,
        violation: Dict,
        priority: int,
        severity: str
    ) -> RemediationAction:
        """Generiert IaC-spezifische Remediation."""
        check_id = violation.get("check_id", "unknown")
        resource = violation.get("resource", "unknown")
        
        return RemediationAction(
            priority=priority,
            tool="iac",
            action=f"Fix {check_id} in {resource}",
            description=f"Apply security best practices to {resource}",
            command="terraform plan && terraform apply",
            files_to_modify=[violation.get("file_path", "main.tf")],
            estimated_effort="medium",
            risk_level="medium",
            verification_steps=[
                "Run terraform plan to review changes",
                "Apply changes in staging",
                "Re-run Checkov scan"
            ]
        )
    
    def _generate_license_action(
        self,
        violation: Dict,
        priority: int,
        severity: str
    ) -> RemediationAction:
        """Generiert License-spezifische Remediation."""
        package = violation.get("package", "unknown")
        license_type = violation.get("license", "unknown")
        
        return RemediationAction(
            priority=priority,
            tool="license",
            action=f"Replace {package} with permissive-licensed alternative",
            description=f"Remove {license_type} licensed dependency",
            command=None,  # Requires manual selection of alternative
            files_to_modify=["package.json", "requirements.txt"],
            estimated_effort="high",
            risk_level="high",
            verification_steps=[
                "Research alternative packages",
                "Test alternative in development",
                "Update documentation",
                "Re-run license scan"
            ]
        )
    
    def _generate_dast_action(
        self,
        violation: Dict,
        priority: int,
        severity: str
    ) -> RemediationAction:
        """Generiert DAST-spezifische Remediation."""
        vuln_type = violation.get("name", "vulnerability")
        url = violation.get("url", "unknown")
        
        # Determine fix based on vulnerability type
        if "xss" in vuln_type.lower():
            action = "Implement output encoding and Content Security Policy"
            description = "Fix Cross-Site Scripting (XSS) vulnerability"
            files = ["src/templates/*.html", "src/middleware/security.py"]
        elif "sql" in vuln_type.lower():
            action = "Use prepared statements and parameterized queries"
            description = "Fix SQL Injection vulnerability"
            files = ["src/database/queries.py"]
        else:
            action = f"Fix {vuln_type} vulnerability"
            description = f"Address security issue at {url}"
            files = ["src/"]
        
        return RemediationAction(
            priority=priority,
            tool="dast",
            action=action,
            description=description,
            command=None,  # Requires manual code changes
            files_to_modify=files,
            estimated_effort="high",
            risk_level="high",
            verification_steps=[
                "Implement fix in code",
                "Run unit tests",
                "Re-run DAST scan",
                "Perform manual penetration testing"
            ]
        )
    
    def _calculate_dependencies(
        self,
        actions: List[RemediationAction]
    ) -> Dict[str, List[str]]:
        """Berechnet Cross-Tool-Dependencies."""
        dependencies = {}
        
        # Example: Container rebuild depends on SCA fixes
        container_actions = [a for a in actions if a.tool == "container"]
        sca_actions = [a for a in actions if a.tool == "sca"]
        
        if container_actions and sca_actions:
            dependencies["container"] = ["sca"]
        
        # IaC changes may require DAST re-scan
        iac_actions = [a for a in actions if a.tool == "iac"]
        dast_actions = [a for a in actions if a.tool == "dast"]
        
        if iac_actions and dast_actions:
            dependencies["dast"] = ["iac"]
        
        return dependencies
    
    def _generate_verification_plan(
        self,
        actions: List[RemediationAction]
    ) -> List[str]:
        """Generiert einen Verifikations-Plan."""
        plan = [
            "1. Apply fixes in development environment",
            "2. Run unit tests",
            "3. Run integration tests",
            "4. Re-run all security scans (SCA, Container, IaC, License, DAST)",
            "5. Deploy to staging environment",
            "6. Perform manual security review",
            "7. Deploy to production",
            "8. Monitor for regressions"
        ]
        
        return plan
    
    def _estimate_total_effort(self, actions: List[RemediationAction]) -> str:
        """Schätzt den Gesamtaufwand."""
        if not actions:
            return "none"
        
        effort_scores = {"low": 1, "medium": 2, "high": 3}
        total_score = sum(
            effort_scores.get(a.estimated_effort, 0) for a in actions
        )
        
        avg_score = total_score / len(actions)
        
        if avg_score <= 1.5:
            return "low (1-2 days)"
        elif avg_score <= 2.5:
            return "medium (3-5 days)"
        else:
            return "high (1-2 weeks)"
    
    def generate_implementation_guide(self, plan: RemediationPlan) -> str:
        """Generiert einen Implementation Guide als Markdown."""
        lines = [
            "# 🛠️  Security Remediation Implementation Guide",
            "",
            f"**Project:** `{plan.project_path}`",
            f"**Total Actions:** {plan.total_actions}",
            f"**Estimated Effort:** {plan.estimated_total_effort}",
            "",
            "---",
            "",
            "## 📋 Action Plan",
            "",
        ]
        
        for action in plan.actions:
            severity_emoji = "🔴" if action.risk_level == "high" else \
                           "🟠" if action.risk_level == "medium" else "🟢"
            
            lines.extend([
                f"### {action.priority}. {severity_emoji} [{action.tool.upper()}] {action.action}",
                "",
                f"**Description:** {action.description}",
                f"**Estimated Effort:** {action.estimated_effort}",
                f"**Risk Level:** {action.risk_level}",
                "",
            ])
            
            if action.command:
                lines.extend([
                    "**Command:**",
                    "```bash",
                    action.command,
                    "```",
                    "",
                ])
            
            if action.files_to_modify:
                lines.extend([
                    "**Files to Modify:**",
                ])
                for file in action.files_to_modify:
                    lines.append(f"- `{file}`")
                lines.append("")
            
            if action.verification_steps:
                lines.extend([
                    "**Verification Steps:**",
                ])
                for i, step in enumerate(action.verification_steps, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")
            
            lines.append("---")
            lines.append("")
        
        # Cross-Tool Dependencies
        if plan.cross_tool_dependencies:
            lines.extend([
                "## 🔗 Cross-Tool Dependencies",
                "",
            ])
            
            for tool, deps in plan.cross_tool_dependencies.items():
                lines.append(f"- **{tool.upper()}** depends on: {', '.join(deps)}")
            
            lines.append("")
        
        # Verification Plan
        lines.extend([
            "## ✅ Verification Plan",
            "",
        ])
        
        for step in plan.verification_plan:
            lines.append(f"- {step}")
        
        lines.extend([
            "",
            "---",
            "",
            "*Guide generated by SIN-Code-Security-Bundle Remediation Engine*",
        ])
        
        return "\n".join(lines)
