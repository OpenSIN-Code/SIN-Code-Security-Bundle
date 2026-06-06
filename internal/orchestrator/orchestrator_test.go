package orchestrator

import (
	"testing"

	"github.com/OpenSIN-Code/SIN-Code-Security-Bundle/pkg/models"
)

func TestNewOrchestrator(t *testing.T) {
	o := NewOrchestrator()
	if o == nil {
		t.Fatal("NewOrchestrator() returned nil")
	}
	if o.Timeout != 1800 {
		t.Errorf("expected Timeout=1800, got %d", o.Timeout)
	}
}

func TestToolsMap(t *testing.T) {
	if len(Tools) != 6 {
		t.Errorf("expected 6 tools, got %d", len(Tools))
	}
	expected := []string{"sca", "container", "iac", "license", "dast", "sast"}
	for _, key := range expected {
		if _, ok := Tools[key]; !ok {
			t.Errorf("expected tool %s to be defined", key)
		}
	}
}

func TestComplianceFrameworksMap(t *testing.T) {
	if len(ComplianceFrameworks) != 8 {
		t.Errorf("expected 8 frameworks, got %d", len(ComplianceFrameworks))
	}
	expected := []string{"cis", "nist", "soc2", "iso27001", "gdpr", "hipaa", "pci", "owasp"}
	for _, key := range expected {
		if _, ok := ComplianceFrameworks[key]; !ok {
			t.Errorf("expected framework %s to be defined", key)
		}
	}
}

func TestStatusFromSummary(t *testing.T) {
	o := NewOrchestrator()

	// Test with critical
	summaryCritical := map[string]interface{}{"critical": 2, "high": 1}
	if o.statusFromSummary(summaryCritical) != "failed" {
		t.Errorf("expected status=failed for critical issues, got %s", o.statusFromSummary(summaryCritical))
	}

	// Test with high
	summaryHigh := map[string]interface{}{"critical": 0, "high": 2}
	if o.statusFromSummary(summaryHigh) != "warning" {
		t.Errorf("expected status=warning for high issues, got %s", o.statusFromSummary(summaryHigh))
	}

	// Test with no issues
	summaryPassed := map[string]interface{}{"critical": 0, "high": 0, "medium": 0}
	if o.statusFromSummary(summaryPassed) != "passed" {
		t.Errorf("expected status=passed for no issues, got %s", o.statusFromSummary(summaryPassed))
	}
}

func TestCalculateOverallScore(t *testing.T) {
	o := NewOrchestrator()

	// All passed
	toolsPassed := map[string]models.ToolResult{
		"sca":       {ToolName: "sca", Status: "passed", Summary: map[string]interface{}{}},
		"container": {ToolName: "container", Status: "passed", Summary: map[string]interface{}{}},
	}
	score := o.calculateOverallScore(toolsPassed)
	if score != 100 {
		t.Errorf("expected score=100 for all passed, got %d", score)
	}

	// Warning with high issues
	toolsWarning := map[string]models.ToolResult{
		"sca": {ToolName: "sca", Status: "warning", Summary: map[string]interface{}{
			"critical": 0, "high": 3, "medium": 5,
		}},
	}
	score = o.calculateOverallScore(toolsWarning)
	// 100 - (3*10) - (5*3) = 100 - 30 - 15 = 55
	if score != 55 {
		t.Errorf("expected score=55 for warning, got %d", score)
	}

	// Failed
	toolsFailed := map[string]models.ToolResult{
		"sca": {ToolName: "sca", Status: "failed", Summary: map[string]interface{}{
			"critical": 1, "high": 0, "medium": 0,
		}},
	}
	score = o.calculateOverallScore(toolsFailed)
	if score != 30 {
		t.Errorf("expected score=30 for failed, got %d", score)
	}

	// Skipped tools
	toolsSkipped := map[string]models.ToolResult{
		"sca": {ToolName: "sca", Status: "skipped", Summary: map[string]interface{}{}},
	}
	score = o.calculateOverallScore(toolsSkipped)
	if score != 100 {
		t.Errorf("expected score=100 when all skipped, got %d", score)
	}
}

func TestDetermineOverallStatus(t *testing.T) {
	o := NewOrchestrator()

	// All passed
	toolsPassed := map[string]models.ToolResult{
		"sca":       {ToolName: "sca", Status: "passed"},
		"container": {ToolName: "container", Status: "passed"},
	}
	if o.determineOverallStatus(toolsPassed, "high") != "passed" {
		t.Errorf("expected status=passed for all passed, got %s", o.determineOverallStatus(toolsPassed, "high"))
	}

	// Has warning
	toolsWarning := map[string]models.ToolResult{
		"sca":       {ToolName: "sca", Status: "passed"},
		"container": {ToolName: "container", Status: "warning"},
	}
	if o.determineOverallStatus(toolsWarning, "high") != "warning" {
		t.Errorf("expected status=warning, got %s", o.determineOverallStatus(toolsWarning, "high"))
	}

	// Has failed
	toolsFailed := map[string]models.ToolResult{
		"sca":       {ToolName: "sca", Status: "passed"},
		"container": {ToolName: "container", Status: "failed"},
	}
	if o.determineOverallStatus(toolsFailed, "high") != "failed" {
		t.Errorf("expected status=failed, got %s", o.determineOverallStatus(toolsFailed, "high"))
	}
}

func TestCalculateCompliance(t *testing.T) {
	o := NewOrchestrator()

	tools := map[string]models.ToolResult{
		"sca": {ToolName: "sca", Status: "warning", Summary: map[string]interface{}{
			"critical": 0, "high": 2, "medium": 3,
		}},
	}
	frameworks := []string{"cis", "nist"}
	compliance := o.calculateCompliance(tools, frameworks)

	if len(compliance) != 2 {
		t.Errorf("expected 2 compliance scores, got %d", len(compliance))
	}

	cis, ok := compliance["cis"]
	if !ok {
		t.Fatal("expected cis to be in compliance")
	}
	if cis.Name != "CIS Benchmarks" {
		t.Errorf("expected Name=CIS Benchmarks, got %s", cis.Name)
	}
	if cis.Status == "" {
		t.Error("expected Status to be set")
	}
}

func TestGenerateTopFixes(t *testing.T) {
	o := NewOrchestrator()

	tools := map[string]models.ToolResult{
		"sca": {ToolName: "sca", Status: "failed", Violations: []map[string]interface{}{
			{"severity": "CRITICAL", "package": "openssl", "cve": "CVE-2024-1"},
			{"severity": "HIGH", "package": "axios", "cve": "CVE-2024-2"},
		}},
	}
	fixes := o.generateTopFixes(tools)

	if len(fixes) < 2 {
		t.Errorf("expected at least 2 fixes, got %d", len(fixes))
	}
	if fixes[0].Severity != "CRITICAL" {
		t.Errorf("expected first fix to be CRITICAL, got %s", fixes[0].Severity)
	}
	if fixes[0].Priority != 1 {
		t.Errorf("expected first fix priority=1, got %d", fixes[0].Priority)
	}
}

func TestGenerateFixAction(t *testing.T) {
	o := NewOrchestrator()

	// Test SCA fix action
	scaViolation := map[string]interface{}{"package": "axios"}
	scaAction := o.generateFixAction("sca", scaViolation)
	if scaAction != "Update axios to latest version" {
		t.Errorf("expected SCA action to contain 'axios', got %s", scaAction)
	}

	// Test container fix action
	containerAction := o.generateFixAction("container", map[string]interface{}{})
	if containerAction != "Rebuild Docker image with updated base" {
		t.Errorf("expected container action, got %s", containerAction)
	}

	// Test IaC fix action
	iacAction := o.generateFixAction("iac", map[string]interface{}{})
	if iacAction != "Apply IaC security best practices" {
		t.Errorf("expected IaC action, got %s", iacAction)
	}

	// Test license fix action
	licenseAction := o.generateFixAction("license", map[string]interface{}{})
	if licenseAction != "Replace with permissive-licensed alternative" {
		t.Errorf("expected license action, got %s", licenseAction)
	}

	// Test DAST fix action
	dastAction := o.generateFixAction("dast", map[string]interface{}{})
	if dastAction != "Fix web application vulnerability" {
		t.Errorf("expected DAST action, got %s", dastAction)
	}
}

func TestGetInt(t *testing.T) {
	m := map[string]interface{}{
		"float": 42.0,
		"int":   42,
		"string": "42",
	}

	if getInt(m, "float") != 42 {
		t.Errorf("expected getInt(float)=42, got %d", getInt(m, "float"))
	}
	if getInt(m, "int") != 42 {
		t.Errorf("expected getInt(int)=42, got %d", getInt(m, "int"))
	}
	if getInt(m, "string") != 0 {
		t.Errorf("expected getInt(string)=0, got %d", getInt(m, "string"))
	}
	if getInt(m, "missing") != 0 {
		t.Errorf("expected getInt(missing)=0, got %d", getInt(m, "missing"))
	}
}

func TestFullScan(t *testing.T) {
	o := NewOrchestrator()
	opts := models.ScanOptions{
		Path:       ".",
		Compliance: []string{"cis", "nist"},
		FailOn:     "high",
		SkipTools:  []string{"dast"},
		Verbose:    false,
	}
	result, err := o.FullScan(opts)
	if err != nil {
		t.Fatalf("FullScan failed: %v", err)
	}
	if result == nil {
		t.Fatal("FullScan returned nil result")
	}
	if result.Path != "." {
		t.Errorf("expected Path=., got %s", result.Path)
	}
	if result.Status == "" {
		t.Error("expected Status to be set")
	}
	if result.ScanDurationSeconds <= 0 {
		t.Errorf("expected positive duration, got %f", result.ScanDurationSeconds)
	}
	if len(result.Tools) == 0 {
		t.Error("expected at least one tool result")
	}
}

func TestFullScanWithDAST(t *testing.T) {
	o := NewOrchestrator()
	opts := models.ScanOptions{
		Path:      ".",
		TargetURL: "http://example.com",
		SkipTools: []string{},
		Verbose:   false,
	}
	result, err := o.FullScan(opts)
	if err != nil {
		t.Fatalf("FullScan with DAST failed: %v", err)
	}
	if result == nil {
		t.Fatal("FullScan returned nil result")
	}
	if _, ok := result.Tools["dast"]; !ok {
		t.Error("expected DAST tool to be present")
	}
}

func TestFullScanSkipAll(t *testing.T) {
	o := NewOrchestrator()
	opts := models.ScanOptions{
		Path:      ".",
		SkipTools: []string{"sca", "container", "iac", "license", "dast"},
		Verbose:   false,
	}
	result, err := o.FullScan(opts)
	if err != nil {
		t.Fatalf("FullScan with all skipped failed: %v", err)
	}
	if result == nil {
		t.Fatal("FullScan returned nil result")
	}
	if result.OverallScore != 100 {
		t.Errorf("expected score=100 when all skipped, got %d", result.OverallScore)
	}
	if result.Status != "passed" {
		t.Errorf("expected status=passed when all skipped, got %s", result.Status)
	}
}
