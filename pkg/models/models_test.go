package models

import (
	"encoding/json"
	"testing"
)

func TestToolResult(t *testing.T) {
	tr := ToolResult{
		ToolName:            "sca",
		Status:              "warning",
		Summary:             map[string]interface{}{"critical": 0, "high": 3, "medium": 5},
		Violations:          []map[string]interface{}{{"severity": "HIGH", "cve": "CVE-2024-1"}},
		ScanDurationSeconds: 15.5,
		Error:               "",
	}
	if tr.ToolName != "sca" {
		t.Errorf("expected ToolName=sca, got %s", tr.ToolName)
	}
	if tr.Status != "warning" {
		t.Errorf("expected Status=warning, got %s", tr.Status)
	}
	if len(tr.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(tr.Violations))
	}
}

func TestComplianceScore(t *testing.T) {
	cs := ComplianceScore{
		Name:        "CIS Benchmarks",
		Score:       94.6,
		Status:      "pass",
		TotalIssues: 3,
	}
	if cs.Name != "CIS Benchmarks" {
		t.Errorf("expected Name=CIS Benchmarks, got %s", cs.Name)
	}
	if cs.Score != 94.6 {
		t.Errorf("expected Score=94.6, got %f", cs.Score)
	}
	if cs.Status != "pass" {
		t.Errorf("expected Status=pass, got %s", cs.Status)
	}
}

func TestTopFix(t *testing.T) {
	tf := TopFix{
		Priority:  1,
		Tool:      "sca",
		ToolName:  "SCA (Software Composition Analysis)",
		Severity:  "CRITICAL",
		Action:    "Update openssl to latest version",
		Violation: map[string]interface{}{"cve": "CVE-2024-1"},
	}
	if tf.Priority != 1 {
		t.Errorf("expected Priority=1, got %d", tf.Priority)
	}
	if tf.Severity != "CRITICAL" {
		t.Errorf("expected Severity=CRITICAL, got %s", tf.Severity)
	}
}

func TestBundleScanResult(t *testing.T) {
	bsr := BundleScanResult{
		Path:                "./my-project",
		OverallScore:        72,
		Status:              "warning",
		Tools:               map[string]ToolResult{"sca": {ToolName: "sca", Status: "warning"}},
		Compliance:          map[string]ComplianceScore{"cis": {Name: "CIS", Score: 94.6, Status: "pass"}},
		TopFixes:            []TopFix{{Priority: 1, Tool: "sca", Severity: "HIGH", Action: "Fix"}},
		ScanDurationSeconds: 120.5,
		Timestamp:           "2026-06-06T12:00:00Z",
	}
	if bsr.Path != "./my-project" {
		t.Errorf("expected Path=./my-project, got %s", bsr.Path)
	}
	if bsr.OverallScore != 72 {
		t.Errorf("expected OverallScore=72, got %d", bsr.OverallScore)
	}
	if len(bsr.Tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(bsr.Tools))
	}
	if len(bsr.Compliance) != 1 {
		t.Errorf("expected 1 compliance score, got %d", len(bsr.Compliance))
	}
	if len(bsr.TopFixes) != 1 {
		t.Errorf("expected 1 top fix, got %d", len(bsr.TopFixes))
	}
}

func TestBundleScanResultJSON(t *testing.T) {
	bsr := BundleScanResult{
		Path:         "./my-project",
		OverallScore: 72,
		Status:       "warning",
		Tools: map[string]ToolResult{
			"sca": {
				ToolName: "sca",
				Status:   "warning",
				Summary:  map[string]interface{}{"high": 3},
			},
		},
		Compliance: map[string]ComplianceScore{
			"cis": {Name: "CIS", Score: 94.6, Status: "pass"},
		},
		TopFixes:            []TopFix{{Priority: 1, Tool: "sca", Severity: "HIGH", Action: "Fix"}},
		ScanDurationSeconds: 120.5,
		Timestamp:           "2026-06-06T12:00:00Z",
	}
	data, err := json.Marshal(bsr)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var decoded BundleScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if decoded.Path != bsr.Path {
		t.Errorf("expected Path=%s, got %s", bsr.Path, decoded.Path)
	}
	if decoded.OverallScore != bsr.OverallScore {
		t.Errorf("expected OverallScore=%d, got %d", bsr.OverallScore, decoded.OverallScore)
	}
	if len(decoded.Tools) != len(bsr.Tools) {
		t.Errorf("expected %d tools, got %d", len(bsr.Tools), len(decoded.Tools))
	}
	if len(decoded.Compliance) != len(bsr.Compliance) {
		t.Errorf("expected %d compliance scores, got %d", len(bsr.Compliance), len(decoded.Compliance))
	}
	if len(decoded.TopFixes) != len(bsr.TopFixes) {
		t.Errorf("expected %d top fixes, got %d", len(bsr.TopFixes), len(decoded.TopFixes))
	}
}

func TestScanOptions(t *testing.T) {
	so := ScanOptions{
		Path:         "./my-project",
		Compliance:   []string{"cis", "nist"},
		FailOn:       "high",
		SkipTools:    []string{"dast"},
		TargetURL:    "http://localhost:3000",
		OutputFormat: "json",
		Verbose:      true,
	}
	if so.Path != "./my-project" {
		t.Errorf("expected Path=./my-project, got %s", so.Path)
	}
	if len(so.Compliance) != 2 {
		t.Errorf("expected 2 compliance frameworks, got %d", len(so.Compliance))
	}
	if !so.Verbose {
		t.Error("expected Verbose=true")
	}
}

func TestToolInfo(t *testing.T) {
	ti := ToolInfo{
		Key:    "sca",
		Name:   "SCA (Software Composition Analysis)",
		Emoji:  "📦",
		Weight: 25,
	}
	if ti.Key != "sca" {
		t.Errorf("expected Key=sca, got %s", ti.Key)
	}
	if ti.Name != "SCA (Software Composition Analysis)" {
		t.Errorf("expected Name=SCA (Software Composition Analysis), got %s", ti.Name)
	}
	if ti.Emoji != "📦" {
		t.Errorf("expected Emoji=📦, got %s", ti.Emoji)
	}
	if ti.Weight != 25 {
		t.Errorf("expected Weight=25, got %d", ti.Weight)
	}
}
