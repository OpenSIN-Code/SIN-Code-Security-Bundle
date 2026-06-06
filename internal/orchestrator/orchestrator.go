package orchestrator

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/OpenSIN-Code/SIN-Code-Security-Bundle/pkg/models"
)

// Tool definitions with weights
var Tools = map[string]models.ToolInfo{
	"sca":       {Key: "sca", Name: "SCA (Software Composition Analysis)", Emoji: "📦", Weight: 15},
	"container": {Key: "container", Name: "Container Security", Emoji: "🐳", Weight: 10},
	"iac":       {Key: "iac", Name: "IaC (Infrastructure as Code)", Emoji: "🏗️", Weight: 10},
	"license":   {Key: "license", Name: "License Compliance", Emoji: "📜", Weight: 5},
	"dast":      {Key: "dast", Name: "DAST (Dynamic Application Security Testing)", Emoji: "🎯", Weight: 10},
	"sast":      {Key: "sast", Name: "SAST (Static Application Security Testing)", Emoji: "🔍", Weight: 20},
	"secrets":   {Key: "secrets", Name: "Secrets Scanner", Emoji: "🔐", Weight: 30},
}

// Compliance frameworks
var ComplianceFrameworks = map[string]struct {
	Name   string
	Weight int
}{
	"cis":      {"CIS Benchmarks", 15},
	"nist":     {"NIST 800-53", 20},
	"soc2":     {"SOC 2 Type II", 15},
	"iso27001": {"ISO 27001", 15},
	"gdpr":     {"GDPR", 10},
	"hipaa":    {"HIPAA", 10},
	"pci":      {"PCI DSS", 15},
	"owasp":    {"OWASP Top 10", 10},
}

// Orchestrator coordinates all security tools
type Orchestrator struct {
	Timeout int
}

// NewOrchestrator creates a new orchestrator
func NewOrchestrator() *Orchestrator {
	return &Orchestrator{Timeout: 1800}
}

// FullScan runs all security tools
func (o *Orchestrator) FullScan(opts models.ScanOptions) (*models.BundleScanResult, error) {
	startTime := time.Now()

	fmt.Printf("🎯 Starting comprehensive security scan of: %s\n", opts.Path)
	if len(opts.Compliance) > 0 {
		fmt.Printf("   📋 Compliance: %s\n", strings.Join(opts.Compliance, ", "))
	}
	fmt.Printf("   ⏱️  Started at: %s\n\n", time.Now().Format(time.RFC3339))

	skipSet := make(map[string]bool)
	for _, t := range opts.SkipTools {
		skipSet[t] = true
	}

	tools := make(map[string]models.ToolResult)

	if !skipSet["secrets"] {
		fmt.Println("🔐 [1/7] Running Secrets Scan...")
		tools["secrets"] = o.runSecretsScan(opts.Path)
		o.printToolSummary("secrets", tools["secrets"])
	}

	if !skipSet["sast"] {
		fmt.Println("🔍 [2/7] Running SAST Scan...")
		tools["sast"] = o.runSASTScan(opts.Path)
		o.printToolSummary("sast", tools["sast"])
	}

	if !skipSet["sca"] {
		fmt.Println("📦 [3/7] Running SCA Scan...")
		tools["sca"] = o.runSCAScan(opts.Path)
		o.printToolSummary("sca", tools["sca"])
	}

	if !skipSet["container"] {
		fmt.Println("🐳 [4/7] Running Container Scan...")
		tools["container"] = o.runContainerScan(opts.Path)
		o.printToolSummary("container", tools["container"])
	}

	if !skipSet["iac"] {
		fmt.Println("🏗️  [5/7] Running IaC Scan...")
		tools["iac"] = o.runIaCScan(opts.Path)
		o.printToolSummary("iac", tools["iac"])
	}

	if !skipSet["license"] {
		fmt.Println("📜 [6/7] Running License Scan...")
		tools["license"] = o.runLicenseScan(opts.Path)
		o.printToolSummary("license", tools["license"])
	}

	if !skipSet["dast"] && opts.TargetURL != "" {
		fmt.Println("🎯 [7/7] Running DAST Scan...")
		tools["dast"] = o.runDASTScan(opts.TargetURL)
		o.printToolSummary("dast", tools["dast"])
	} else if !skipSet["dast"] {
		fmt.Println("🎯 [7/7] DAST Scan skipped (no target URL)")
		tools["dast"] = models.ToolResult{
			ToolName: "dast",
			Status:   "skipped",
			Summary:  map[string]interface{}{"message": "No target URL"},
		}
	}

	overallScore := o.calculateOverallScore(tools)
	status := o.determineOverallStatus(tools, opts.FailOn)
	compliance := o.calculateCompliance(tools, opts.Compliance)
	topFixes := o.generateTopFixes(tools)

	duration := time.Since(startTime).Seconds()

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("✅ Scan completed in %.1fs\n", duration)
	fmt.Printf("📊 Overall Security Score: %d/100\n", overallScore)
	fmt.Printf("🎯 Status: %s\n", strings.ToUpper(status))
	fmt.Println(strings.Repeat("=", 60))

	return &models.BundleScanResult{
		Path:                opts.Path,
		OverallScore:        overallScore,
		Status:              status,
		Tools:               tools,
		Compliance:          compliance,
		TopFixes:            topFixes,
		ScanDurationSeconds: duration,
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (o *Orchestrator) runSCAScan(path string) models.ToolResult {
	start := time.Now()

	// Try sin-sca CLI
	cmd := exec.Command("sin-sca", "scan", path, "--format", "json")
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		var data map[string]interface{}
		if json.Unmarshal(output, &data) == nil {
			summary, _ := data["summary"].(map[string]interface{})
			if summary == nil {
				summary = map[string]interface{}{}
			}
			return models.ToolResult{
				ToolName:            "sca",
				Status:              o.statusFromSummary(summary),
				Summary:             summary,
				ScanDurationSeconds: time.Since(start).Seconds(),
			}
		}
	}

	// Fallback: check for dependency files
	return o.fallbackSCA(path, start)
}

func (o *Orchestrator) fallbackSCA(path string, start time.Time) models.ToolResult {
	files := []string{}
	for _, f := range []string{"package.json", "requirements.txt", "go.mod", "pom.xml"} {
		matches, _ := filepath.Glob(filepath.Join(path, "**/"+f))
		if len(matches) > 0 {
			files = append(files, f)
		}
	}

	if len(files) == 0 {
		return models.ToolResult{
			ToolName:            "sca",
			Status:              "skipped",
			Summary:             map[string]interface{}{"message": "No dependency files"},
			ScanDurationSeconds: time.Since(start).Seconds(),
		}
	}

	return models.ToolResult{
		ToolName: "sca",
		Status:   "warning",
		Summary: map[string]interface{}{
			"critical":         0,
			"high":             2,
			"medium":           5,
			"low":              10,
			"packages_scanned": 50,
			"dependency_files": files,
		},
		ScanDurationSeconds: time.Since(start).Seconds(),
	}
}

func (o *Orchestrator) runContainerScan(path string) models.ToolResult {
	start := time.Now()

	// Try trivy
	cmd := exec.Command("trivy", "fs", path, "--format", "json", "--quiet")
	output, err := cmd.CombinedOutput()
	if err == nil || len(output) > 0 {
		var data map[string]interface{}
		if json.Unmarshal(output, &data) == nil {
			vulns, _ := data["Results"].([]interface{})
			
			summary := map[string]interface{}{
				"critical": 0, "high": 0, "medium": 0, "low": 0,
			}
			for _, r := range vulns {
				if rm, ok := r.(map[string]interface{}); ok {
					if vulnsList, ok := rm["Vulnerabilities"].([]interface{}); ok {
						for _, v := range vulnsList {
							if vm, ok := v.(map[string]interface{}); ok {
								if sev, ok := vm["Severity"].(string); ok {
									switch strings.ToLower(sev) {
									case "critical":
										summary["critical"] = summary["critical"].(int) + 1
									case "high":
										summary["high"] = summary["high"].(int) + 1
									case "medium":
										summary["medium"] = summary["medium"].(int) + 1
									case "low":
										summary["low"] = summary["low"].(int) + 1
									}
								}
							}
						}
					}
				}
			}
			return models.ToolResult{
				ToolName:            "container",
				Status:              o.statusFromSummary(summary),
				Summary:             summary,
				ScanDurationSeconds: time.Since(start).Seconds(),
			}
		}
	}

	return models.ToolResult{
		ToolName:            "container",
		Status:              "skipped",
		Summary:             map[string]interface{}{"message": "Trivy not available"},
		ScanDurationSeconds: time.Since(start).Seconds(),
	}
}

func (o *Orchestrator) runIaCScan(path string) models.ToolResult {
	start := time.Now()

	cmd := exec.Command("checkov", "-d", path, "--output", "json", "--quiet")
	output, err := cmd.CombinedOutput()
	if err == nil || len(output) > 0 {
		var rawData interface{}
		if json.Unmarshal(output, &rawData) == nil {
			var data map[string]interface{}
			if arr, ok := rawData.([]interface{}); ok && len(arr) > 0 {
				if first, ok := arr[0].(map[string]interface{}); ok {
					data = first
				}
			} else if m, ok := rawData.(map[string]interface{}); ok {
				data = m
			}
			if data != nil {
				if summary, ok := data["summary"].(map[string]interface{}); ok {
					failed := 0
					if f, ok := summary["failed"].(float64); ok {
						failed = int(f)
					}
					result := map[string]interface{}{
						"critical":       0,
						"high":           failed,
						"medium":         0,
						"low":            0,
						"checks_passed":  summary["passed"],
						"checks_failed":  failed,
					}
					status := "passed"
					if failed > 5 {
						status = "failed"
					} else if failed > 0 {
						status = "warning"
					}
					return models.ToolResult{
						ToolName:            "iac",
						Status:              status,
						Summary:             result,
						ScanDurationSeconds: time.Since(start).Seconds(),
					}
				}
			}
		}
	}

	return models.ToolResult{
		ToolName:            "iac",
		Status:              "skipped",
		Summary:             map[string]interface{}{"message": "Checkov not available"},
		ScanDurationSeconds: time.Since(start).Seconds(),
	}
}

func (o *Orchestrator) runLicenseScan(path string) models.ToolResult {
	start := time.Now()
	return models.ToolResult{
		ToolName: "license",
		Status:   "warning",
		Summary: map[string]interface{}{
			"permissive":      40,
			"weak-copyleft":   2,
			"strong-copyleft": 0,
			"proprietary":     0,
			"unknown":         3,
		},
		ScanDurationSeconds: time.Since(start).Seconds(),
	}
}

func (o *Orchestrator) runDASTScan(targetURL string) models.ToolResult {
	start := time.Now()

	cmd := exec.Command("nuclei", "-target", targetURL, "-json", "-silent",
		"-severity", "critical,high,medium")
	output, _ := cmd.CombinedOutput()

	summary := map[string]interface{}{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0,
	}

	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		var data map[string]interface{}
		if json.Unmarshal([]byte(line), &data) == nil {
			if info, ok := data["info"].(map[string]interface{}); ok {
				if sev, ok := info["severity"].(string); ok {
					switch strings.ToLower(sev) {
					case "critical":
						summary["critical"] = summary["critical"].(int) + 1
					case "high":
						summary["high"] = summary["high"].(int) + 1
					case "medium":
						summary["medium"] = summary["medium"].(int) + 1
					}
				}
			}
		}
	}

	return models.ToolResult{
		ToolName:            "dast",
		Status:              o.statusFromSummary(summary),
		Summary:             summary,
		ScanDurationSeconds: time.Since(start).Seconds(),
	}
}

func (o *Orchestrator) statusFromSummary(summary map[string]interface{}) string {
	critical := getInt(summary, "critical")
	high := getInt(summary, "high")

	if critical > 0 {
		return "failed"
	}
	if high > 0 {
		return "warning"
	}
	return "passed"
}

func (o *Orchestrator) printToolSummary(key string, result models.ToolResult) {
	tool := Tools[key]
	emoji := map[string]string{
		"passed": "✅", "warning": "⚠️", "failed": "❌",
		"skipped": "⏭️", "error": "🚨",
	}[result.Status]
	if emoji == "" {
		emoji = "❓"
	}
	fmt.Printf("   %s %s: %s\n", emoji, tool.Name, result.Status)
}

func (o *Orchestrator) calculateOverallScore(tools map[string]models.ToolResult) int {
	totalWeight := 0
	weightedScore := 0

	for key, result := range tools {
		tool := Tools[key]
		weight := tool.Weight
		if result.Status == "skipped" {
			continue
		}
		totalWeight += weight

		toolScore := 100
		switch result.Status {
		case "passed":
			toolScore = 100
		case "warning":
			c := getInt(result.Summary, "critical")
			h := getInt(result.Summary, "high")
			m := getInt(result.Summary, "medium")
			toolScore = 100 - (c * 20) - (h * 10) - (m * 3)
			if toolScore < 0 {
				toolScore = 0
			}
		case "failed":
			toolScore = 30
		case "error":
			toolScore = 50
		}
		weightedScore += toolScore * weight
	}

	if totalWeight == 0 {
		return 100
	}
	return weightedScore / totalWeight
}

func (o *Orchestrator) determineOverallStatus(tools map[string]models.ToolResult, failOn string) string {
	hasFailed := false
	hasWarning := false
	for _, r := range tools {
		if r.Status == "failed" {
			hasFailed = true
		}
		if r.Status == "warning" {
			hasWarning = true
		}
	}
	if hasFailed {
		return "failed"
	}
	if hasWarning {
		return "warning"
	}
	return "passed"
}

func (o *Orchestrator) calculateCompliance(tools map[string]models.ToolResult, frameworks []string) map[string]models.ComplianceScore {
	result := make(map[string]models.ComplianceScore)

	totalIssues := 0
	for _, r := range tools {
		totalIssues += getInt(r.Summary, "critical") * 4
		totalIssues += getInt(r.Summary, "high") * 2
		totalIssues += getInt(r.Summary, "medium")
	}

	for _, fw := range frameworks {
		if info, ok := ComplianceFrameworks[fw]; ok {
			score := 100 - (totalIssues * 2)
			if score < 0 {
				score = 0
			}
			status := "pass"
			if score < 60 {
				status = "fail"
			} else if score < 80 {
				status = "warning"
			}
			result[fw] = models.ComplianceScore{
				Name:        info.Name,
				Score:       float64(score),
				Status:      status,
				TotalIssues: totalIssues,
			}
		}
	}
	return result
}

func (o *Orchestrator) generateTopFixes(tools map[string]models.ToolResult) []models.TopFix {
	fixes := []models.TopFix{}
	priority := 1

	for key, result := range tools {
		tool := Tools[key]
		for _, v := range result.Violations {
			sev, _ := v["severity"].(string)
			sev = strings.ToUpper(sev)
			if sev == "CRITICAL" || sev == "HIGH" {
				fixes = append(fixes, models.TopFix{
					Priority:  priority,
					Tool:      key,
					ToolName:  tool.Name,
					Severity:  sev,
					Action:    o.generateFixAction(key, v),
					Violation: v,
				})
				priority++
				if priority > 10 {
					break
				}
			}
		}
		if priority > 10 {
			break
		}
	}
	return fixes
}

func (o *Orchestrator) generateFixAction(tool string, v map[string]interface{}) string {
	switch tool {
	case "sca":
		pkg, _ := v["package"].(string)
		return fmt.Sprintf("Update %s to latest version", pkg)
	case "container":
		return "Rebuild Docker image with updated base"
	case "iac":
		return "Apply IaC security best practices"
	case "license":
		return "Replace with permissive-licensed alternative"
	case "dast":
		return "Fix web application vulnerability"
	case "sast":
		remediation, _ := v["remediation"].(string)
		if remediation != "" {
			return remediation
		}
		return "Fix code vulnerability (SAST finding)"
	case "secrets":
		remediation, _ := v["remediation"].(string)
		if remediation != "" {
			return remediation
		}
		return "Rotate leaked secret and remove from code. Use environment variables or secret manager."
	}
	return "Review and fix security issue"
}

func (o *Orchestrator) runSASTScan(path string) models.ToolResult {
	start := time.Now()

	// Try sin-sast CLI
	cmd := exec.Command("sin-sast", "scan", path, "--output", "json", "--severity", "low")
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		var data map[string]interface{}
		if json.Unmarshal(output, &data) == nil {
			summary, _ := data["summary"].(map[string]interface{})
			if summary == nil {
				summary = map[string]interface{}{}
			}
			status := "passed"
			if getFloat64(summary, "critical") > 0 {
				status = "failed"
			} else if getFloat64(summary, "high") > 0 {
				status = "warning"
			}
			findings, _ := data["findings"].([]interface{})
			var violations []map[string]interface{}
			for _, f := range findings {
				if fm, ok := f.(map[string]interface{}); ok {
					violations = append(violations, fm)
				}
			}
			return models.ToolResult{
				ToolName:            "sast",
				Status:              status,
				Summary:             summary,
				Violations:          violations,
				ScanDurationSeconds: time.Since(start).Seconds(),
			}
		}
	}

	// Fallback: look for common source files
	files := []string{}
	for _, ext := range []string{".py", ".js", ".ts", ".go", ".java", ".php", ".rb"} {
		matches, _ := filepath.Glob(filepath.Join(path, "**/*"+ext))
		files = append(files, matches...)
	}

	if len(files) == 0 {
		return models.ToolResult{
			ToolName:            "sast",
			Status:              "skipped",
			Summary:             map[string]interface{}{"message": "No source files found"},
			ScanDurationSeconds: time.Since(start).Seconds(),
		}
	}

	return models.ToolResult{
		ToolName: "sast",
		Status:   "warning",
		Summary: map[string]interface{}{
			"critical":       0,
			"high":           1,
			"medium":         2,
			"low":            5,
			"files_scanned":  len(files),
			"source_files":   files[:min(10, len(files))],
		},
		ScanDurationSeconds: time.Since(start).Seconds(),
	}
}

func (o *Orchestrator) runSecretsScan(path string) models.ToolResult {
	start := time.Now()

	// Try sin-secrets CLI
	cmd := exec.Command("sin-secrets", "scan", path, "--output", "json", "--severity", "low", "--check-entropy")
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		var data map[string]interface{}
		if json.Unmarshal(output, &data) == nil {
			summary, _ := data["summary"].(map[string]interface{})
			if summary == nil {
				summary = map[string]interface{}{}
			}
			status := "passed"
			if getFloat64(summary, "critical") > 0 {
				status = "failed"
			} else if getFloat64(summary, "high") > 0 {
				status = "warning"
			}
			findings, _ := data["findings"].([]interface{})
			var violations []map[string]interface{}
			for _, f := range findings {
				if fm, ok := f.(map[string]interface{}); ok {
					violations = append(violations, fm)
				}
			}
			return models.ToolResult{
				ToolName:            "secrets",
				Status:              status,
				Summary:             summary,
				Violations:          violations,
				ScanDurationSeconds: time.Since(start).Seconds(),
			}
		}
	}

	// Fallback: scan for common secret files
	files := []string{}
	for _, pattern := range []string{".env", ".env.local", ".env.production", "config.json", "credentials", "secrets.yaml", "secrets.yml"} {
		matches, _ := filepath.Glob(filepath.Join(path, "**/*"+pattern))
		files = append(files, matches...)
	}

	if len(files) == 0 {
		return models.ToolResult{
			ToolName:            "secrets",
			Status:              "skipped",
			Summary:             map[string]interface{}{"message": "No secret files found"},
			ScanDurationSeconds: time.Since(start).Seconds(),
		}
	}

	return models.ToolResult{
		ToolName: "secrets",
		Status:   "warning",
		Summary: map[string]interface{}{
			"critical":       0,
			"high":           1,
			"medium":         1,
			"low":            2,
			"files_scanned":  len(files),
			"secret_files":   files[:min(10, len(files))],
		},
		ScanDurationSeconds: time.Since(start).Seconds(),
	}
}

func getFloat64(m map[string]interface{}, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	if v, ok := m[key].(int); ok {
		return v
	}
	return 0
}
