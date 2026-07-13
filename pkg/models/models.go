// SPDX-License-Identifier: MIT
package models

// ToolResult represents result of a single security tool
type ToolResult struct {
	ToolName              string                   `json:"tool_name" yaml:"tool_name"`
	Status                string                   `json:"status" yaml:"status"`
	Summary               map[string]interface{}   `json:"summary" yaml:"summary"`
	Violations            []map[string]interface{} `json:"violations" yaml:"violations"`
	ScanDurationSeconds   float64                  `json:"scan_duration_seconds" yaml:"scan_duration_seconds"`
	Error                 string                   `json:"error,omitempty" yaml:"error,omitempty"`
}

// ComplianceScore represents compliance metrics for a framework
type ComplianceScore struct {
	Name        string  `json:"name" yaml:"name"`
	Score       float64 `json:"score" yaml:"score"`
	Status      string  `json:"status" yaml:"status"`
	TotalIssues int     `json:"total_issues" yaml:"total_issues"`
}

// TopFix represents a prioritized fix action
type TopFix struct {
	Priority   int                    `json:"priority" yaml:"priority"`
	Tool       string                 `json:"tool" yaml:"tool"`
	ToolName   string                 `json:"tool_name" yaml:"tool_name"`
	Severity   string                 `json:"severity" yaml:"severity"`
	Action     string                 `json:"action" yaml:"action"`
	Violation  map[string]interface{} `json:"violation" yaml:"violation"`
}

// BundleScanResult represents complete bundle scan result
type BundleScanResult struct {
	Path                string                       `json:"path" yaml:"path"`
	OverallScore        int                          `json:"overall_score" yaml:"overall_score"`
	Status              string                       `json:"status" yaml:"status"`
	Tools               map[string]ToolResult        `json:"tools" yaml:"tools"`
	Compliance          map[string]ComplianceScore   `json:"compliance" yaml:"compliance"`
	TopFixes            []TopFix                     `json:"top_fixes" yaml:"top_fixes"`
	ScanDurationSeconds float64                      `json:"scan_duration_seconds" yaml:"scan_duration_seconds"`
	Timestamp           string                       `json:"timestamp" yaml:"timestamp"`
}

// ScanOptions represents scan configuration
type ScanOptions struct {
	Path         string
	Compliance   []string
	FailOn       string
	SkipTools    []string
	TargetURL    string
	OutputFormat string
	Verbose      bool
}

// ToolInfo represents tool metadata
type ToolInfo struct {
	Key    string `json:"key" yaml:"key"`
	Name   string `json:"name" yaml:"name"`
	Emoji  string `json:"emoji" yaml:"emoji"`
	Weight int    `json:"weight" yaml:"weight"`
}
