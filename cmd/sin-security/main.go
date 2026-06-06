package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/OpenSIN-Code/SIN-Code-Security-Bundle/internal/orchestrator"
	"github.com/OpenSIN-Code/SIN-Code-Security-Bundle/pkg/models"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"

	compliance     string
	failOn         string
	skipTools      string
	targetURL      string
	outputFormat   string
	verbose        bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sin-security",
		Short: "SIN-Code Unified Security Platform",
		Long: `🎯 SIN-Code Security Bundle - Unified Security Platform

Orchestrates all 5 Security-Tools:
  📦 SCA (Software Composition Analysis)
  🐳 Container Security
  🏗️  IaC (Infrastructure as Code)
  📜 License Compliance
  🎯 DAST (Dynamic Application Security Testing)

Perfect for scanning AnythingLLM-based projects like OpenAfD-Chat!`,
		Version: version,
	}

	// Full scan command
	scanCmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Run full security scan across all tools",
		Args:  cobra.ExactArgs(1),
		RunE:  runScan,
	}
	scanCmd.Flags().StringVar(&compliance, "compliance", "", "Compliance frameworks (cis,nist,soc2,iso27001,gdpr,pci,owasp)")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "high", "Severity threshold (critical, high, medium, low)")
	scanCmd.Flags().StringVar(&skipTools, "skip-tools", "", "Tools to skip (sca,container,iac,license,dast)")
	scanCmd.Flags().StringVar(&targetURL, "target-url", "", "URL for DAST scan")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "o", "text", "Output format (json, text)")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Specific tool commands
	scaCmd := &cobra.Command{
		Use:   "sca [path]",
		Short: "Run SCA scan only",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			skipTools = "container,iac,license,dast"
			return runScan(cmd, args)
		},
	}

	containerCmd := &cobra.Command{
		Use:   "container [path]",
		Short: "Run Container scan only",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			skipTools = "sca,iac,license,dast"
			return runScan(cmd, args)
		},
	}

	iacCmd := &cobra.Command{
		Use:   "iac [path]",
		Short: "Run IaC scan only",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			skipTools = "sca,container,license,dast"
			return runScan(cmd, args)
		},
	}

	licenseCmd := &cobra.Command{
		Use:   "license [path]",
		Short: "Run License scan only",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			skipTools = "sca,container,iac,dast"
			return runScan(cmd, args)
		},
	}

	dastCmd := &cobra.Command{
		Use:   "dast [url]",
		Short: "Run DAST scan only",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			skipTools = "sca,container,iac,license"
			targetURL = args[0]
			return runScan(cmd, []string{"."})
		},
	}

	// OpenAfD-Chat specific scan (AnythingLLM-based)
	openafdCmd := &cobra.Command{
		Use:   "openafd [path-or-url]",
		Short: "Scan OpenAfD-Chat (AnythingLLM) project",
		Long: `Specialized scan for OpenAfD-Chat and other AnythingLLM-based projects.

Includes:
  • AnythingLLM-specific Nuclei templates
  • Telemetry endpoint checks
  • Vector database misconfiguration detection
  • API key exposure detection
  • Workspace access control verification`,
		Args: cobra.ExactArgs(1),
		RunE: runOpenAfDScan,
	}
	openafdCmd.Flags().StringVar(&targetURL, "url", "", "Running instance URL")

	// List commands
	listToolsCmd := &cobra.Command{
		Use:   "list-tools",
		Short: "List all available security tools",
		Run:   runListTools,
	}

	listFrameworksCmd := &cobra.Command{
		Use:   "list-frameworks",
		Short: "List all compliance frameworks",
		Run:   runListFrameworks,
	}

	rootCmd.AddCommand(scanCmd, scaCmd, containerCmd, iacCmd, licenseCmd, dastCmd, openafdCmd, listToolsCmd, listFrameworksCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	path := args[0]

	var complianceList, skipList []string
	if compliance != "" {
		for _, c := range splitAndTrim(compliance) {
			complianceList = append(complianceList, c)
		}
	}
	if skipTools != "" {
		for _, s := range splitAndTrim(skipTools) {
			skipList = append(skipList, s)
		}
	}

	opts := models.ScanOptions{
		Path:         path,
		Compliance:   complianceList,
		FailOn:       failOn,
		SkipTools:    skipList,
		TargetURL:    targetURL,
		OutputFormat: outputFormat,
		Verbose:      verbose,
	}

	orch := orchestrator.NewOrchestrator()
	result, err := orch.FullScan(opts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if outputFormat == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		encoder.Encode(result)
	}

	if result.Status == "failed" {
		os.Exit(1)
	}
	return nil
}

func runOpenAfDScan(cmd *cobra.Command, args []string) error {
	path := args[0]

	title := color.New(color.FgMagenta, color.Bold)
	title.Println("\n🇩🇪 OpenAfD-Chat Security Scan (AnythingLLM-based)")
	title.Println(strings.Repeat("=", 60))

	fmt.Println("\n📋 This scan includes AnythingLLM-specific checks:")
	fmt.Println("   • API key exposure (OPENAI_API_KEY, ANTHROPIC_API_KEY)")
	fmt.Println("   • Telemetry endpoints (PostHog)")
	fmt.Println("   • Vector database misconfigurations")
	fmt.Println("   • Workspace access control")
	fmt.Println("   • CORS configuration")
	fmt.Println("   • File upload vulnerabilities")
	fmt.Println("   • Authentication mechanisms")
	fmt.Println()

	// Run with DAST if URL provided
	opts := models.ScanOptions{
		Path:       path,
		Compliance: []string{"cis", "nist", "gdpr"},
		FailOn:     "high",
		TargetURL:  targetURL,
	}

	orch := orchestrator.NewOrchestrator()
	result, err := orch.FullScan(opts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if result.Status == "failed" {
		os.Exit(1)
	}
	return nil
}

func runListTools(cmd *cobra.Command, args []string) {
	fmt.Println("\n🔍 Available Security Tools")
	fmt.Println(strings.Repeat("=", 50))

	for _, tool := range orchestrator.Tools {
		fmt.Printf("  %s %s (%s)\n", tool.Emoji, tool.Key, tool.Name)
		fmt.Printf("     Weight: %d%%\n\n", tool.Weight)
	}
}

func runListFrameworks(cmd *cobra.Command, args []string) {
	fmt.Println("\n📋 Available Compliance Frameworks")
	fmt.Println(strings.Repeat("=", 50))

	for key, fw := range orchestrator.ComplianceFrameworks {
		fmt.Printf("  • %s (%s) - Weight: %d%%\n", key, fw.Name, fw.Weight)
	}
	fmt.Println()
}

func splitAndTrim(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
