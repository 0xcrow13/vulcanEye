package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"time"
)

var scanStartTime time.Time

// InitOutput initializes the output system and starts timing
func InitOutput(cfg *ScanConfig) {
	scanStartTime = time.Now()
	cfg.findings = make([]Finding, 0)

	// Initialize log file if specified
	if cfg.LogFile != "" {
		f, err := os.Create(cfg.LogFile)
		if err != nil {
			fmt.Printf("%s[!] Could not create log file: %v%s\n", ColorRed, err, ColorReset)
			return
		}
		cfg.logWriter = f
	}
}

// LogRequest logs HTTP request details
func LogRequest(cfg *ScanConfig, method, url string, headers interface{}, body string) {
	if cfg.logWriter == nil {
		return
	}

	logFile := cfg.logWriter.(*os.File)
	fmt.Fprintf(logFile, "\n=== REQUEST ===\n")
	fmt.Fprintf(logFile, "Method: %s\n", method)
	fmt.Fprintf(logFile, "URL: %s\n", url)
	fmt.Fprintf(logFile, "Headers:\n")
	fmt.Fprintf(logFile, "%v\n", headers)
	if body != "" {
		fmt.Fprintf(logFile, "Body: %s\n", body)
	}
}

// LogResponse logs HTTP response details
func LogResponse(cfg *ScanConfig, statusCode int, headers map[string][]string, body string) {
	if cfg.logWriter == nil {
		return
	}

	logFile := cfg.logWriter.(*os.File)
	fmt.Fprintf(logFile, "\n=== RESPONSE ===\n")
	fmt.Fprintf(logFile, "Status: %d\n", statusCode)
	fmt.Fprintf(logFile, "Headers:\n")
	for k, v := range headers {
		for _, val := range v {
			fmt.Fprintf(logFile, "  %s: %s\n", k, val)
		}
	}
	fmt.Fprintf(logFile, "Body (first 500 chars):\n%s\n", truncateString(body, 500))
}

// AddFinding adds a vulnerability finding to the report
func AddFinding(cfg *ScanConfig, finding Finding) {
	if finding.Timestamp == "" {
		finding.Timestamp = time.Now().Format("2006-01-02 15:04:05")
	}
	cfg.findings = append(cfg.findings, finding)
}

// FinalizeOutput writes the final report in the requested format
func FinalizeOutput(cfg *ScanConfig) error {
	report := ScanReport{
		StartTime: scanStartTime.Format("2006-01-02 15:04:05"),
		EndTime:   time.Now().Format("2006-01-02 15:04:05"),
		Target:    cfg.URL,
		Total:     len(cfg.findings),
		Findings:  cfg.findings,
	}

	// Close log file if open
	if cfg.logWriter != nil {
		logFile := cfg.logWriter.(*os.File)
		logFile.Close()
	}

	// Output in requested format
	if cfg.OutputFormat == "json" {
		return outputJSON(&report, cfg.OutputFile)
	} else if cfg.OutputFormat == "xml" {
		return outputXML(&report, cfg.OutputFile)
	}
	// Default text format is already printed via printBullet/fmt.Printf

	return nil
}

// outputJSON writes the report as JSON
func outputJSON(report *ScanReport, filename string) error {
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	if filename != "" {
		return os.WriteFile(filename, jsonData, 0644)
	}

	fmt.Println(string(jsonData))
	return nil
}

// outputXML writes the report as XML
func outputXML(report *ScanReport, filename string) error {
	xmlData, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal XML: %v", err)
	}

	// Add XML declaration
	output := []byte(xml.Header + string(xmlData))

	if filename != "" {
		return os.WriteFile(filename, output, 0644)
	}

	fmt.Println(string(output))
	return nil
}

// Helper function to truncate strings
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
