package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"time"

	"github.com/Xwal13/VulcanEye/internal/config"
)

var scanStartTime time.Time

func InitOutput(cfg *config.ScanConfig) {
	scanStartTime = time.Now()
	cfg.Findings = make([]config.Finding, 0)

	if cfg.LogFile != "" {
		f, err := os.Create(cfg.LogFile)
		if err != nil {
			fmt.Printf("%s[!] Could not create log file: %v%s\n", config.ColorRed, err, config.ColorReset)
			return
		}
		cfg.LogWriter = f
	}
}

func LogRequest(cfg *config.ScanConfig, method, url string, headers interface{}, body string) {
	if cfg.LogWriter == nil {
		return
	}

	logFile := cfg.LogWriter.(*os.File)
	fmt.Fprintf(logFile, "\n=== REQUEST ===\n")
	fmt.Fprintf(logFile, "Method: %s\n", method)
	fmt.Fprintf(logFile, "URL: %s\n", url)
	fmt.Fprintf(logFile, "Headers:\n")
	fmt.Fprintf(logFile, "%v\n", headers)
	if body != "" {
		fmt.Fprintf(logFile, "Body: %s\n", body)
	}
}

func LogResponse(cfg *config.ScanConfig, statusCode int, headers map[string][]string, body string) {
	if cfg.LogWriter == nil {
		return
	}

	logFile := cfg.LogWriter.(*os.File)
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

func AddFinding(cfg *config.ScanConfig, finding config.Finding) {
	if finding.Timestamp == "" {
		finding.Timestamp = time.Now().Format("2006-01-02 15:04:05")
	}
	cfg.Findings = append(cfg.Findings, finding)
}

func FinalizeOutput(cfg *config.ScanConfig) error {
	report := config.ScanReport{
		StartTime: scanStartTime.Format("2006-01-02 15:04:05"),
		EndTime:   time.Now().Format("2006-01-02 15:04:05"),
		Target:    cfg.URL,
		Total:     len(cfg.Findings),
		Findings:  cfg.Findings,
	}

	if cfg.LogWriter != nil {
		logFile := cfg.LogWriter.(*os.File)
		logFile.Close()
	}

	if cfg.OutputFormat == "json" {
		return outputJSON(&report, cfg.OutputFile)
	} else if cfg.OutputFormat == "xml" {
		return outputXML(&report, cfg.OutputFile)
	}

	return nil
}

func PrintBullet(color, msg string) {
	fmt.Printf("%s  %s %s%s\n", color, config.IconBullet, msg, config.ColorReset)
}

func outputJSON(report *config.ScanReport, filename string) error {
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

func outputXML(report *config.ScanReport, filename string) error {
	xmlData, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal XML: %v", err)
	}

	output := []byte(xml.Header + string(xmlData))

	if filename != "" {
		return os.WriteFile(filename, output, 0644)
	}

	fmt.Println(string(output))
	return nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
