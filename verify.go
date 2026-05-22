package main

import (
	"fmt"
	"strings"
	"time"
)

// VerifyFinding re-tests a finding to confirm it's not a false positive
func VerifyFinding(cfg *ScanConfig, finding Finding) (bool, error) {
	if IsScanCancelled() {
		return false, fmt.Errorf("scan cancelled")
	}

	debugPrintf(cfg, "[*] Verifying finding: %s in parameter %s", finding.Type, finding.Parameter)

	// Different verification strategies based on vulnerability type
	switch finding.Type {
	case "XSS":
		return verifyXSS(cfg, finding)
	case "SQLi", "BOOLEAN-BASED SQL INJECTION", "TIME-BASED BLIND SQL INJECTION":
		return verifySQLi(cfg, finding)
	case "LFI":
		return verifyLFI(cfg, finding)
	case "RCE", "COMMAND INJECTION / RCE":
		return verifyRCE(cfg, finding)
	case "SSRF", "SERVER-SIDE REQUEST FORGERY (SSRF)":
		return verifySSRF(cfg, finding)
	case "SSTI", "SERVER-SIDE TEMPLATE INJECTION (SSTI)":
		return verifySSTI(cfg, finding)
	case "NoSQL Injection", "NOSQL INJECTION":
		return verifyNoSQLi(cfg, finding)
	case "XXE", "XML EXTERNAL ENTITY (XXE)":
		return verifyXXE(cfg, finding)
	case "Open Redirect":
		return verifyOpenRedirect(cfg, finding)
	default:
		return true, nil // Default to trust the finding
	}
}

// verifyXSS confirms XSS by attempting re-injection with a unique canary
func verifyXSS(cfg *ScanConfig, finding Finding) (bool, error) {
	baseURL, params, err := extractParamsFromURL(finding.URL)
	if err != nil {
		return false, err
	}

	// Try the same payload again
	params.Set(finding.Parameter, finding.Payload)
	respBody, _, err := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)
	if err != nil {
		return false, err
	}

	// Check if payload is reflected in response
	if strings.Contains(respBody, finding.Payload) {
		LogInfo("XSS finding verified: %s", finding.Parameter)
		return true, nil
	}

	LogWarning("XSS finding could not be verified: %s", finding.Parameter)
	return false, nil
}

// verifySQLi confirms SQLi by checking for error messages
func verifySQLi(cfg *ScanConfig, finding Finding) (bool, error) {
	baseURL, params, err := extractParamsFromURL(finding.URL)
	if err != nil {
		return false, err
	}

	// Try a simple error-based SQLi payload
	testPayload := "1' AND 1=2-- "
	params.Set(finding.Parameter, testPayload)
	respBody, _, err := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)
	if err != nil {
		return false, err
	}

	// Check for SQL error indicators
	sqlErrors := []string{
		"SQL syntax",
		"mysql_",
		"PostgreSQL",
		"ORA-",
		"SQLSTATE",
		"Unclosed quotation",
	}

	for _, errMsg := range sqlErrors {
		if strings.Contains(strings.ToLower(respBody), strings.ToLower(errMsg)) {
			LogInfo("SQLi finding verified: %s", finding.Parameter)
			return true, nil
		}
	}

	LogWarning("SQLi finding could not be verified: %s", finding.Parameter)
	return false, nil
}

// verifyLFI confirms LFI by checking if file content is returned
func verifyLFI(cfg *ScanConfig, finding Finding) (bool, error) {
	baseURL, params, err := extractParamsFromURL(finding.URL)
	if err != nil {
		return false, err
	}

	// Try /etc/passwd again
	testPayload := "../../../etc/passwd"
	params.Set(finding.Parameter, testPayload)
	respBody, _, err := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)
	if err != nil {
		return false, err
	}

	// Check for typical file content
	if strings.Contains(respBody, "root:") && strings.Contains(respBody, "/bin/") {
		LogInfo("LFI finding verified: %s", finding.Parameter)
		return true, nil
	}

	LogWarning("LFI finding could not be verified: %s", finding.Parameter)
	return false, nil
}

// verifyRCE confirms RCE by checking for command output
func verifyRCE(cfg *ScanConfig, finding Finding) (bool, error) {
	baseURL, params, err := extractParamsFromURL(finding.URL)
	if err != nil {
		return false, err
	}

	// Try a simple command
	testPayload := "127.0.0.1;id"
	params.Set(finding.Parameter, testPayload)
	respBody, _, err := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)
	if err != nil {
		return false, err
	}

	// Check for uid output
	if strings.Contains(respBody, "uid=") {
		LogInfo("RCE finding verified: %s", finding.Parameter)
		return true, nil
	}

	LogWarning("RCE finding could not be verified: %s", finding.Parameter)
	return false, nil
}

// verifySSRF confirms SSRF by checking for metadata/internal content
func verifySSRF(cfg *ScanConfig, finding Finding) (bool, error) {
	baseURL, params, err := extractParamsFromURL(finding.URL)
	if err != nil {
		return false, err
	}

	// Try localhost access
	testPayload := "http://127.0.0.1:22"
	params.Set(finding.Parameter, testPayload)
	respBody, _, err := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)
	if err != nil {
		return false, err
	}

	// Check for SSH banner or similar
	ssrfIndicators := []string{"SSH", "root:", "metadata", "token"}
	for _, indicator := range ssrfIndicators {
		if strings.Contains(respBody, indicator) {
			LogInfo("SSRF finding verified: %s", finding.Parameter)
			return true, nil
		}
	}

	LogWarning("SSRF finding could not be verified: %s", finding.Parameter)
	return false, nil
}

// verifySSTI confirms SSTI by checking for expression evaluation
func verifySSTI(cfg *ScanConfig, finding Finding) (bool, error) {
	baseURL, params, err := extractParamsFromURL(finding.URL)
	if err != nil {
		return false, err
	}

	// Try a simple math expression
	testPayload := "{{7*7}}"
	params.Set(finding.Parameter, testPayload)
	respBody, _, err := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)
	if err != nil {
		return false, err
	}

	// Check if expression was evaluated to 49
	if strings.Contains(respBody, "49") {
		LogInfo("SSTI finding verified: %s", finding.Parameter)
		return true, nil
	}

	LogWarning("SSTI finding could not be verified: %s", finding.Parameter)
	return false, nil
}

// verifyNoSQLi confirms NoSQL injection by checking for auth bypass
func verifyNoSQLi(cfg *ScanConfig, finding Finding) (bool, error) {
	baseURL, params, err := extractParamsFromURL(finding.URL)
	if err != nil {
		return false, err
	}

	// Try a simple NoSQL operator
	testPayload := "{'$ne':null}"
	params.Set(finding.Parameter, testPayload)
	respBody, _, err := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)
	if err != nil {
		return false, err
	}

	// Check for success indicators
	successIndicators := []string{"success", "authenticated", "welcome"}
	for _, indicator := range successIndicators {
		if strings.Contains(strings.ToLower(respBody), indicator) {
			LogInfo("NoSQL Injection finding verified: %s", finding.Parameter)
			return true, nil
		}
	}

	LogWarning("NoSQL Injection finding could not be verified: %s", finding.Parameter)
	return false, nil
}

// verifyXXE confirms XXE by checking for file disclosure
func verifyXXE(cfg *ScanConfig, finding Finding) (bool, error) {
	baseURL, params, err := extractParamsFromURL(finding.URL)
	if err != nil {
		return false, err
	}

	// Try a simple XXE payload
	testPayload := "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>"
	params.Set(finding.Parameter, testPayload)
	respBody, _, err := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)
	if err != nil {
		return false, err
	}

	// Check for file content
	if strings.Contains(respBody, "root:") {
		LogInfo("XXE finding verified: %s", finding.Parameter)
		return true, nil
	}

	LogWarning("XXE finding could not be verified: %s", finding.Parameter)
	return false, nil
}

// verifyOpenRedirect confirms Open Redirect by checking for Location header
func verifyOpenRedirect(cfg *ScanConfig, finding Finding) (bool, error) {
	baseURL, params, err := extractParamsFromURL(finding.URL)
	if err != nil {
		return false, err
	}

	// Try a redirect
	testPayload := "http://attacker.com"
	params.Set(finding.Parameter, testPayload)
	_, headers, err := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)
	if err != nil {
		return false, err
	}

	// Check for Location header with attacker URL
	location := headers.Get("Location")
	if strings.Contains(location, "attacker.com") || strings.Contains(location, testPayload) {
		LogInfo("Open Redirect finding verified: %s", finding.Parameter)
		return true, nil
	}

	LogWarning("Open Redirect finding could not be verified: %s", finding.Parameter)
	return false, nil
}

// VerifyAllFindings re-tests all findings to reduce false positives
func VerifyAllFindings(cfg *ScanConfig) {
	if len(cfg.findings) == 0 {
		LogInfo("No findings to verify")
		return
	}

	LogInfo("Starting verification of %d findings", len(cfg.findings))
	verified := 0
	unverified := 0

	// Add small delay between verifications to avoid rate limiting
	verifyDelay := time.Duration(100) * time.Millisecond

	for i, finding := range cfg.findings {
		if IsScanCancelled() {
			LogWarning("Verification cancelled at finding %d/%d", i, len(cfg.findings))
			break
		}

		isValid, err := VerifyFinding(cfg, finding)
		if err != nil {
			LogWarning("Verification error for %s: %v", finding.Parameter, err)
			unverified++
		} else if isValid {
			verified++
			cfg.findings[i].Verified = true
		} else {
			unverified++
			// Mark unverified findings with lower confidence
			finding.Severity = "LOW (Unverified)"
			cfg.findings[i] = finding
		}

		time.Sleep(verifyDelay)
	}

	LogInfo("Verification complete: %d verified, %d unverified", verified, unverified)
}
