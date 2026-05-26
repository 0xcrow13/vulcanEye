package app

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/Xwal13/VulcanEye/internal/config"
	"github.com/Xwal13/VulcanEye/internal/httpclient"
	"github.com/Xwal13/VulcanEye/internal/output"
	"github.com/Xwal13/VulcanEye/internal/scanner"
	"github.com/Xwal13/VulcanEye/internal/utils"
)

func Run() {
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" {
			utils.PrintUsage()
			os.Exit(0)
		}
	}

	urlFlag := flag.String("u", "", "Target URL to scan")
	methodFlag := flag.String("m", "GET", "HTTP method (GET or POST)")
	paramFlag := flag.String("p", "", "Parameter name to inject if not present (if omitted, will auto-detect)")
	cookieFlag := flag.String("cookie", "", "Cookie header to use for authenticated scans")
	outputFlag := flag.String("o", "", "Output file to save the results")
	debugFlag := flag.Bool("d", false, "Enable debug mode")
	crawlLevelFlag := flag.Int("crawl", 1, "Crawl level (default 1, higher = deeper crawl)")
	rateFlag := flag.Int("rate", 10, "Max requests per second (0 = unlimited)")
	proxyFlag := flag.String("proxy", "", "HTTP proxy URL (e.g., http://127.0.0.1:8080 for Burp/ZAP)")
	userAgentFlag := flag.String("agent", "", "Custom User-Agent header")
	logFlag := flag.String("log", "", "Log file for request/response details")
	outputFormatFlag := flag.String("format", "text", "Output format: text, json, or xml")
	errorLogFlag := flag.String("elog", "", "Error log file for warnings and errors")
	verifyFlag := flag.Bool("verify", false, "Verify findings by re-testing them (reduces false positives)")

	// Custom headers (can be specified multiple times)
	headerFlag := flag.String("hdr", "", "Custom header (format: \"Name: Value\")")

	// New flags for per-bug scanning
	scanXSSFlag := flag.Bool("x", false, "Scan for Cross-Site Scripting (XSS)")
	scanSQLiFlag := flag.Bool("s", false, "Scan for SQL Injection (SQLi)")
	scanLFIFlag := flag.Bool("l", false, "Scan for Local File Inclusion (LFI)")
	scanRCEFlag := flag.Bool("r", false, "Scan for Remote Code Execution (RCE)")
	scanOpenRedirectFlag := flag.Bool("or", false, "Scan for Open Redirect")
	scanPathTraversalFlag := flag.Bool("pt", false, "Scan for Path Traversal")
	scanCSRFFlag := flag.Bool("csrf", false, "Scan for Cross-Site Request Forgery (CSRF)")
	scanSSRFFlag := flag.Bool("ssrf", false, "Scan for Server-Side Request Forgery (SSRF)")
	scanSSTIFlag := flag.Bool("ssti", false, "Scan for Server-Side Template Injection (SSTI)")
	scanNoSQLiFlag := flag.Bool("nosql", false, "Scan for NoSQL Injection")
	scanXXEFlag := flag.Bool("xxe", false, "Scan for XML External Entity (XXE)")
	scanHeaderInjectionFlag := flag.Bool("header", false, "Scan for Header Injection (CRLF)")

	flag.Parse()

	if *urlFlag == "" {
		utils.PrintUsage()
		os.Exit(1)
	}

	cfg := &config.ScanConfig{
		URL:               *urlFlag,
		Method:            strings.ToUpper(*methodFlag),
		InjectParam:       *paramFlag,
		Cookie:            *cookieFlag,
		OutputFile:        *outputFlag,
		Debug:             *debugFlag,
		CrawlLevel:        *crawlLevelFlag,
		RateLimit:         *rateFlag,
		Proxy:             *proxyFlag,
		UserAgent:         *userAgentFlag,
		LogFile:           *logFlag,
		OutputFormat:      *outputFormatFlag,
		CustomHeaders:     parseCustomHeaders(*headerFlag),
		ScanXSS:           *scanXSSFlag,
		ScanSQLi:          *scanSQLiFlag,
		ScanLFI:           *scanLFIFlag,
		ScanRCE:           *scanRCEFlag,
		ScanOpenRedirect:  *scanOpenRedirectFlag,
		ScanPathTraversal: *scanPathTraversalFlag,
		ScanCSRF:          *scanCSRFFlag,
		ScanSSRF:          *scanSSRFFlag,
		ScanSSTI:          *scanSSTIFlag,
		ScanNoSQLi:        *scanNoSQLiFlag,
		ScanXXE:           *scanXXEFlag,
		ScanHeaderInjection: *scanHeaderInjectionFlag,
	}
	if cfg.RateLimit > 0 {
		cfg.RateLimiter = config.NewRateLimiter(cfg.RateLimit)
		defer cfg.RateLimiter.Stop()
	}

	// If no scan type is specified, enable all
	if !cfg.ScanXSS && !cfg.ScanSQLi && !cfg.ScanLFI && !cfg.ScanRCE && !cfg.ScanOpenRedirect && !cfg.ScanPathTraversal && !cfg.ScanCSRF && !cfg.ScanSSRF && !cfg.ScanSSTI && !cfg.ScanNoSQLi && !cfg.ScanXXE && !cfg.ScanHeaderInjection {
		cfg.ScanXSS = true
		cfg.ScanSQLi = true
		cfg.ScanLFI = true
		cfg.ScanRCE = true
		cfg.ScanOpenRedirect = true
		cfg.ScanPathTraversal = true
		cfg.ScanCSRF = true
		cfg.ScanSSRF = true
		cfg.ScanSSTI = true
		cfg.ScanNoSQLi = true
		cfg.ScanXXE = true
		cfg.ScanHeaderInjection = true
	}

	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Printf("%s[!] Could not open output file: %v%s\n", config.ColorRed, err, config.ColorReset)
			return
		}
		defer f.Close()
		os.Stdout = f
	}

	// Initialize output system for structured formats and logging
	output.InitOutput(cfg)

	// Initialize error logger
	if *errorLogFlag != "" {
		utils.InitErrorLogger(*errorLogFlag)
		defer utils.CloseErrorLogger()
	}

	// Initialize graceful shutdown handling
	utils.InitGracefulShutdown(cfg)
	utils.MarkScanStarted()
	defer utils.MarkScanCompleted()

	utils.PrintBanner()
	printBoxedSection(cfg.URL)

	printBullet(config.ColorCyan, "Fingerprinting backend technologies")
	printBullet(config.ColorCyan, "Host: "+extractHost(cfg.URL))
	printBullet(config.ColorCyan, "WebServer:")

	urls := scanner.CrawlSite(cfg, cfg.URL, cfg.CrawlLevel)
	if len(urls) == 1 {
		printBullet(config.ColorCyan, fmt.Sprintf("Found %d URL", len(urls)))
	} else {
		printBullet(config.ColorCyan, fmt.Sprintf("Found %d URLs", len(urls)))
	}
	for _, u := range urls {
		fmt.Printf("%s    %s %s%s\n", config.ColorCyan, config.IconBullet, u, config.ColorReset)
	}
	fmt.Println()

	for _, targetURL := range urls {
		printBullet(config.ColorCyan, "Scanning "+targetURL)
		pageBody, _, err := httpclient.FetchURL(cfg, targetURL, "GET", nil, nil)
		if err != nil {
			fmt.Printf("%s  %s %s%s\n", config.ColorRed, config.IconWarn, err.Error(), config.ColorReset)
			continue
		}
		paramList, _, _ := scanner.ExtractParamNamesFromHTML(pageBody, cfg.Method)
		uploadForms := scanner.FindFileUploadForms(pageBody)
		if cfg.Debug {
			for _, f := range uploadForms {
				fmt.Printf("%s    %s action=%q method=%q fileField=%q otherFields=%v%s\n", config.ColorCyan, config.IconBullet, f.Action, f.Method, f.FileField, f.OtherFields, config.ColorReset)
			}
		}
		scanner.ScanFileUploadForms(cfg, targetURL, uploadForms)

		if len(paramList) == 0 {
			_, params, _ := httpclient.ExtractParamsFromURL(targetURL)
			for k := range params {
				paramList = append(paramList, k)
			}
		}

		if cfg.InjectParam != "" {
			paramList = []string{cfg.InjectParam}
		}
		if len(paramList) == 0 {
			printBullet(config.ColorYellow, "No injectable parameters found on page")
			if cfg.ScanCSRF {
				scanner.ScanCSRF(cfg, targetURL, "", "", "", targetURL, url.Values{})
			}
			continue
		}
		printBullet(config.ColorCyan, fmt.Sprintf("Auto-detected parameters: %v", paramList))

		var wg sync.WaitGroup
		sem := make(chan struct{}, 5)
		for _, param := range paramList {
			sem <- struct{}{}
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				defer func() { <-sem }()

				baseURL, params, _ := httpclient.ExtractParamsFromURL(targetURL)
				origVal := params.Get(p)
				baseVal := origVal
				if baseVal == "" {
					if scanner.IsNumericParam(p) {
						baseVal = "1"
					} else {
						baseVal = "test"
					}
				}

				for _, submitName := range []string{"Submit", "submit", "go", "Go"} {
					if _, ok := params[submitName]; !ok {
						params.Set(submitName, "Submit")
					}
				}

				origMethod := cfg.Method
				defer func() { cfg.Method = origMethod }()

				if p == "ip" && strings.Contains(targetURL, "/vulnerabilities/exec/") {
					cfg.Method = "POST"
					params.Set("Submit", "Submit")
					baseVal = "127.0.0.1"
				}

				if cfg.ScanRCE {
					printBullet(config.ColorCyan, fmt.Sprintf("Scanning %s for RCE", p))
					if !scanner.ScanRCE(cfg, p, baseVal, origVal, baseURL, params) {
						printBullet(config.ColorGreen, fmt.Sprintf("No RCE in %s", p))
					}
				}

				if cfg.ScanXSS {
					printBullet(config.ColorCyan, fmt.Sprintf("Scanning %s for XSS", p))
					xssFound := scanner.ScanXSS(cfg, p, baseVal, origVal, baseURL, params)
					if xssFound == 0 {
						printBullet(config.ColorGreen, fmt.Sprintf("No XSS in %s", p))
					} else {
						printBullet(config.ColorRed, fmt.Sprintf("Found %d XSS in %s", xssFound, p))
					}
				}

				if cfg.ScanSQLi {
					printBullet(config.ColorCyan, fmt.Sprintf("Scanning %s for SQLi", p))
					sqliFound := scanner.ScanSQLi(cfg, p, baseVal, origVal, baseURL, params)
					if sqliFound == 0 {
						printBullet(config.ColorGreen, fmt.Sprintf("No SQLi in %s", p))
					} else {
						printBullet(config.ColorRed, fmt.Sprintf("Found %d SQLi in %s", sqliFound, p))
					}

					if scanner.ScanBooleanSQLi(cfg, p, baseVal, origVal, baseURL, params) {
						printBullet(config.ColorRed, fmt.Sprintf("Boolean SQLi in %s", p))
					} else {
						printBullet(config.ColorGreen, fmt.Sprintf("No boolean SQLi in %s", p))
					}

					if scanner.ScanSQLiTimeBased(cfg, p, baseVal, origVal, baseURL, params) {
						printBullet(config.ColorRed, fmt.Sprintf("Time-based SQLi in %s", p))
					} else {
						printBullet(config.ColorGreen, fmt.Sprintf("No time-based SQLi in %s", p))
					}
				}

				if cfg.ScanLFI {
					printBullet(config.ColorCyan, fmt.Sprintf("Scanning %s for LFI", p))
					lfiFound := scanner.ScanLFI(cfg, p, baseVal, origVal, baseURL, params)
					if lfiFound == 0 {
						printBullet(config.ColorGreen, fmt.Sprintf("No LFI in %s", p))
					} else {
						printBullet(config.ColorRed, fmt.Sprintf("Found %d LFI in %s", lfiFound, p))
					}
				}

				if cfg.ScanPathTraversal {
					printBullet(config.ColorCyan, fmt.Sprintf("Scanning %s for Path Traversal", p))
					ptFound := scanner.ScanPathTraversal(cfg, p, baseVal, origVal, baseURL, params)
					if ptFound == 0 {
						printBullet(config.ColorGreen, fmt.Sprintf("No Path Traversal in %s", p))
					} else {
						printBullet(config.ColorRed, fmt.Sprintf("Found %d Path Traversal in %s", ptFound, p))
					}
				}

				if cfg.ScanCSRF {
					printBullet(config.ColorCyan, fmt.Sprintf("Scanning %s for CSRF", p))
					csrfFound := scanner.ScanCSRF(cfg, targetURL, p, baseVal, origVal, baseURL, params)
					if csrfFound == 0 {
						printBullet(config.ColorGreen, fmt.Sprintf("No CSRF risk in %s", p))
					} else {
						printBullet(config.ColorRed, fmt.Sprintf("CSRF risk in %s", p))
					}
				}

				if cfg.ScanOpenRedirect {
					redirectParams := []string{"url", "next", "redirect", "return", "dest", "destination", "continue"}
					openRedirectParam := false
					for _, rParam := range redirectParams {
						if strings.EqualFold(p, rParam) {
							openRedirectParam = true
							break
						}
					}
					if openRedirectParam {
						printBullet(config.ColorCyan, fmt.Sprintf("Scanning %s for Open Redirect", p))
						if !scanner.ScanOpenRedirect(cfg, p, baseVal, origVal, baseURL, params) {
							printBullet(config.ColorGreen, fmt.Sprintf("No Open Redirect in %s", p))
						}
					} else {
						printBullet(config.ColorCyan, fmt.Sprintf("Skipping Open Redirect for %s (not a redirect param)", p))
					}
				}

				if cfg.ScanSSRF {
					printBullet(config.ColorCyan, fmt.Sprintf("Scanning %s for SSRF", p))
					if !scanner.ScanSSRF(cfg, p, baseVal, origVal, baseURL, params) {
						printBullet(config.ColorGreen, fmt.Sprintf("No SSRF in %s", p))
					}
				}

				if cfg.ScanSSTI {
					printBullet(config.ColorCyan, fmt.Sprintf("Scanning %s for SSTI", p))
					if !scanner.ScanSSTI(cfg, p, baseVal, origVal, baseURL, params) {
						printBullet(config.ColorGreen, fmt.Sprintf("No SSTI in %s", p))
					}
				}

				if cfg.ScanNoSQLi {
					printBullet(config.ColorCyan, fmt.Sprintf("Scanning %s for NoSQL Injection", p))
					if !scanner.ScanNoSQLi(cfg, p, baseVal, origVal, baseURL, params) {
						printBullet(config.ColorGreen, fmt.Sprintf("No NoSQL Injection in %s", p))
					}
				}

				if cfg.ScanXXE {
					printBullet(config.ColorCyan, fmt.Sprintf("Scanning %s for XXE", p))
					if !scanner.ScanXXE(cfg, p, baseVal, origVal, baseURL, params) {
						printBullet(config.ColorGreen, fmt.Sprintf("No XXE in %s", p))
					}
				}

				if cfg.ScanHeaderInjection {
					printBullet(config.ColorCyan, fmt.Sprintf("Scanning %s for Header Injection", p))
					if !scanner.ScanHeaderInjection(cfg, p, baseVal, origVal, baseURL, params) {
						printBullet(config.ColorGreen, fmt.Sprintf("No Header Injection in %s", p))
					}
				}
			}(param)
		}
		wg.Wait()
	}

	// Verify findings if requested
	if *verifyFlag && len(cfg.Findings) > 0 {
		utils.LogInfo("Starting finding verification...")
		utils.VerifyAllFindings(cfg)
		utils.LogInfo("Finding verification complete")
	}

	// Finalize output and write results in the requested format
	if err := output.FinalizeOutput(cfg); err != nil {
		fmt.Printf("%s[!] Error writing output: %v%s\n", config.ColorRed, err, config.ColorReset)
	}
}

// parseCustomHeaders parses a custom header string (format: "Name: Value")
func parseCustomHeaders(headerStr string) map[string]string {
	headers := make(map[string]string)
	if headerStr == "" {
		return headers
	}

	parts := strings.Split(headerStr, ":")
	if len(parts) >= 2 {
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(strings.Join(parts[1:], ":"))
		headers[name] = value
	}
	return headers
}

func extractHost(fullURL string) string {
	u, err := url.Parse(fullURL)
	if err != nil {
		return ""
	}
	return u.Host
}

func printBullet(color, msg string) {
	fmt.Printf("%s  %s %s%s\n", color, config.IconBullet, msg, config.ColorReset)
}

func printBoxedSection(title string) {
	fmt.Println()
	fmt.Printf("%s  ── Target ── %s%s\n", config.ColorCyan, title, config.ColorReset)
}