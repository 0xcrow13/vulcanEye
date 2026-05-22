# VulcanEye

**VulcanEye** is a fast, user-friendly web vulnerability scanner for penetration testers and bug bounty hunters.  
It automates the detection of common web application security issues—like XSS, SQLi, LFI, RCE, SSRF, SSTI, NoSQL injection, XXE, Header Injection, Open Redirect, Path Traversal, and CSRF—across URLs and page parameters.

## Features

- 🚀 **Blazing fast** scanning with automatic crawling and parameter detection
- 🔎 **Detects**:  
   - Cross-Site Scripting (XSS)  
   - SQL Injection (SQLi) - Error-based, Boolean-based, and Time-based  
   - Local File Inclusion (LFI)  
   - Remote Code Execution (RCE)  
   - Server-Side Request Forgery (SSRF)
   - Server-Side Template Injection (SSTI)
   - NoSQL Injection
   - XML External Entity (XXE)
   - Header Injection (CRLF)
   - Open Redirect  
   - Path Traversal  
   - Cross-Site Request Forgery (CSRF)
- 🕵️ **Crawls** target sites to discover endpoints and forms
- 🪝 **Auto-detects injectable parameters** in forms and URLs
- 🍪 **Supports authenticated scans** (via cookies)
- 🔍 **Verifies findings** to reduce false positives (via `--verify`)
- 📊 **Multiple output formats**: text (default), JSON, XML for CI/CD integration
- 🔗 **Proxy support**: Route through Burp Suite or ZAP for additional analysis
- ⚙️ **Customizable**: Custom headers, User-Agent, rate limiting
- 🛡️ **Graceful shutdown**: SIGINT/SIGTERM handling with partial result output
- 👨‍💻 **Built in Go** — runs anywhere, easy to install

## Installation

```sh
go install github.com/Xwal13/VulcanEye@latest
```

Make sure `$GOPATH/bin` or `$HOME/go/bin` is in your `$PATH`.

## Usage

```sh
VulcanEye -u <url> [options]
```

### Main options

- `-u` : Target URL (required)
- `-m` : HTTP method (GET or POST, default: GET)
- `-p` : Parameter to inject (auto-detects if omitted)
- `-cookie` : Cookie header for authenticated scans
- `-o` : Output file to save the results
- `-d` : Enable debug mode
- `-crawl` : Crawl depth (default: 1)
- `-rate` : Max requests per second (default: 10, 0 = unlimited)
- `-proxy` : HTTP proxy URL (e.g., `http://127.0.0.1:8080` for Burp/ZAP)
- `-agent` : Custom User-Agent header
- `-hdr` : Custom header (format: "Name: Value")
- `-log` : Log file for request/response details
- `-elog` : Error log file for warnings and errors
- `-format` : Output format (text, json, or xml, default: text)
- `-verify` : Verify findings by re-testing them (reduces false positives)

### Vulnerability flags

- `-x` : Scan for XSS
- `-s` : Scan for SQLi (error-based, boolean-based, and time-based)
- `-l` : Scan for LFI
- `-r` : Scan for RCE
- `-ssrf` : Scan for Server-Side Request Forgery (SSRF)
- `-ssti` : Scan for Server-Side Template Injection (SSTI)
- `-nosql` : Scan for NoSQL Injection
- `-xxe` : Scan for XML External Entity (XXE)
- `-header` : Scan for Header Injection (CRLF)
- `-or` : Scan for Open Redirect
- `-pt` : Scan for Path Traversal
- `-csrf` : Scan for CSRF

### Examples

```sh
VulcanEye -u "http://site.com/search.php?test=1" -x
VulcanEye -u "http://site.com/" -m POST -cookie "PHPSESSID=xyz"
VulcanEye -u "http://site.com/" -s -l
VulcanEye -u "http://site.com/profile" -csrf
VulcanEye -u "http://site.com/" -o results.txt
VulcanEye -u "http://site.com/" -rate 50 -x  # Aggressive scanning (50 req/sec)
VulcanEye -u "http://site.com/" -rate 2 -x   # Stealthy scanning (2 req/sec)
VulcanEye -u "http://site.com/" -ssrf -ssti -nosql -xxe  # Advanced vulnerabilities
VulcanEye -u "http://site.com/" -format json -o results.json  # CI/CD integration
VulcanEye -u "http://site.com/" -verify -log requests.log  # Verify findings, log requests
VulcanEye -u "http://site.com/" -proxy http://127.0.0.1:8080  # Route through Burp
VulcanEye -u "http://site.com/" -agent "Mozilla/5.0" -hdr "X-Custom: Value"  # Custom headers
```

If no scan flags are specified, **all vulnerability scans are performed by default**.

## Performance Features

### Concurrent Parameter Scanning
VulcanEye scans multiple parameters concurrently (up to 5 simultaneous goroutines) for faster scanning while maintaining server stability.

### Rate Limiting
Use the `-rate` flag to control request throughput:
- **Default**: 10 requests/second
- **Aggressive scanning**: Use `-rate 50` or higher for faster scanning
- **Stealthy scanning**: Use `-rate 1` or `-rate 2` for slower, less detectable scanning
- **Unlimited**: Use `-rate 0` to disable rate limiting (not recommended for live targets)

The rate limiter is applied at the HTTP layer (all scanners), ensuring centralized control and preventing server overload.

## Vulnerability Detection Details

### SQL Injection (SQLi)
- **Error-based**: Detects SQL syntax errors in responses
- **Boolean-based**: Compares responses between TRUE and FALSE conditions
- **Time-based**: Uses SLEEP/WAITFOR/BENCHMARK to detect timing differences

### Server-Side Template Injection (SSTI)
- Detects template injection across multiple template engines
- Supported: Jinja2, ERB, Freemarker, Velocity

### NoSQL Injection
- Tests MongoDB operators ($ne, $gt, $exists)
- Detects JavaScript injection in NoSQL queries

### XML External Entity (XXE)
- Tests for external entity loading
- Detects file disclosure via XML parsing vulnerabilities

### Server-Side Request Forgery (SSRF)
- Tests requests to internal IP ranges (127.0.0.1, localhost, AWS metadata)
- Detects access to internal services and cloud metadata

### Header Injection (CRLF)
- Tests for CRLF injection in HTTP headers
- Detects response splitting and header injection vulnerabilities

### CSRF
- **Improved detection** with regex-based token identification
- Checks for SameSite cookie flags
- Detects Content-Type validation
- Identifies double-submit cookie patterns

## Integration & Advanced Features

### Structured Output Formats
Export scan results in multiple formats for CI/CD integration:
- **JSON**: `-format json -o results.json` — machine-readable format for parsing
- **XML**: `-format xml -o results.xml` — compatible with security tools
- **Text**: Default human-readable format with color output

### Proxy Support
Route all traffic through a proxy for additional inspection:
```sh
VulcanEye -u "http://site.com" -proxy http://127.0.0.1:8080
```
Compatible with:
- Burp Suite (default port 8080)
- OWASP ZAP (default port 8080)
- Mitmproxy and similar tools

### Request/Response Logging
Log all HTTP requests and responses for manual verification:
```sh
VulcanEye -u "http://site.com" -log requests.log
```
Includes request headers, method, URL, and truncated response bodies for debugging.

### Finding Verification
Re-test discovered vulnerabilities to reduce false positives:
```sh
VulcanEye -u "http://site.com" -verify
```
Verification strategies:
- **XSS**: Re-injects payload to confirm reflection
- **SQLi**: Tests error-based payloads for SQL error messages
- **LFI**: Attempts `/etc/passwd` access to confirm file reading
- **RCE**: Re-executes command to confirm output
- **SSRF**: Tests localhost/metadata endpoint access
- **SSTI**: Re-evaluates template expressions
- **NoSQL**: Re-attempts injection operators
- **XXE**: Attempts external entity loading

### Error Handling & Graceful Shutdown
- **Error logging**: `-elog errors.log` to track warnings and errors
- **Graceful shutdown**: Press Ctrl+C to stop scan and save partial results
- **Proper error handling**: All I/O errors are captured and logged (no silent failures)

---

## Credits

Developed by [Xwal13](https://github.com/Xwal13)

---

**Disclaimer:** Use only against systems you have permission to test.  
Illegal or unauthorized usage is strictly prohibited.
