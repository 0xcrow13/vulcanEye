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
- `--cookie` : Cookie header for authenticated scans
- `-o` : Output file for results
- `-d` : Enable debug mode
- `--crawl` : Crawl depth (default: 1)
- `-rate` : Max requests per second (default: 10, 0 = unlimited)

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
VulcanEye -u "http://site.com/" -m POST --cookie "PHPSESSID=xyz"
VulcanEye -u "http://site.com/" -s -l
VulcanEye -u "http://site.com/profile" --csrf
VulcanEye -u "http://site.com/" -o results.txt
VulcanEye -u "http://site.com/" -rate 50 -x  # Aggressive scanning (50 req/sec)
VulcanEye -u "http://site.com/" -rate 2 -x   # Stealthy scanning (2 req/sec)
VulcanEye -u "http://site.com/" -ssrf -ssti -nosql -xxe  # Scan for advanced vulnerabilities
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

---

## Credits

Developed by [Xwal13](https://github.com/Xwal13)

---

**Disclaimer:** Use only against systems you have permission to test.  
Illegal or unauthorized usage is strictly prohibited.
