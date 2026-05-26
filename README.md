<pre>
██╗   ██╗██╗   ██╗██╗      ██████╗ █████╗ ███╗   ██╗███████╗██╗   ██╗███████╗
██║   ██║██║   ██║██║     ██╔════╝██╔══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔════╝
██║   ██║██║   ██║██║     ██║     ███████║██╔██╗ ██║█████╗   ╚████╔╝ █████╗  
╚██╗ ██╔╝██║   ██║██║     ██║     ██╔══██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔══╝  
 ╚████╔╝ ╚██████╔╝███████╗╚██████╗██║  ██║██║ ╚████║███████╗   ██║   ███████╗
  ╚═══╝   ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝
</pre>

*Web Vulnerability Scanner — by [0xcrow13](https://github.com/0xcrow13/)*

---

**VulcanEye** automates detection of XSS, SQLi, LFI, RCE, SSRF, SSTI, NoSQL, XXE, Header Injection, Open Redirect, Path Traversal, and CSRF — with crawling, rate limiting, proxy support, and CI/CD-friendly JSON/XML output.

## Quick Start

```sh
go install github.com/Xwal13/VulcanEye@latest
VulcanEye -u "http://example.com/page.php?id=1" -x -s
```

If no scan flags are given, **all** vulnerability checks run.

## Features

| What | How |
|------|-----|
| **12 vuln types** | XSS, SQLi (error/boolean/time), LFI, RCE, SSRF, SSTI, NoSQL, XXE, Header Injection, Open Redirect, Path Traversal, CSRF |
| **Concurrent** | Scans all parameters in parallel (up to 5 goroutines) |
| **Auto-crawl** | Discovers endpoints and forms (`-crawl N`) |
| **Rate limiting** | `-rate N` (default 10, 0 = unlimited) |
| **Finding verification** | `-verify` re-tests to cut false positives |
| **Output** | `-format text\|json\|xml -o file` |
| **Proxy** | `-proxy http://127.0.0.1:8080` (Burp/ZAP) |
| **Authenticated** | `-cookie "PHPSESSID=..."` |
| **Graceful Ctrl+C** | Saves partial results on interrupt |

## Usage

```
VulcanEye -u <url> [options]
```

| Flag | Description |
|------|-------------|
| `-u` | Target URL **(required)** |
| `-x` `-s` `-l` `-r` | XSS, SQLi, LFI, RCE |
| `-ssrf` `-ssti` `-nosql` | SSRF, SSTI, NoSQL |
| `-xxe` `-header` `-or` | XXE, Header Injection, Open Redirect |
| `-pt` `-csrf` | Path Traversal, CSRF |
| `-m` | HTTP method (GET\|POST, default GET) |
| `-p` | Parameter to inject (auto-detect) |
| `-cookie` | Auth cookie |
| `-o` | Output file |
| `-format` | Output format (text\|json\|xml) |
| `-verify` | Verify findings |
| `-log` / `-elog` | Request / error log files |
| `-proxy` | HTTP proxy |
| `-rate` | Requests/sec (default 10) |
| `-crawl` | Crawl depth (default 1) |
| `-d` | Debug mode |

## Examples

```sh
VulcanEye -u "http://site.com/" -x -s -l -r
VulcanEye -u "http://site.com/" -format json -o results.json
VulcanEye -u "http://site.com/" -verify -log requests.log
VulcanEye -u "http://site.com/" -proxy http://127.0.0.1:8080
VulcanEye -u "http://site.com/" -rate 50 -x          # aggressive
VulcanEye -u "http://site.com/" -rate 2 -x            # stealthy
```

---

**Disclaimer:** For authorized testing only. Unauthorized use is illegal.
