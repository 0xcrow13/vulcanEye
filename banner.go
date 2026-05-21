package main

import "fmt"

func printBanner() {
  fmt.Print(ColorCyan)
  fmt.Println("██╗   ██╗██╗   ██╗██╗      ██████╗ █████╗ ███╗   ██╗███████╗██╗   ██╗███████╗")
  fmt.Println("██║   ██║██║   ██║██║     ██╔════╝██╔══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔════╝")
  fmt.Println("██║   ██║██║   ██║██║     ██║     ███████║██╔██╗ ██║█████╗   ╚████╔╝ █████╗  ")
  fmt.Println("╚██╗ ██╔╝██║   ██║██║     ██║     ██╔══██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔══╝  ")
  fmt.Println(" ╚████╔╝ ╚██████╔╝███████╗╚██████╗██║  ██║██║ ╚████║███████╗   ██║   ███████╗")
  fmt.Println("  ╚═══╝   ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝")
  fmt.Println()
  fmt.Println("              Web Vulnerability Scanner by Xwal13")
  fmt.Print(ColorReset)
}

func printUsage() {
  printBanner()
  fmt.Println()
  fmt.Println("Usage: VulcanEye -u <url> [options]")
  fmt.Println()
  fmt.Println("Options:")
  fmt.Println("  -u string    Target URL to scan (required)")
  fmt.Println("  -m string    HTTP method (GET or POST) (default \"GET\")")
  fmt.Println("  -p string    Parameter name to inject (auto-detect all if omitted)")
  fmt.Println("  --cookie     Cookie header for authenticated scans")
  fmt.Println("  -o string    Output file to save results")
  fmt.Println("  -d           Enable debug mode")
  fmt.Println("  --crawl int  Crawl depth (default 1)")
  fmt.Println()
  fmt.Println("Scan types:")
  fmt.Println("  -x           Cross-Site Scripting (XSS)")
  fmt.Println("  -s           SQL Injection (SQLi)")
  fmt.Println("  -l           Local File Inclusion (LFI)")
  fmt.Println("  -r           Remote Code Execution (RCE)")
  fmt.Println("  --or         Open Redirect")
  fmt.Println("  --pt         Path Traversal")
  fmt.Println("  --csrf       Cross-Site Request Forgery (CSRF)")
  fmt.Println()
  fmt.Println("Examples:")
  fmt.Println("  VulcanEye -u \"http://target.com/page.php?id=1\"")
  fmt.Println("  VulcanEye -u \"http://target.com/\" -m POST --cookie \"PHPSESSID=abc\"")
  fmt.Println("  VulcanEye -u \"http://target.com/\" -x -s")
  fmt.Println()
  fmt.Println("If no scan type is specified, all scans are performed.")
}