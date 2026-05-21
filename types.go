package main

import "time"

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorPurple = "\033[35m"
	ColorBlue   = "\033[94m"
	ColorBold   = "\033[1m"
	ColorWhite  = "\033[97m"
	ColorDim    = "\033[2m"
)

const (
	IconBullet  = "○"
	IconFinding = "✘"
	IconWarn    = "⚠"
	IconInfo    = "→"
)

type RateLimiter struct {
	ticker *time.Ticker
}

func NewRateLimiter(rps int) *RateLimiter {
	if rps < 1 {
		rps = 10
	}
	return &RateLimiter{
		ticker: time.NewTicker(time.Second / time.Duration(rps)),
	}
}

func (rl *RateLimiter) Wait() {
	<-rl.ticker.C
}

func (rl *RateLimiter) Stop() {
	rl.ticker.Stop()
}

type ScanConfig struct {
	URL               string
	Method            string
	InjectParam       string
	Cookie            string
	OutputFile        string
	Debug             bool
	CrawlLevel        int
	RateLimit         int
	Proxy             string
	CustomHeaders     map[string]string
	UserAgent         string
	LogFile           string
	OutputFormat      string // "text", "json", "xml"

	ScanXSS           bool
	ScanSQLi          bool
	ScanLFI           bool
	ScanRCE           bool
	ScanOpenRedirect  bool
	ScanPathTraversal bool
	ScanCSRF          bool
	ScanSSRF          bool
	ScanSSTI          bool
	ScanNoSQLi        bool
	ScanXXE           bool
	ScanHeaderInjection bool

	rateLimiter *RateLimiter
	findings    []Finding
	logWriter   interface{}
}

type UploadForm struct {
	Action      string
	Method      string
	FileField   string
	OtherFields map[string]string
}

// Finding represents a discovered vulnerability
type Finding struct {
	Type        string `json:"type" xml:"type,attr"`
	Severity    string `json:"severity" xml:"severity,attr"`
	Parameter   string `json:"parameter" xml:"parameter"`
	Payload     string `json:"payload" xml:"payload"`
	URL         string `json:"url" xml:"url"`
	Method      string `json:"method" xml:"method"`
	Timestamp   string `json:"timestamp" xml:"timestamp"`
	Description string `json:"description" xml:"description"`
}

// ScanReport represents the complete scan results
type ScanReport struct {
	StartTime string    `json:"startTime" xml:"startTime"`
	EndTime   string    `json:"endTime" xml:"endTime"`
	Target    string    `json:"target" xml:"target"`
	Total     int       `json:"totalFindings" xml:"totalFindings"`
	Findings  []Finding `json:"findings" xml:"findings>finding"`
}