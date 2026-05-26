package config

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
	Ticker *time.Ticker
}

func NewRateLimiter(rps int) *RateLimiter {
	if rps < 1 {
		rps = 10
	}
	return &RateLimiter{
		Ticker: time.NewTicker(time.Second / time.Duration(rps)),
	}
}

func (rl *RateLimiter) Wait() {
	<-rl.Ticker.C
}

func (rl *RateLimiter) Stop() {
	rl.Ticker.Stop()
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
	OutputFormat      string

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

	RateLimiter *RateLimiter
	Findings    []Finding
	LogWriter   interface{}
}

type UploadForm struct {
	Action      string
	Method      string
	FileField   string
	OtherFields map[string]string
}

type Finding struct {
	Type        string `json:"type" xml:"type,attr"`
	Severity    string `json:"severity" xml:"severity,attr"`
	Parameter   string `json:"parameter" xml:"parameter"`
	Payload     string `json:"payload" xml:"payload"`
	URL         string `json:"url" xml:"url"`
	Method      string `json:"method" xml:"method"`
	Timestamp   string `json:"timestamp" xml:"timestamp"`
	Description string `json:"description" xml:"description"`
	Verified    bool   `json:"verified" xml:"verified,attr"`
}

type ScanReport struct {
	StartTime string    `json:"startTime" xml:"startTime"`
	EndTime   string    `json:"endTime" xml:"endTime"`
	Target    string    `json:"target" xml:"target"`
	Total     int       `json:"totalFindings" xml:"totalFindings"`
	Findings  []Finding `json:"findings" xml:"findings>finding"`
}
