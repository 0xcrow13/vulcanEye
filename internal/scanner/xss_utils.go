package scanner

import (
	"crypto/rand"
	"fmt"
	"html"
	"net/url"
	"strings"
	"time"

)

func genCanary() string {
	b := make([]byte, 6)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("xssCANARY-%08x", time.Now().UnixNano()&0xFFFFFFFF)
	}
	return fmt.Sprintf("xssCANARY-%s", fmt.Sprintf("%x", b))
}

func injectCanary(payload, canary string) string {
	return strings.ReplaceAll(payload, "%CANARY%", canary)
}

func isPayloadReflected(respBody, canary string) (exact bool, filtered string) {
	if strings.Contains(respBody, canary) {
		return true, ""
	}
	htmlEncoded := html.EscapeString(canary)
	if strings.Contains(respBody, htmlEncoded) {
		return false, "HTML-encoded"
	}
	jsEscaped := toJSEscaped(canary)
	if strings.Contains(respBody, jsEscaped) {
		return false, "JavaScript-escaped"
	}
	urlEncoded := url.QueryEscape(canary)
	if strings.Contains(respBody, urlEncoded) {
		return false, "URL-encoded"
	}
	if isPartialReflection(respBody, canary) {
		return false, "Partially reflected (filtered)"
	}
	return false, ""
}

func toJSEscaped(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		out.WriteString(fmt.Sprintf("\\x%02x", s[i]))
	}
	return out.String()
}

func isPartialReflection(respBody, payload string) bool {
	shortest := 6
	if len(payload) < shortest {
		shortest = len(payload)
	}
	for l := len(payload); l >= shortest; l-- {
		for i := 0; i <= len(payload)-l; i++ {
			sub := payload[i : i+l]
			if strings.Contains(respBody, sub) {
				return true
			}
		}
	}
	return false
}

func findReflections(respBody, payload string) []XSSContext {
	contexts := []XSSContext{}
	idx := 0
	searchBody := respBody
	for {
		idx = strings.Index(searchBody, payload)
		if idx == -1 {
			break
		}
		start := idx - 30
		end := idx + len(payload) + 30
		if start < 0 {
			start = 0
		}
		if end > len(searchBody) {
			end = len(searchBody)
		}
		snippet := searchBody[start:end]
		contexts = append(contexts, detectXSSContext(snippet))
		searchBody = searchBody[idx+len(payload):]
	}
	return contexts
}

func detectXSSContext(snippet string) XSSContext {
	contextIndicators := []struct {
		contextType XSSContext
		patterns    []string
	}{
		{XSSContextHTMLBody, []string{">" + snippet, ">" + snippet[10:20], snippet[10:20] + "<"}},
		{XSSContextAttribute, []string{`"` + snippet, `"` + snippet[:5], `'` + snippet, `'` + snippet[:5]}},
		{XSSContextJSBlock, []string{"<script", "javascript:", "onload=", "onerror=", "onfocus=", "onclick=", "onmouseover=", "onkeypress="}},
		{XSSContextEventHandler, []string{"onfocus=", "onblur=", "onchange=", "onclick=", "ondblclick=", "onerror=", "onfocusin=", "onfocusout=", "onkeydown=", "onkeypress=", "onkeyup=", "onload=", "onmousedown=", "onmousemove=", "onmouseout=", "onmouseover=", "onmouseup=", "onreset=", "onresize=", "onscroll=", "onselect=", "onsubmit=", "onunload="}},
	}

	for _, indicator := range contextIndicators {
		for _, pattern := range indicator.patterns {
			if strings.Contains(snippet, pattern) {
				return indicator.contextType
			}
		}
	}
	return XSSContextUnknown
}
