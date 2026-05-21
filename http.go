package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// getHTTPTransport creates an HTTP transport with optional proxy support
func getHTTPTransport(cfg *ScanConfig) *http.Transport {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			tr.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return tr
}

// fetchURL performs GET or POST requests and returns the response body and headers.
func fetchURL(cfg *ScanConfig, u string, method string, data url.Values, extraHeaders map[string]string) (string, http.Header, error) {
	if cfg.rateLimiter != nil {
		cfg.rateLimiter.Wait()
	}
	tr := getHTTPTransport(cfg)
	client := &http.Client{Timeout: 15 * time.Second, Transport: tr}

	var req *http.Request
	var err error
	if method == "POST" {
		req, err = http.NewRequest("POST", u, strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest("GET", u, nil)
	}

	if err != nil {
		return "", nil, err
	}

	// Set User-Agent (use custom if provided, otherwise default)
	userAgent := cfg.UserAgent
	if userAgent == "" {
		userAgent = "pwntwo/1.0"
	}
	req.Header.Set("User-Agent", userAgent)

	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}

	// Add custom headers from config
	if cfg.CustomHeaders != nil {
		for k, v := range cfg.CustomHeaders {
			req.Header.Set(k, v)
		}
	}

	// Add extra headers passed to function
	if extraHeaders != nil {
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
	}

	debugPrintf(cfg, "%s %s", method, u)
	if data != nil && len(data) > 0 {
		debugPrintf(cfg, "POST data: %s", data.Encode())
	}
	if cfg.Cookie != "" {
		debugPrintf(cfg, "Using Cookie: %s", cfg.Cookie)
	}

	// Log request if logging enabled
	LogRequest(cfg, method, u, req.Header, data.Encode())

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)

	// Log response if logging enabled
	LogResponse(cfg, resp.StatusCode, resp.Header, string(bodyBytes))

	return string(bodyBytes), resp.Header, nil
}

// fetchMultipart handles multipart file uploads
func fetchMultipart(cfg *ScanConfig, u string, params map[string]string, fileField, fileName string, fileContent []byte, extraHeaders map[string]string) (string, http.Header, error) {
	if cfg.rateLimiter != nil {
		cfg.rateLimiter.Wait()
	}
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for key, val := range params {
		w.WriteField(key, val)
	}
	if fileField != "" && fileName != "" && fileContent != nil {
		fw, err := w.CreateFormFile(fileField, fileName)
		if err != nil {
			return "", nil, err
		}
		_, err = fw.Write(fileContent)
		if err != nil {
			return "", nil, err
		}
	}
	w.Close()

	req, err := http.NewRequest("POST", u, &b)
	if err != nil {
		return "", nil, err
	}

	// Set User-Agent (use custom if provided, otherwise default)
	userAgent := cfg.UserAgent
	if userAgent == "" {
		userAgent = "pwntwo/1.0"
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", w.FormDataContentType())

	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}

	// Add custom headers from config
	if cfg.CustomHeaders != nil {
		for k, v := range cfg.CustomHeaders {
			req.Header.Set(k, v)
		}
	}

	// Add extra headers passed to function
	if extraHeaders != nil {
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
	}

	tr := getHTTPTransport(cfg)
	client := &http.Client{Timeout: 15 * time.Second, Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	return string(bodyBytes), resp.Header, nil
}

// extractParamsFromURL splits a URL into its base and query params.
func extractParamsFromURL(rawurl string) (string, url.Values, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", nil, err
	}
	params, _ := url.ParseQuery(u.RawQuery)
	u.RawQuery = ""
	return u.String(), params, nil
}