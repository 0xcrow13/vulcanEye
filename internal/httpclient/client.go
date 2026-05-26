package httpclient

import (
	"bytes"
	"crypto/tls"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Xwal13/VulcanEye/internal/config"
	"github.com/Xwal13/VulcanEye/internal/output"
)

func GetHTTPTransport(cfg *config.ScanConfig) *http.Transport {
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

func FetchURL(cfg *config.ScanConfig, u string, method string, data url.Values, extraHeaders map[string]string) (string, http.Header, error) {
	if cfg.RateLimiter != nil {
		cfg.RateLimiter.Wait()
	}
	tr := GetHTTPTransport(cfg)
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

	userAgent := cfg.UserAgent
	if userAgent == "" {
		userAgent = "pwntwo/1.0"
	}
	req.Header.Set("User-Agent", userAgent)

	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}

	if cfg.CustomHeaders != nil {
		for k, v := range cfg.CustomHeaders {
			req.Header.Set(k, v)
		}
	}

	if extraHeaders != nil {
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
	}

	config.DebugPrintf(cfg, "%s %s", method, u)
	if data != nil && len(data) > 0 {
		config.DebugPrintf(cfg, "POST data: %s", data.Encode())
	}
	if cfg.Cookie != "" {
		config.DebugPrintf(cfg, "Using Cookie: %s", cfg.Cookie)
	}

	output.LogRequest(cfg, method, u, req.Header, data.Encode())

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		config.DebugPrintf(cfg, "[!] Error reading response body: %v", err)
		return "", resp.Header, err
	}

	output.LogResponse(cfg, resp.StatusCode, resp.Header, string(bodyBytes))

	return string(bodyBytes), resp.Header, nil
}

func FetchMultipart(cfg *config.ScanConfig, u string, params map[string]string, fileField, fileName string, fileContent []byte, extraHeaders map[string]string) (string, http.Header, error) {
	if cfg.RateLimiter != nil {
		cfg.RateLimiter.Wait()
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

	userAgent := cfg.UserAgent
	if userAgent == "" {
		userAgent = "pwntwo/1.0"
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", w.FormDataContentType())

	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}

	if cfg.CustomHeaders != nil {
		for k, v := range cfg.CustomHeaders {
			req.Header.Set(k, v)
		}
	}

	if extraHeaders != nil {
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
	}

	tr := GetHTTPTransport(cfg)
	client := &http.Client{Timeout: 15 * time.Second, Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		config.DebugPrintf(cfg, "[!] Error reading response body: %v", err)
		return "", resp.Header, err
	}
	return string(bodyBytes), resp.Header, nil
}

func ExtractParamsFromURL(rawurl string) (string, url.Values, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", nil, err
	}
	params, _ := url.ParseQuery(u.RawQuery)
	u.RawQuery = ""
	return u.String(), params, nil
}
