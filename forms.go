package main

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"golang.org/x/net/html"
)

// Extract parameter names from all forms and links in HTML
func extractParamNamesFromHTML(htmlStr string, scanMethod string) ([]string, map[string]bool, error) {
	var paramSet = make(map[string]struct{})
	var fileInputs = make(map[string]bool)
	tokenizer := html.NewTokenizer(strings.NewReader(htmlStr))
	inForm := false
	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			linkParams := extractGETParamsFromLinks(htmlStr)
			for _, p := range linkParams {
				paramSet[p] = struct{}{}
			}
			paramNames := make([]string, 0, len(paramSet))
			for p := range paramSet {
				paramNames = append(paramNames, p)
			}
			sort.Strings(paramNames)
			return paramNames, fileInputs, nil
		case html.StartTagToken:
			t := tokenizer.Token()
			if strings.EqualFold(t.Data, "form") {
				inForm = true
			}
			if strings.EqualFold(t.Data, "input") && inForm {
				inputType := "text"
				inputName := ""
				for _, a := range t.Attr {
					if strings.EqualFold(a.Key, "type") {
						inputType = strings.ToLower(a.Val)
					}
					if strings.EqualFold(a.Key, "name") {
						inputName = a.Val
					}
				}
				if inputName != "" && inputType != "submit" && inputType != "button" && inputType != "reset" && inputType != "image" {
					paramSet[inputName] = struct{}{}
				}
				if inputType == "file" && inputName != "" {
					fileInputs[inputName] = true
				}
			}
			if strings.EqualFold(t.Data, "textarea") && inForm {
				inputName := ""
				for _, a := range t.Attr {
					if strings.EqualFold(a.Key, "name") {
						inputName = a.Val
					}
				}
				if inputName != "" {
					paramSet[inputName] = struct{}{}
				}
			}
		case html.EndTagToken:
			t := tokenizer.Token()
			if strings.EqualFold(t.Data, "form") {
				inForm = false
			}
		}
	}
}

// Extract GET parameters from all <a href="...?..."> links
func extractGETParamsFromLinks(htmlStr string) []string {
	var params []string
	tokenizer := html.NewTokenizer(strings.NewReader(htmlStr))
	set := make(map[string]struct{})
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.StartTagToken {
			t := tokenizer.Token()
			if strings.EqualFold(t.Data, "a") {
				for _, a := range t.Attr {
					if strings.EqualFold(a.Key, "href") && strings.Contains(a.Val, "?") {
						u, err := url.Parse(a.Val)
						if err == nil {
							qs := u.RawQuery
							if qs == "" {
								parts := strings.SplitN(a.Val, "?", 2)
								if len(parts) == 2 {
									qs = parts[1]
								}
							}
							vals, _ := url.ParseQuery(qs)
							for k := range vals {
								set[k] = struct{}{}
							}
						}
					}
				}
			}
		}
	}
	for k := range set {
		params = append(params, k)
	}
	sort.Strings(params)
	return params
}

// Find all links (absolute or relative) on a page
func findLinks(baseURL string, htmlStr string) []string {
	var found []string
	tokenizer := html.NewTokenizer(strings.NewReader(htmlStr))
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.StartTagToken {
			t := tokenizer.Token()
			if strings.EqualFold(t.Data, "a") {
				for _, a := range t.Attr {
					if strings.EqualFold(a.Key, "href") {
						link := a.Val
						u, err := url.Parse(link)
						if err != nil || u.Scheme == "mailto" || u.Scheme == "javascript" {
							continue
						}
						if !u.IsAbs() {
							base, _ := url.Parse(baseURL)
							link = base.ResolveReference(u).String()
						}
						if strings.HasPrefix(link, baseURL) {
							found = append(found, link)
						}
					}
				}
			}
		}
	}
	return found
}

// Robust file upload form parser: detects file field regardless of attribute order, case, and multipart enctype
func findFileUploadForms(htmlStr string) []UploadForm {
	var uploadForms []UploadForm
	tokenizer := html.NewTokenizer(strings.NewReader(htmlStr))
	inForm := false
	var cur UploadForm
	var enctype string

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return uploadForms
		case html.StartTagToken:
			t := tokenizer.Token()
			if strings.EqualFold(t.Data, "form") {
				inForm = true
				cur = UploadForm{
					Method:      "POST",
					Action:      "",
					FileField:   "",
					OtherFields: map[string]string{},
				}
				enctype = ""
				for _, a := range t.Attr {
					switch strings.ToLower(a.Key) {
					case "action":
						cur.Action = a.Val
					case "method":
						cur.Method = strings.ToUpper(a.Val)
					case "enctype":
						enctype = strings.ToLower(a.Val)
					}
				}
			}
			if inForm && strings.EqualFold(t.Data, "input") {
				var name, ftype, value string
				ftype = "text"
				for _, a := range t.Attr {
					switch strings.ToLower(a.Key) {
					case "type":
						ftype = strings.ToLower(a.Val)
					case "name":
						name = a.Val
					case "value":
						value = a.Val
					}
				}
				if name == "" {
					continue
				}
				if ftype == "file" {
					cur.FileField = name
				} else if ftype != "submit" && ftype != "button" && ftype != "reset" && ftype != "image" {
					cur.OtherFields[name] = value
				}
				if ftype == "submit" {
					cur.OtherFields[name] = value
				}
			}
		case html.EndTagToken:
			t := tokenizer.Token()
			if strings.EqualFold(t.Data, "form") && inForm {
				// Only add if it is multipart and has a file field
				if cur.FileField != "" && strings.Contains(enctype, "multipart/form-data") {
					uploadForms = append(uploadForms, cur)
				}
				inForm = false
			}
		}
	}
}

// Scan file upload forms for vulnerabilities
func scanFileUploadForms(cfg *ScanConfig, pageURL string, forms []UploadForm) {
	if len(forms) == 0 {
		printBullet(ColorGreen, "No file upload forms found on this page")
		return
	}
	for _, form := range forms {
		if cfg.Debug {
			fmt.Printf("[DEBUG] Upload form found: action=%q method=%q fileField=%q otherFields=%v\n", form.Action, form.Method, form.FileField, form.OtherFields)
		}
		fullURL := form.Action
		if fullURL == "" || fullURL == "#" {
			fullURL = pageURL
		} else if !strings.HasPrefix(fullURL, "http") {
			base, _ := url.Parse(pageURL)
			fullURL = base.ResolveReference(&url.URL{Path: form.Action}).String()
		}
		printBullet(ColorCyan, fmt.Sprintf("Scanning file field '%s' via form action '%s'", form.FileField, form.Action))
		fileName := "pwntest.php"
		fileContent := []byte("<?php echo 'pwntwouploadmarker'; ?>")
		otherFields := form.OtherFields
		respBody, _, err := fetchMultipart(cfg, fullURL, otherFields, form.FileField, fileName, fileContent, nil)
		if err != nil {
			fmt.Printf("%s  %s %s%s\n", ColorRed, IconWarn, err.Error(), ColorReset)
			continue
		}
		successMarkers := []string{
			"pwntwouploadmarker",
			"uploaded",
			"success",
			"File uploaded",
			fileName,
		}
		vuln := false
		for _, m := range successMarkers {
			if strings.Contains(respBody, m) {
				fmt.Printf("%s  %s POSSIBLE FILE UPLOAD VULNERABILITY%s\n", ColorRed, IconFinding, ColorReset)
				fmt.Printf("    %sFile field    :%s %s%s\n", ColorYellow, ColorReset, form.FileField, ColorReset)
				fmt.Printf("    %sUploaded file :%s %s%s\n", ColorYellow, ColorReset, fileName, ColorReset)
				fmt.Printf("    %sUpload URL    :%s %s%s\n", ColorYellow, ColorReset, fullURL, ColorReset)
				vuln = true
			}
		}
		if !vuln {
			printBullet(ColorGreen, fmt.Sprintf("No file upload vulnerabilities in field '%s'", form.FileField))
		}
	}
}

// Debug print for HTML before parsing forms (add this in your main scanning function)
func debugPrintHTML(cfg *ScanConfig, pageBody string) {
	if cfg.Debug {
		fmt.Println("==== PAGE HTML START ====")
		fmt.Println(pageBody)
		fmt.Println("==== PAGE HTML END ====")
	}
}