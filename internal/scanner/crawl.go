package scanner

import (
	"github.com/Xwal13/VulcanEye/internal/config"
	"github.com/Xwal13/VulcanEye/internal/httpclient"
)

func CrawlSite(cfg *config.ScanConfig, startURL string, maxLevel int) []string {
	visited := map[string]bool{}
	queue := []struct {
		url   string
		level int
	}{{startURL, 0}}
	var found []string

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if item.level > maxLevel {
			continue
		}
		if visited[item.url] {
			continue
		}
		visited[item.url] = true
		found = append(found, item.url)

		body, _, err := httpclient.FetchURL(cfg, item.url, "GET", nil, nil)
		if err != nil {
			config.DebugPrintf(cfg, "[CRAWL] Error fetching %s: %v", item.url, err)
			continue
		}
		links := FindLinks(cfg.URL, body)
		for _, link := range links {
			if !visited[link] {
				queue = append(queue, struct {
					url   string
					level int
				}{link, item.level + 1})
			}
		}
	}
	return found
}
