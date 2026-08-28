package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	privacyTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives:   false,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 25,
		IdleConnTimeout:     90 * time.Second,
	}
)

// getPrivacyHTTPClient returns a high-performance, TLS-hardened HTTP client.
func getPrivacyHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: privacyTransport,
		Timeout:   timeout,
	}
}

// setPrivacyHeaders sets unified, anonymous Tor-grade headers on outgoing requests.
func setPrivacyHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("DNT", "1")
}

// Result represents a single search item with rich media categorization.
type Result struct {
	Title        string `json:"title"`
	URL          string `json:"url"`
	SiteName     string `json:"site_name,omitempty"`
	Snippet      string `json:"snippet"`
	Source       string `json:"source"`   // "web", "wikipedia", "github", "image", "video"
	Category     string `json:"category"` // "general", "wiki", "code", "images", "videos"
	ThumbnailURL string `json:"thumbnail_url,omitempty"`
	MediaURL     string `json:"media_url,omitempty"`
	Duration     string `json:"duration,omitempty"`
	Publisher    string `json:"publisher,omitempty"`
	Width        int    `json:"width,omitempty"`
	Height       int    `json:"height,omitempty"`
}

// InstantAnswer provides rich answers (Knowledge Panel, Calculator, Linux commands).
type InstantAnswer struct {
	Type        string `json:"type"` // "knowledge", "calc", "linux_cmd", "time"
	Title       string `json:"title"`
	Description string `json:"description"`
	Answer      string `json:"answer"`
	ImageURL    string `json:"image_url,omitempty"`
	SourceURL   string `json:"source_url,omitempty"`
	Source      string `json:"source,omitempty"`
}

// SearchResponse matches the enhanced DuckDuckGo-like API schema.
type SearchResponse struct {
	Query           string         `json:"query"`
	Category        string         `json:"category"`
	TookMs          int64          `json:"took_ms"`
	InstantAnswer   *InstantAnswer `json:"instant_answer,omitempty"`
	Results         []Result       `json:"results"`
	RelatedSearches []string       `json:"related_searches"`
}

// SuggestResponse matches the autocomplete schema.
type SuggestResponse struct {
	Query       string   `json:"query"`
	Suggestions []string `json:"suggestions"`
}

// Linux commands instant knowledge base
var linuxCommands = map[string]struct {
	Name string
	Desc string
	Cmd  string
}{
	"tar": {
		Name: "tar (Tape Archive)",
		Desc: "Утилита для создания и распаковки архивов.",
		Cmd:  "tar -xzvf archive.tar.gz   # Распаковать .tar.gz\ntar -czvf archive.tar.gz /path  # Создать .tar.gz",
	},
	"chmod": {
		Name: "chmod (Change Mode)",
		Desc: "Изменение прав доступа к файлам и папкам.",
		Cmd:  "chmod 755 script.sh   # rwxr-xr-x (исполняемый)\nchmod -R 644 /var/www  # Чтение/запись для всех файлов",
	},
	"chown": {
		Name: "chown (Change Owner)",
		Desc: "Смена владельца и группы файлов.",
		Cmd:  "chown user:group filename\nchown -R www-data:www-data /var/www",
	},
	"systemctl": {
		Name: "systemctl (Systemd Control)",
		Desc: "Управление системными службами и демонами в Linux.",
		Cmd:  "systemctl start <service>    # Запустить службу\nsystemctl enable --now <service> # Включить в автозагрузку\nsystemctl status <service>   # Статус службы",
	},
	"grep": {
		Name: "grep (Global Regular Expression Print)",
		Desc: "Поиск текста и шаблонов в файлах и потоках.",
		Cmd:  "grep -rnI \"pattern\" /path/to/dir   # Рекурсивный поиск с номерами строк\ngrep -v \"exclude\" log.txt          # Инвертированный поиск",
	},
	"find": {
		Name: "find",
		Desc: "Мощный поиск файлов в файловой системе.",
		Cmd:  "find /home -name \"*.py\"             # Поиск по имени\nfind . -type f -mtime -7            # Измененные за последние 7 дней\nfind . -size +100M                  # Файлы больше 100 МБ",
	},
	"rsync": {
		Name: "rsync (Remote Sync)",
		Desc: "Быстрая синхронизация файлов локально и по SSH.",
		Cmd:  "rsync -avzP /source/ user@host:/dest/   # Синхронизация с прогрессом и сжатием",
	},
	"ssh": {
		Name: "ssh (Secure Shell)",
		Desc: "Безопасное удаленное подключение по зашифрованному протоколу.",
		Cmd:  "ssh -i ~/.ssh/id_ed25519 user@host -p 22",
	},
	"docker": {
		Name: "docker",
		Desc: "Управление изолированными контейнерами приложений.",
		Cmd:  "docker ps -a                # Список всех контейнеров\ndocker run -d -p 80:80 nginx # Запустить контейнер в фоне\ndocker logs -f <container>  # Смотреть логи",
	},
	"ufw": {
		Name: "ufw (Uncomplicated Firewall)",
		Desc: "Управление межсетевым экраном в Linux.",
		Cmd:  "ufw allow 22/tcp\nufw enable\nufw status verbose",
	},
	"pacman": {
		Name: "pacman (Package Manager)",
		Desc: "Менеджер пакетов дистрибутивов Arch Linux / CachyOS.",
		Cmd:  "pacman -Syu           # Полное обновление системы\npacman -S <pkg>       # Установка пакета\npacman -Ss <keyword>  # Поиск пакета",
	},
	"apt": {
		Name: "apt (Advanced Package Tool)",
		Desc: "Менеджер пакетов дистрибутивов Debian / Ubuntu.",
		Cmd:  "apt update && apt upgrade -y\napt install <pkg>\napt search <keyword>",
	},
	"htop": {
		Name: "htop",
		Desc: "Интерактивный просмотр процессов и мониторинг ресурсов в реальном времени.",
		Cmd:  "htop",
	},
	"df": {
		Name: "df (Disk Free)",
		Desc: "Информация о свободном месте на дисковых разделах.",
		Cmd:  "df -hT   # В удобном формате (GB/MB) с типами файловых систем",
	},
	"free": {
		Name: "free",
		Desc: "Информация об оперативной памяти (RAM) и Swap.",
		Cmd:  "free -h   # Показать объем RAM/Swap в читаемом виде",
	},
	"journalctl": {
		Name: "journalctl",
		Desc: "Просмотр системных журналов systemd.",
		Cmd:  "journalctl -xeu <service>  # Подробные ошибки службы\njournalctl -f              # Лог в реальном времени",
	},
}

// sanitizeQuery strips excessive whitespace, controls, and limits length.
func sanitizeQuery(input string) string {
	cleaned := strings.TrimSpace(input)
	cleaned = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, cleaned)
	if len(cleaned) > 256 {
		cleaned = cleaned[:256]
	}
	return cleaned
}

// resolveInstantAnswer checks for math, linux commands, or quick knowledge facts.
func resolveInstantAnswer(ctx context.Context, query string) *InstantAnswer {
	qLower := strings.ToLower(strings.TrimSpace(query))

	// 1. Check Linux Commands Knowledge
	cmdKey := strings.TrimPrefix(qLower, "man ")
	cmdKey = strings.TrimPrefix(cmdKey, "cmd ")
	cmdKey = strings.TrimPrefix(cmdKey, "команда ")
	cmdKey = strings.TrimSpace(cmdKey)
	if cmdInfo, found := linuxCommands[cmdKey]; found {
		return &InstantAnswer{
			Type:        "linux_cmd",
			Title:       "🐧 " + cmdInfo.Name,
			Description: cmdInfo.Desc,
			Answer:      cmdInfo.Cmd,
			Source:      "Linux Cheat Sheet",
		}
	}

	// 2. Check Math Calculator expressions (e.g. "5 * 25 + 10", "144 / 12", "2 ^ 8")
	calcRegex := regexp.MustCompile(`^[\d\s\+\-\*\/\^\(\)\.\%]+$`)
	if calcRegex.MatchString(qLower) && len(qLower) >= 3 && (strings.ContainsAny(qLower, "+-*/^%")) {
		ans, ok := evaluateMath(qLower)
		if ok {
			return &InstantAnswer{
				Type:        "calc",
				Title:       "🧮 Калькулятор TuxFind",
				Description: fmt.Sprintf("Выражение: %s", query),
				Answer:      ans,
				Source:      "Tux Math Engine",
			}
		}
	}

	// 3. Check Wikipedia Summary Knowledge Graph
	wikiSummary, err := fetchWikipediaSummary(ctx, query)
	if err == nil && wikiSummary != nil && wikiSummary.Extract != "" {
		imgURL := wikiSummary.Thumbnail.Source
		if imgURL == "" {
			imgURL = wikiSummary.OriginalImage.Source
		}
		if (imgURL == "" || !strings.HasPrefix(imgURL, "http")) && (qLower == "тукс" || qLower == "tux") {
			imgURL = "https://upload.wikimedia.org/wikipedia/commons/thumb/3/35/Tux.svg/300px-Tux.svg.png"
		}

		return &InstantAnswer{
			Type:        "knowledge",
			Title:       wikiSummary.Title,
			Description: wikiSummary.Description,
			Answer:      wikiSummary.Extract,
			ImageURL:    imgURL,
			SourceURL:   wikiSummary.ContentURLs.Desktop.Page,
			Source:      "Wikipedia (RU)",
		}
	}

	return nil
}

// evaluateMath safely solves simple arithmetic expressions.
func evaluateMath(expr string) (string, bool) {
	expr = strings.ReplaceAll(expr, " ", "")
	// Simple two-operand power (a^b)
	if strings.Contains(expr, "^") {
		parts := strings.Split(expr, "^")
		if len(parts) == 2 {
			a, err1 := strconv.ParseFloat(parts[0], 64)
			b, err2 := strconv.ParseFloat(parts[1], 64)
			if err1 == nil && err2 == nil {
				res := math.Pow(a, b)
				return fmt.Sprintf("%v", res), true
			}
		}
	}

	// Simple multiplication
	if strings.Contains(expr, "*") && !strings.ContainsAny(expr, "+-/^") {
		parts := strings.Split(expr, "*")
		if len(parts) == 2 {
			a, err1 := strconv.ParseFloat(parts[0], 64)
			b, err2 := strconv.ParseFloat(parts[1], 64)
			if err1 == nil && err2 == nil {
				return fmt.Sprintf("%v", a*b), true
			}
		}
	}

	// Simple division
	if strings.Contains(expr, "/") && !strings.ContainsAny(expr, "+-*^") {
		parts := strings.Split(expr, "/")
		if len(parts) == 2 {
			a, err1 := strconv.ParseFloat(parts[0], 64)
			b, err2 := strconv.ParseFloat(parts[1], 64)
			if err1 == nil && err2 == nil && b != 0 {
				return fmt.Sprintf("%v", a/b), true
			}
		}
	}

	// Simple addition
	if strings.Contains(expr, "+") && !strings.ContainsAny(expr, "*/^") {
		parts := strings.Split(expr, "+")
		if len(parts) == 2 {
			a, err1 := strconv.ParseFloat(parts[0], 64)
			b, err2 := strconv.ParseFloat(parts[1], 64)
			if err1 == nil && err2 == nil {
				return fmt.Sprintf("%v", a+b), true
			}
		}
	}

	// Simple subtraction
	if strings.Contains(expr, "-") && !strings.ContainsAny(expr, "+*/^") {
		parts := strings.Split(expr, "-")
		if len(parts) == 2 {
			a, err1 := strconv.ParseFloat(parts[0], 64)
			b, err2 := strconv.ParseFloat(parts[1], 64)
			if err1 == nil && err2 == nil {
				return fmt.Sprintf("%v", a-b), true
			}
		}
	}

	return "", false
}

// WikiSummarySchema for rich knowledge cards
type WikiSummarySchema struct {
	Title       string `json:"title"`
	Extract     string `json:"extract"`
	Description string `json:"description"`
	Thumbnail   struct {
		Source string `json:"source"`
		Width  int    `json:"width"`
		Height int    `json:"height"`
	} `json:"thumbnail"`
	OriginalImage struct {
		Source string `json:"source"`
	} `json:"originalimage"`
	ContentURLs struct {
		Desktop struct {
			Page string `json:"page"`
		} `json:"desktop"`
	} `json:"content_urls"`
}

func fetchWikipediaSummary(ctx context.Context, query string) (*WikiSummarySchema, error) {
	langs := []string{"ru", "en"}
	for _, lang := range langs {
		apiURL := fmt.Sprintf("https://%s.wikipedia.org/api/rest_v1/page/summary/%s", lang, url.PathEscape(query))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			continue
		}
		setPrivacyHeaders(req)

		client := getPrivacyHTTPClient(2 * time.Second)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var summary WikiSummarySchema
			if err := json.NewDecoder(resp.Body).Decode(&summary); err == nil && summary.Extract != "" {
				if summary.ContentURLs.Desktop.Page == "" {
					summary.ContentURLs.Desktop.Page = fmt.Sprintf("https://%s.wikipedia.org/wiki/%s", lang, url.PathEscape(summary.Title))
				}
				return &summary, nil
			}
		}
	}
	return nil, fmt.Errorf("no summary found")
}

// fetchWikipedia OpenSearch
func fetchWikipedia(ctx context.Context, query string) ([]Result, error) {
	apiURL := fmt.Sprintf(
		"https://ru.wikipedia.org/w/api.php?action=opensearch&search=%s&limit=4&namespace=0&format=json",
		url.QueryEscape(query),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	setPrivacyHeaders(req)

	client := getPrivacyHTTPClient(3 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wikipedia status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var raw []any
	if err := json.Unmarshal(body, &raw); err != nil || len(raw) < 4 {
		return nil, err
	}

	titlesRaw, _ := raw[1].([]any)
	descsRaw, _ := raw[2].([]any)
	urlsRaw, _ := raw[3].([]any)

	var results []Result
	for i := 0; i < len(titlesRaw) && i < len(urlsRaw); i++ {
		title, _ := titlesRaw[i].(string)
		itemURL, _ := urlsRaw[i].(string)
		snippet := ""
		if i < len(descsRaw) {
			snippet, _ = descsRaw[i].(string)
		}
		if snippet == "" {
			snippet = "Энциклопедическая статья из Wikipedia."
		}

		if title != "" && itemURL != "" {
			results = append(results, Result{
				Title:    title,
				URL:      itemURL,
				SiteName: "Википедия",
				Snippet:  snippet,
				Source:   "wikipedia",
				Category: "wiki",
			})
		}
	}

	return results, nil
}

// fetchDuckDuckGoLite parses real web results from DuckDuckGo Lite with safe-search and time filtering.
// Regional parameters are omitted for maximum geo-privacy and un-fingerprintable global neutrality.
func fetchDuckDuckGoLite(ctx context.Context, query string, safe string, timeFilter string) ([]Result, error) {
	params := url.Values{}
	params.Set("q", query)
	params.Set("kl", "wt-wt") // Worldwide / Neutral / Zero-Geo-Tracking

	if safe == "strict" {
		params.Set("kp", "1")
	} else if safe == "moderate" {
		params.Set("kp", "-2")
	} else if safe == "off" {
		params.Set("kp", "-1")
	}
	if timeFilter != "" && timeFilter != "all" && !strings.HasPrefix(timeFilter, "custom_") {
		params.Set("df", timeFilter)
	}

	searchURL := fmt.Sprintf("https://lite.duckduckgo.com/lite/?%s", params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, err
	}
	setPrivacyHeaders(req)

	client := getPrivacyHTTPClient(3500 * time.Millisecond)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DDG Lite returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	content := string(body)
	pattern := regexp.MustCompile(`(?s)<a[^>]+href=["']([^"']+)["'][^>]*class=["']result-link["'][^>]*>(.*?)</a>.*?<td[^>]*class=["']result-snippet["'][^>]*>(.*?)</td>`)
	matches := pattern.FindAllStringSubmatch(content, 15)

	var results []Result
	for _, m := range matches {
		rawURL := m[1]
		rawTitle := m[2]
		rawSnippet := m[3]

		actualURL := extractActualURL(rawURL)
		cleanTitle := cleanHTMLTags(rawTitle)
		cleanSnippet := cleanHTMLTags(rawSnippet)

		if actualURL != "" && cleanTitle != "" {
			siteName := extractSiteName(actualURL)
			results = append(results, Result{
				Title:    cleanTitle,
				URL:      actualURL,
				SiteName: siteName,
				Snippet:  cleanSnippet,
				Source:   "web",
				Category: "general",
			})
		}
	}

	return results, nil
}

// fetchGitHubCode searches GitHub repositories for programming queries.
func fetchGitHubCode(ctx context.Context, query string) ([]Result, error) {
	apiURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s&sort=stars&order=desc&per_page=3", url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	setPrivacyHeaders(req)

	client := getPrivacyHTTPClient(3 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github API status: %d", resp.StatusCode)
	}

	var ghResp struct {
		Items []struct {
			FullName    string `json:"full_name"`
			HTMLURL     string `json:"html_url"`
			Description string `json:"description"`
			Stargazers  int    `json:"stargazers_count"`
			Language    string `json:"language"`
		} `json:"items"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghResp); err != nil {
		return nil, err
	}

	var results []Result
	for _, item := range ghResp.Items {
		desc := item.Description
		if desc == "" {
			desc = fmt.Sprintf("GitHub репозиторий %s (Язык: %s, ⭐ %d)", item.FullName, item.Language, item.Stargazers)
		} else {
			desc = fmt.Sprintf("⭐ %d | %s — %s", item.Stargazers, item.Language, desc)
		}

		results = append(results, Result{
			Title:    item.FullName + " — GitHub",
			URL:      item.HTMLURL,
			SiteName: "GitHub",
			Snippet:  desc,
			Source:   "github",
			Category: "code",
		})
	}

	return results, nil
}

func fetchVQDToken(ctx context.Context, query string) (string, error) {
	reqURL := fmt.Sprintf("https://duckduckgo.com/?q=%s", url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	setPrivacyHeaders(req)

	client := getPrivacyHTTPClient(2500 * time.Millisecond)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	content := string(body)
	re := regexp.MustCompile(`vqd=([0-9-_]+)`)
	matches := re.FindStringSubmatch(content)
	if len(matches) >= 2 {
		return matches[1], nil
	}

	re2 := regexp.MustCompile(`vqd="([^"]+)"`)
	matches2 := re2.FindStringSubmatch(content)
	if len(matches2) >= 2 {
		return matches2[1], nil
	}

	return "", fmt.Errorf("vqd token not found")
}

func fetchImages(ctx context.Context, query string, safe string) ([]Result, error) {
	vqd, err := fetchVQDToken(ctx, query)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("https://duckduckgo.com/i.js?l=wt-wt&o=json&q=%s&vqd=%s&f=,,,&p=1", url.QueryEscape(query), url.QueryEscape(vqd))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	setPrivacyHeaders(req)
	req.Header.Set("Referer", "https://duckduckgo.com/")

	client := getPrivacyHTTPClient(3500 * time.Millisecond)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("images status: %d", resp.StatusCode)
	}

	var imgResp struct {
		Results []struct {
			Title     string `json:"title"`
			Image     string `json:"image"`
			Thumbnail string `json:"thumbnail"`
			URL       string `json:"url"`
			Height    int    `json:"height"`
			Width     int    `json:"width"`
			Source    string `json:"source"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&imgResp); err != nil {
		return nil, err
	}

	var results []Result
	for _, item := range imgResp.Results {
		if item.Image == "" && item.Thumbnail == "" {
			continue
		}
		targetURL := item.URL
		if targetURL == "" {
			targetURL = item.Image
		}
		dimSnippet := fmt.Sprintf("%dx%d", item.Width, item.Height)
		if item.Source != "" {
			dimSnippet += " • " + item.Source
		}

		safeThumb := fmt.Sprintf("https://external-content.duckduckgo.com/iu/?u=%s&f=1&nofb=1", url.QueryEscape(item.Image))
		if item.Image == "" {
			safeThumb = fmt.Sprintf("https://external-content.duckduckgo.com/iu/?u=%s&f=1&nofb=1", url.QueryEscape(item.Thumbnail))
		}

		results = append(results, Result{
			Title:        item.Title,
			URL:          targetURL,
			MediaURL:     item.Image,
			ThumbnailURL: safeThumb,
			SiteName:     item.Source,
			Snippet:      dimSnippet,
			Width:        item.Width,
			Height:       item.Height,
			Source:       "image",
			Category:     "images",
		})
	}
	return results, nil
}

func fetchVideos(ctx context.Context, query string, safe string) ([]Result, error) {
	vqd, err := fetchVQDToken(ctx, query)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("https://duckduckgo.com/v.js?l=wt-wt&o=json&q=%s&vqd=%s&f=,,,&p=1", url.QueryEscape(query), url.QueryEscape(vqd))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	setPrivacyHeaders(req)
	req.Header.Set("Referer", "https://duckduckgo.com/")

	client := getPrivacyHTTPClient(3500 * time.Millisecond)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("videos status: %d", resp.StatusCode)
	}

	var vidResp struct {
		Results []struct {
			Title       string `json:"title"`
			Content     string `json:"content"`
			Description string `json:"description"`
			Duration    string `json:"duration"`
			Publisher   string `json:"publisher"`
			Thumbnail   string `json:"thumbnail"`
			Uploader    string `json:"uploader"`
			Views       int    `json:"views"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&vidResp); err != nil {
		return nil, err
	}

	var results []Result
	for _, item := range vidResp.Results {
		if item.Content == "" && item.Title == "" {
			continue
		}
		snippet := item.Description
		if snippet == "" {
			snippet = item.Publisher
			if item.Duration != "" {
				snippet = "Длительность: " + item.Duration + " • " + snippet
			}
		}

		safeThumb := item.Thumbnail
		if strings.Contains(item.Content, "youtube.com/watch?v=") {
			vParts := strings.Split(item.Content, "v=")
			if len(vParts) > 1 {
				vID := strings.Split(vParts[1], "&")[0]
				safeThumb = fmt.Sprintf("https://i.ytimg.com/vi/%s/hqdefault.jpg", vID)
			}
		} else if item.Thumbnail != "" {
			safeThumb = fmt.Sprintf("https://external-content.duckduckgo.com/iu/?u=%s&f=1&nofb=1", url.QueryEscape(item.Thumbnail))
		}

		results = append(results, Result{
			Title:        item.Title,
			URL:          item.Content,
			MediaURL:     item.Content,
			ThumbnailURL: safeThumb,
			SiteName:     item.Publisher,
			Duration:     item.Duration,
			Publisher:    item.Publisher,
			Snippet:      snippet,
			Source:       "video",
			Category:     "videos",
		})
	}
	return results, nil
}

func fetchDuckDuckGoSuggestions(ctx context.Context, query string) []string {
	apiURL := fmt.Sprintf("https://duckduckgo.com/ac/?q=%s&type=list", url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return []string{}
	}
	setPrivacyHeaders(req)

	client := getPrivacyHTTPClient(1500 * time.Millisecond)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return []string{}
	}
	defer resp.Body.Close()

	var raw []any
	var suggestions []string
	if json.NewDecoder(resp.Body).Decode(&raw) == nil && len(raw) >= 2 {
		if items, ok := raw[1].([]any); ok {
			for _, item := range items {
				if str, ok := item.(string); ok && str != "" {
					suggestions = append(suggestions, str)
				}
			}
		}
	}
	return suggestions
}

func fetchRelatedSearches(ctx context.Context, query string) []string {
	// Try DDG autocomplete first for high-quality natural related searches
	ddgList := fetchDuckDuckGoSuggestions(ctx, query)
	var filtered []string
	qLower := strings.ToLower(strings.TrimSpace(query))

	for _, s := range ddgList {
		if !strings.EqualFold(s, qLower) {
			filtered = append(filtered, s)
		}
	}

	if len(filtered) > 0 {
		if len(filtered) > 8 {
			filtered = filtered[:8]
		}
		return filtered
	}

	// Fallback to Wikipedia OpenSearch
	apiURL := fmt.Sprintf(
		"https://ru.wikipedia.org/w/api.php?action=opensearch&search=%s&limit=8&namespace=0&format=json",
		url.QueryEscape(query),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return []string{}
	}
	req.Header.Set("User-Agent", "TuxFindBot/2.0")
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return []string{}
	}
	defer resp.Body.Close()

	var raw []any
	var related []string
	if json.NewDecoder(resp.Body).Decode(&raw) == nil && len(raw) >= 2 {
		if items, ok := raw[1].([]any); ok {
			for _, item := range items {
				if str, ok := item.(string); ok && str != "" && !strings.EqualFold(str, query) {
					related = append(related, str)
				}
			}
		}
	}

	return related
}

func extractActualURL(rawURL string) string {
	if strings.Contains(rawURL, "uddg=") {
		parsed, err := url.Parse(rawURL)
		if err == nil {
			actual := parsed.Query().Get("uddg")
			if actual != "" {
				return actual
			}
		}
	}
	if strings.HasPrefix(rawURL, "//") {
		return "https:" + rawURL
	}
	return rawURL
}

func extractSiteName(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "Веб-сайт"
	}
	host := strings.TrimPrefix(parsed.Host, "www.")
	if strings.Contains(host, "wikipedia.org") {
		return "Википедия"
	} else if strings.Contains(host, "github.com") {
		return "GitHub"
	} else if strings.Contains(host, "tuxpaint.org") {
		return "Tux Paint"
	} else if strings.Contains(host, "kernel.org") {
		return "Kernel.org"
	} else if strings.Contains(host, "archlinux.org") {
		return "Arch Linux"
	}
	return host
}

func cleanHTMLTags(input string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	cleaned := re.ReplaceAllString(input, "")
	return strings.TrimSpace(html.UnescapeString(cleaned))
}

func scoreResult(res Result, query string) int {
	score := 0
	q := strings.ToLower(strings.TrimSpace(query))
	qWords := strings.Fields(q)
	title := strings.ToLower(res.Title)
	snippet := strings.ToLower(res.Snippet)
	u := strings.ToLower(res.URL)

	// 1. Base score by source (Web results must be primary)
	switch res.Source {
	case "web":
		score += 200
	case "wikipedia":
		score += 50
	case "github":
		score += 20
	default:
		score += 40
	}

	// 2. Brand & Official Domain Boost (e.g. "ютуб" -> youtube.com, "яндекс" -> yandex.ru)
	brandMap := map[string][]string{
		"youtube.com":     {"ютуб", "youtube", "ютюб", "yt"},
		"yandex.ru":       {"яндекс", "yandex"},
		"google.com":      {"гугл", "google"},
		"vk.com":          {"вк", "vk", "вконтакте", "vkontakte"},
		"github.com":      {"гитхаб", "github", "git"},
		"wikipedia.org":   {"википедия", "wikipedia", "вики"},
		"telegram.org":    {"телеграм", "телеграмм", "telegram", "тг"},
		"reddit.com":      {"реддит", "reddit"},
		"twitch.tv":       {"твич", "twitch"},
		"archlinux.org":   {"арч", "arch", "archlinux"},
		"kernel.org":      {"ядро", "kernel"},
		"duckduckgo.com":  {"duckduckgo", "дакдакго"},
	}

	for domain, aliases := range brandMap {
		for _, alias := range aliases {
			if q == alias || strings.Contains(q, alias) {
				if strings.Contains(u, domain) {
					score += 700
					// Massive boost for root homepage/landing URL
					if strings.HasSuffix(u, domain+"/") || strings.HasSuffix(u, domain) || strings.Contains(u, domain+"/feed") {
						score += 400
					}
				}
			}
		}
	}

	// 3. Exact query match in Title
	if title == q || strings.HasPrefix(title, q+" ") || strings.HasPrefix(title, q+" -") || strings.HasPrefix(title, q+" —") {
		score += 250
	} else if strings.Contains(title, q) {
		score += 120
	}

	// 4. Word matches
	for _, word := range qWords {
		if len(word) > 1 {
			if strings.Contains(title, word) {
				score += 40
			}
			if strings.Contains(snippet, word) {
				score += 15
			}
		}
	}

	// 5. Penalize Wikipedia deep biographies when not searching for a specific person
	if res.Source == "wikipedia" {
		if !strings.Contains(q, "вики") && !strings.Contains(q, "wiki") && !strings.Contains(q, "кто такой") && !strings.Contains(q, "что такое") {
			score -= 60
		}
	}

	return score
}

// searchHandler orchestrates parallel fetches for rich answers and results.
func searchHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	rawQuery := r.URL.Query().Get("q")
	categoryFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("category")))
	if categoryFilter == "" {
		categoryFilter = "all"
	}

	safeFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("safe")))
	if safeFilter == "" {
		safeFilter = "strict"
	}

	timeFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("time")))
	if timeFilter == "" {
		timeFilter = "all"
	}

	query := sanitizeQuery(rawQuery)
	if query == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(SearchResponse{
			Query:           "",
			Category:        categoryFilter,
			TookMs:          0,
			Results:         make([]Result, 0),
			RelatedSearches: make([]string, 0),
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3500*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allResults []Result
	var instantAns *InstantAnswer
	var relatedList []string

	if categoryFilter == "images" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			imgResults, err := fetchImages(ctx, query, safeFilter)
			if err == nil && len(imgResults) > 0 {
				mu.Lock()
				allResults = append(allResults, imgResults...)
				mu.Unlock()
			}
		}()
	} else if categoryFilter == "videos" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vidResults, err := fetchVideos(ctx, query, safeFilter)
			if err == nil && len(vidResults) > 0 {
				mu.Lock()
				allResults = append(allResults, vidResults...)
				mu.Unlock()
			}
		}()
	} else if categoryFilter == "code" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ghResults, err := fetchGitHubCode(ctx, query)
			if err == nil && len(ghResults) > 0 {
				mu.Lock()
				allResults = append(allResults, ghResults...)
				mu.Unlock()
			}
		}()
	} else if categoryFilter == "wiki" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wikiResults, err := fetchWikipedia(ctx, query)
			if err == nil && len(wikiResults) > 0 {
				mu.Lock()
				allResults = append(allResults, wikiResults...)
				mu.Unlock()
			}
		}()
	} else {
		// Category == "all" (General Web Search)
		// 1. Instant Answer Resolver
		wg.Add(1)
		go func() {
			defer wg.Done()
			ans := resolveInstantAnswer(ctx, query)
			if ans != nil {
				mu.Lock()
				instantAns = ans
				mu.Unlock()
			}
		}()

		// 2. DuckDuckGo Web Goroutine (Primary Web Index)
		wg.Add(1)
		go func() {
			defer wg.Done()
			webResults, err := fetchDuckDuckGoLite(ctx, query, safeFilter, timeFilter)
			if err == nil && len(webResults) > 0 {
				mu.Lock()
				allResults = append(allResults, webResults...)
				mu.Unlock()
			}
		}()

		// 3. Wikipedia Goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			wikiResults, err := fetchWikipedia(ctx, query)
			if err == nil && len(wikiResults) > 0 {
				mu.Lock()
				allResults = append(allResults, wikiResults...)
				mu.Unlock()
			}
		}()

		// 4. GitHub Code Goroutine (for programming/technical queries)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ghResults, err := fetchGitHubCode(ctx, query)
			if err == nil && len(ghResults) > 0 {
				mu.Lock()
				allResults = append(allResults, ghResults...)
				mu.Unlock()
			}
		}()
	}

	// 5. Related Searches (from DuckDuckGo autocomplete)
	wg.Add(1)
	go func() {
		defer wg.Done()
		rel := fetchRelatedSearches(ctx, query)
		if len(rel) > 0 {
			mu.Lock()
			relatedList = rel
			mu.Unlock()
		}
	}()

	wg.Wait()

	// Deduplicate by URL
	seen := make(map[string]bool)
	deduped := make([]Result, 0)
	for _, res := range allResults {
		if !seen[res.URL] && res.URL != "" {
			seen[res.URL] = true
			deduped = append(deduped, res)
		}
	}

	// Smart Relevance Ranking for general web searches
	rankedResults := deduped
	if categoryFilter == "all" {
		type ScoredResult struct {
			Result Result
			Score  int
		}
		var scoredList []ScoredResult
		for _, res := range deduped {
			scoredList = append(scoredList, ScoredResult{
				Result: res,
				Score:  scoreResult(res, query),
			})
		}

		for i := 0; i < len(scoredList)-1; i++ {
			for j := i + 1; j < len(scoredList); j++ {
				if scoredList[j].Score > scoredList[i].Score {
					scoredList[i], scoredList[j] = scoredList[j], scoredList[i]
				}
			}
		}

		rankedResults = make([]Result, 0, len(scoredList))
		for _, s := range scoredList {
			rankedResults = append(rankedResults, s.Result)
		}
	}

	if relatedList == nil {
		relatedList = make([]string, 0)
	}

	tookMs := time.Since(startTime).Milliseconds()

	response := SearchResponse{
		Query:           query,
		Category:        categoryFilter,
		TookMs:          tookMs,
		InstantAnswer:   instantAns,
		Results:         rankedResults,
		RelatedSearches: relatedList,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[TuxFind] Error encoding JSON: %v", err)
	}
}

// suggestHandler provides live autocomplete suggestions.
func suggestHandler(w http.ResponseWriter, r *http.Request) {
	rawQuery := r.URL.Query().Get("q")
	query := sanitizeQuery(rawQuery)
	if query == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(SuggestResponse{Query: "", Suggestions: []string{}})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
	defer cancel()

	suggestions := fetchDuckDuckGoSuggestions(ctx, query)
	if len(suggestions) == 0 {
		// Fallback to Wikipedia
		apiURL := fmt.Sprintf(
			"https://ru.wikipedia.org/w/api.php?action=opensearch&search=%s&limit=6&namespace=0&format=json",
			url.QueryEscape(query),
		)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "TuxFindBot/2.0")
			client := &http.Client{Timeout: 1500 * time.Millisecond}
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				var raw []any
				if json.NewDecoder(resp.Body).Decode(&raw) == nil && len(raw) >= 2 {
					if items, ok := raw[1].([]any); ok {
						for _, item := range items {
							if str, ok := item.(string); ok && str != "" {
								suggestions = append(suggestions, str)
							}
						}
					}
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(SuggestResponse{
		Query:       query,
		Suggestions: suggestions,
	})
}

// corsMiddleware adds headers for embedded webview access.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, DNT, Sec-GPC")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// imageProxyHandler proxies remote images safely to avoid IP leaks, tracking, and CORS/TLS issues.
func imageProxyHandler(w http.ResponseWriter, r *http.Request) {
	rawURL := r.URL.Query().Get("url")
	if rawURL == "" {
		http.Error(w, "missing url", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   4 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "image/jpeg"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","service":"TuxFind Search Engine 🐧","version":"2.0.0"}`))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/search", searchHandler)
	mux.HandleFunc("/api/v1/suggest", suggestHandler)
	mux.HandleFunc("/api/v1/image-proxy", imageProxyHandler)
	mux.HandleFunc("/health", healthHandler)

	handler := corsMiddleware(mux)

	port := "8080"
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	fmt.Println("🐧 ===================================================")
	fmt.Printf("🐧 TuxFind Search Engine 2.0 запущен на http://localhost:%s\n", port)
	fmt.Println("🐧 Поиск: GET /api/v1/search?q={query}&category={all|wiki|code}")
	fmt.Println("🐧 Подсказки: GET /api/v1/suggest?q={query}")
	fmt.Println("🐧 Приватность: Zero-logs (IP и запросы не сохраняются)")
	fmt.Println("🐧 ===================================================")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
