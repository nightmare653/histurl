package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	httpClient = &http.Client{
		Timeout: 20 * time.Second,
	}

	// ---- regex library for sensitive info IN URL STRINGS (and optionally in fetched content) ----
	reEmail          = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
	reAWSAccessKeyID = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reAWSSecret      = regexp.MustCompile(`(?i)\baws[_\-]?secret[_\-]?access[_\-]?key\b|(?i)\bsecret[_\-]?key\b`)
	reGCPAPIKey      = regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)
	reHex32Plus      = regexp.MustCompile(`\b[a-f0-9]{32,64}\b`)
	reJWT            = regexp.MustCompile(`\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b`)
	reURLSecrets     = regexp.MustCompile(`(?i)(api[_\-]?key|apikey|key|token|access[_\-]?token|auth|authorization|secret|password|passwd|pwd|bearer|session|sid|client_secret|client_id|private_key|ssh_key|x-api-key|firebase|slack_token|github_token|pat)=([^&]+)`)
	reInterestingAPI = regexp.MustCompile(`(?i)/api(/v?\d+)?/|/graphql|/oauth|/auth|/login|/callback|/refresh|/token`)
	reJSFile         = regexp.MustCompile(`(?i)\.js(\?.*)?$`)
)

// extensions to split into separate files (check path, case-insensitive)
var interestingExtsOrdered = []string{
	// multi-part first so they win over single-part suffixes
	"tar.gz",
	"sqlitedb", "sqlite3",
	// singles
	"xls", "xml", "xlsx", "json", "pdf", "sql", "doc", "docx", "pptx", "txt",
	"zip", "tgz", "bak", "7z", "rar", "log", "cache", "secret", "db", "backup",
	"yml", "gz", "config", "csv", "yaml", "md", "md5", "tar", "xz", "7zip",
	"p12", "pem", "key", "crt", "csr",
	"sh", "pl", "py", "java", "class", "jar", "war", "ear",
	"dbf", "db3", "accdb", "mdb", "sqlcipher",
	"gitignore", "env", "ini", "conf", "properties", "plist", "cfg",
}

var interestingExtSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(interestingExtsOrdered))
	for _, e := range interestingExtsOrdered {
		m[e] = struct{}{}
	}
	return m
}()

// ---------- CLI flags ----------
type Config struct {
	Domain       string
	DomainsFile  string
	OutDir       string
	Concurrency  int
	FetchContent bool
	DelayMS      int
	UserAgent    string

	// Web Archive hardening
	WATimeoutSec int // per-request timeout for Web Archive
	WARetries    int // retries for Web Archive
	WALimit      int // per-page limit for CDX pagination
}

func parseFlags() Config {
	var cfg Config
	flag.StringVar(&cfg.Domain, "domain", "", "Single domain (e.g. example.com)")
	flag.StringVar(&cfg.DomainsFile, "domains-file", "", "File with one domain per line")
	flag.StringVar(&cfg.OutDir, "out", "out_urls", "Output directory")
	flag.IntVar(&cfg.Concurrency, "P", 6, "Concurrency for per-domain collectors")
	flag.BoolVar(&cfg.FetchContent, "fetch-content", false, "Fetch page content for findings scan (slower, be polite)")
	flag.IntVar(&cfg.DelayMS, "delay-ms", 200, "Politeness delay (ms) between remote requests (per collector)")
	flag.StringVar(&cfg.UserAgent, "ua", "ReconURLCollector/1.0 (+https://example)", "HTTP User-Agent")
	flag.IntVar(&cfg.WATimeoutSec, "wa-timeout", 120, "Web Archive request timeout in seconds")
	flag.IntVar(&cfg.WARetries, "wa-retries", 4, "Web Archive retries on failure (5xx/network)")
	flag.IntVar(&cfg.WALimit, "wa-limit", 10000, "Web Archive CDX page size (with showResumeKey)")
	flag.Parse()
	return cfg
}

// ---------- util ----------
func mustMkdir(dir string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
}

func linesFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, s)
		}
	}
	return out, sc.Err()
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, u := range in {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	return out
}

func writeLines(path string, lines []string) error {
	sort.Strings(lines)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
}

func politeSleep(ms int) { time.Sleep(time.Duration(ms) * time.Millisecond) }

func httpGetWithRetry(client *http.Client, req *http.Request, retries int, baseDelay time.Duration) (*http.Response, error) {
	var lastErr error
	for i := 0; i <= retries; i++ {
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("http %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(baseDelay * time.Duration(i+1))
	}
	return nil, lastErr
}

// ---------- external tool runners ----------
func runCmdCollect(cmdName string, args ...string) ([]string, error) {
	cmd := exec.Command(cmdName, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s failed: %v\n%s", cmdName, err, out.String())
	}
	lines := strings.Split(out.String(), "\n")
	var urls []string
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || !strings.Contains(ln, "://") {
			continue
		}
		urls = append(urls, ln)
	}
	return urls, nil
}

func collectWayback(domain string) ([]string, error) {
	return runCmdCollect("waybackurls", domain)
}

func collectGAU(domain string) ([]string, error) {
	if _, err := exec.LookPath("gauplus"); err == nil {
		return runCmdCollect("gauplus", domain)
	}
	return runCmdCollect("gau", domain)
}

// ---------- Web Archive CDX (paged with showResumeKey) ----------
func collectWebArchiveCDX(ctx context.Context, cfg Config, domain string) ([]string, error) {
	politeSleep(cfg.DelayMS)

	base := "https://web.archive.org/cdx/search/cdx"
	limit := cfg.WALimit
	if limit <= 0 {
		limit = 10000
	}
	params := func(resume string) string {
		q := url.Values{}
		q.Set("url", "*."+domain+"/*")
		q.Set("fl", "original")
		q.Set("output", "text")
		q.Set("collapse", "urlkey")
		q.Set("limit", fmt.Sprintf("%d", limit))
		q.Set("showResumeKey", "true")
		if resume != "" {
			q.Set("resumeKey", resume)
		}
		return q.Encode()
	}

	var urls []string
	resume := ""
	waClient := &http.Client{Timeout: time.Duration(cfg.WATimeoutSec) * time.Second}

	for page := 0; page < 10000; page++ {
		endpoint := base + "?" + params(resume)
		req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		req.Header.Set("User-Agent", cfg.UserAgent)

		resp, err := httpGetWithRetry(waClient, req, cfg.WARetries, 2*time.Second)
		if err != nil {
			return urls, err
		}
		sc := bufio.NewScanner(resp.Body)
		var nextResume string
		for sc.Scan() {
			ln := strings.TrimSpace(sc.Text())
			if ln == "" {
				continue
			}
			if strings.Contains(ln, "://") {
				urls = append(urls, ln)
				continue
			}
			nextResume = ln
		}
		resp.Body.Close()
		if err := sc.Err(); err != nil {
			return urls, err
		}
		if nextResume == "" || nextResume == resume {
			break
		}
		resume = nextResume
		politeSleep(250)
	}
	return urls, nil
}

// ---------- AlienVault OTX (correct path) ----------
type otxURLListResp struct {
	HasMore bool `json:"has_more"`
	URLList []struct {
		URL string `json:"url"`
	} `json:"url_list"`
}

func collectOTX(ctx context.Context, cfg Config, domain string) ([]string, error) {
	var all []string
	limit := 500
	page := 1
	client := &http.Client{Timeout: 45 * time.Second}
	for {
		politeSleep(cfg.DelayMS)
		endpoint := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=%d&page=%d",
			url.PathEscape(domain), limit, page)

		req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		req.Header.Set("User-Agent", cfg.UserAgent)

		resp, err := httpGetWithRetry(client, req, 2, 1500*time.Millisecond)
		if err != nil {
			return all, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode == 404 {
			break
		}
		if resp.StatusCode != 200 {
			return all, fmt.Errorf("otx http %d: %s", resp.StatusCode, string(body))
		}
		var r otxURLListResp
		if err := json.Unmarshal(body, &r); err != nil {
			return all, err
		}
		for _, it := range r.URLList {
			if it.URL != "" {
				all = append(all, it.URL)
			}
		}
		if !r.HasMore {
			break
		}
		page++
	}
	return all, nil
}

// ---------- urlscan.io search ----------
type urlscanSearchResp struct {
	Total   int `json:"total"`
	Results []struct {
		Task struct {
			URL string `json:"url"`
		} `json:"task"`
		Page struct {
			URL string `json:"url"`
		} `json:"page"`
	} `json:"results"`
	HasMore bool     `json:"has_more"`
	Next    []string `json:"next"`
}

func collectUrlscan(ctx context.Context, cfg Config, domain string) ([]string, error) {
	var all []string
	var next []string
	first := true
	for {
		politeSleep(cfg.DelayMS)
		var endpoint string
		if first {
			endpoint = fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=10000", url.QueryEscape(domain))
		} else if len(next) > 0 {
			base := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=10000", url.QueryEscape(domain))
			for _, tok := range next {
				base += "&search_after=" + url.QueryEscape(tok)
			}
			endpoint = base
		} else {
			break
		}

		req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		req.Header.Set("User-Agent", cfg.UserAgent)
		resp, err := httpClient.Do(req)
		if err != nil {
			return all, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return all, fmt.Errorf("urlscan http %d: %s", resp.StatusCode, string(body))
		}
		var r urlscanSearchResp
		if err := json.Unmarshal(body, &r); err != nil {
			return all, err
		}
		for _, res := range r.Results {
			if res.Task.URL != "" {
				all = append(all, res.Task.URL)
			}
			if res.Page.URL != "" {
				all = append(all, res.Page.URL)
			}
		}
		if r.HasMore && len(r.Next) > 0 {
			next = r.Next
			first = false
			continue
		}
		break
	}
	return all, nil
}

// ---------- VirusTotal v2 (hardcoded key as requested) ----------
type vtDomainReport struct {
	DetectedURLs []struct {
		URL string `json:"url"`
	} `json:"detected_urls"`
	UndetectedURLs [][]any `json:"undetected_urls"`
}

func collectVirusTotalV2(ctx context.Context, cfg Config, domain string) ([]string, error) {
	politeSleep(cfg.DelayMS)
	endpoint := "https://www.virustotal.com/vtapi/v2/domain/report?apikey=" +
		"83c834350a8e02d1ee621cb042508f15f1c91be662cdc6a600aded2d4992b659" +
		"&domain=" + url.QueryEscape(domain)

	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("virustotal v2 http %d: %s", resp.StatusCode, string(body))
	}
	var r vtDomainReport
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	var out []string
	for _, d := range r.DetectedURLs {
		if d.URL != "" {
			out = append(out, d.URL)
		}
	}
	for _, arr := range r.UndetectedURLs {
		if len(arr) > 0 {
			if u, ok := arr[0].(string); ok && strings.Contains(u, "://") {
				out = append(out, u)
			}
		}
	}
	return out, nil
}

func collectVirusTotal(ctx context.Context, cfg Config, domain string) ([]string, error) {
	return collectVirusTotalV2(ctx, cfg, domain)
}

// ---------- Findings scan ----------
type Finding struct {
	URL     string
	Match   string
	Pattern string
	Source  string // "url" or "content"
}

func scanURLString(u string) (finds []Finding) {
	checks := []struct {
		re      *regexp.Regexp
		pattern string
	}{
		{reEmail, "email"},
		{reAWSAccessKeyID, "aws_access_key_id"},
		{reAWSSecret, "aws_secret_keyword"},
		{reGCPAPIKey, "gcp_api_key"},
		{reHex32Plus, "hex_32_64"},
		{reJWT, "jwt"},
		{reURLSecrets, "url_secret_param"},
		{reInterestingAPI, "interesting_api_path"},
	}
	for _, c := range checks {
		m := c.re.FindAllString(u, -1)
		for _, mm := range m {
			finds = append(finds, Finding{URL: u, Match: mm, Pattern: c.pattern, Source: "url"})
		}
	}
	return
}

func fetchAndScanContent(ctx context.Context, cfg Config, u string) (finds []Finding) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 || resp.ContentLength == 0 || resp.ContentLength > 3*1024*1024 {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 3*1024*1024))
	text := string(body)
	checks := []struct {
		re      *regexp.Regexp
		pattern string
	}{
		{reEmail, "email"},
		{reAWSAccessKeyID, "aws_access_key_id"},
		{reGCPAPIKey, "gcp_api_key"},
		{reHex32Plus, "hex_32_64"},
		{reJWT, "jwt"},
		{reURLSecrets, "secret_like_kv"},
	}
	for _, c := range checks {
		m := c.re.FindAllString(text, -1)
		for _, mm := range m {
			finds = append(finds, Finding{URL: u, Match: mm, Pattern: c.pattern, Source: "content"})
		}
	}
	return
}

// ---------- Interesting file URL classification ----------
func classifyInterestingURLs(urls []string) (allMatches []string, byExt map[string][]string) {
	byExt = make(map[string][]string, len(interestingExtsOrdered))
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		path := strings.ToLower(u.Path)
		if path == "" {
			continue
		}
		// multi-part and specific first (ordered list)
		for _, ext := range interestingExtsOrdered {
			dot := "." + ext
			if strings.HasSuffix(path, dot) {
				byExt[ext] = append(byExt[ext], raw)
				allMatches = append(allMatches, raw)
				break
			}
		}
	}
	// dedupe each bucket and the flat list
	allMatches = dedupe(allMatches)
	for k, v := range byExt {
		byExt[k] = dedupe(v)
	}
	return
}

// ---------- Per-domain pipeline ----------
func processDomain(ctx context.Context, cfg Config, domain string) (allURLs, jsURLs []string, findings []Finding, err error) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	collectors := []struct {
		name string
		fn   func() ([]string, error)
	}{
		{"webarchive-cdx", func() ([]string, error) { return collectWebArchiveCDX(ctx, cfg, domain) }},
		{"waybackurls", func() ([]string, error) { return collectWayback(domain) }},
		{"gau/gauplus", func() ([]string, error) { return collectGAU(domain) }},
		{"otx", func() ([]string, error) { return collectOTX(ctx, cfg, domain) }},
		{"urlscan", func() ([]string, error) { return collectUrlscan(ctx, cfg, domain) }},
		{"virustotal", func() ([]string, error) { return collectVirusTotal(ctx, cfg, domain) }},
	}

	type result struct {
		name string
		urls []string
		err  error
	}

	results := make(chan result, len(collectors))
	sem := make(chan struct{}, 3)
	for _, c := range collectors {
		wg.Add(1)
		go func(cn string, cf func() ([]string, error)) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			urls, e := cf()
			results <- result{name: cn, urls: urls, err: e}
		}(c.name, c.fn)
	}
	wg.Wait()
	close(results)

	var combined []string
	for r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "[%s] error: %v\n", r.name, r.err)
		} else {
			fmt.Fprintf(os.Stderr, "[%s] collected: %d\n", r.name, len(r.urls))
			combined = append(combined, r.urls...)
		}
	}

	combined = dedupe(combined)

	for _, u := range combined {
		if reJSFile.MatchString(u) {
			jsURLs = append(jsURLs, u)
		}
	}

	for _, u := range combined {
		finds := scanURLString(u)
		if len(finds) > 0 {
			findings = append(findings, finds...)
		}
	}

	if cfg.FetchContent {
		fmt.Fprintln(os.Stderr, "[scan] fetching content for possible secrets (limited)…")
		type cjob struct{ u string }
		jobs := make(chan cjob, len(combined))
		for _, u := range combined {
			jobs <- cjob{u}
		}
		close(jobs)
		var wg2 sync.WaitGroup
		workers := 4
		for i := 0; i < workers; i++ {
			wg2.Add(1)
			go func() {
				defer wg2.Done()
				for j := range jobs {
					politeSleep(100)
					ff := fetchAndScanContent(ctx, cfg, j.u)
					if len(ff) > 0 {
						mu.Lock()
						findings = append(findings, ff...)
						mu.Unlock()
					}
				}
			}()
		}
		wg2.Wait()
	}

	return combined, jsURLs, findings, nil
}

func main() {
	cfg := parseFlags()
	if cfg.Domain == "" && cfg.DomainsFile == "" {
		fmt.Fprintln(os.Stderr, "Provide -domain or -domains-file")
		os.Exit(2)
	}

	var domains []string
	if cfg.Domain != "" {
		domains = []string{cfg.Domain}
	}
	if cfg.DomainsFile != "" {
		list, err := linesFromFile(cfg.DomainsFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "domains-file:", err)
			os.Exit(2)
		}
		domains = append(domains, list...)
	}

	mustMkdir(cfg.OutDir)

	type agg struct {
		all []string
		js  []string
		// interesting files
		intAll []string
		intMap map[string][]string
	}
	aggAll := make(map[string]*agg)

	ctx := context.Background()
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	for _, d := range domains {
		domain := strings.TrimSpace(d)
		if domain == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(dom string) {
			defer wg.Done()
			defer func() { <-sem }()
			fmt.Fprintf(os.Stderr, "\n=== Processing %s ===\n", dom)
			all, js, finds, err := processDomain(ctx, cfg, dom)
			if err != nil {
				fmt.Fprintln(os.Stderr, "process error:", err)
				return
			}
			// classify interesting files
			intAll, intMap := classifyInterestingURLs(all)

			// write per-domain files
			dout := filepath.Join(cfg.OutDir, sanitize(dom))
			mustMkdir(dout)
			_ = writeLines(filepath.Join(dout, "all_urls.txt"), all)
			_ = writeLines(filepath.Join(dout, "js_urls.txt"), js)
			_ = writeLines(filepath.Join(dout, "interesting_files.txt"), intAll)

			byExtDir := filepath.Join(dout, "by_ext")
			mustMkdir(byExtDir)
			for ext, lst := range intMap {
				if len(lst) == 0 {
					continue
				}
				_ = writeLines(filepath.Join(byExtDir, "interesting_"+ext+".txt"), lst)
			}

			if len(finds) > 0 {
				writeFindings(filepath.Join(dout, "findings.txt"), finds)
			} else {
				os.WriteFile(filepath.Join(dout, "findings.txt"), []byte("No findings from regex scan on URLs.\n"), 0o644)
			}

			aggAll[dom] = &agg{all: all, js: js, intAll: intAll, intMap: intMap}
		}(domain)
	}
	wg.Wait()

	// Also create merged files across domains
	var mergedAll, mergedJS, mergedIntAll []string
	mergedIntMap := make(map[string][]string)
	for _, v := range aggAll {
		mergedAll = append(mergedAll, v.all...)
		mergedJS = append(mergedJS, v.js...)
		mergedIntAll = append(mergedIntAll, v.intAll...)
		for ext, lst := range v.intMap {
			mergedIntMap[ext] = append(mergedIntMap[ext], lst...)
		}
	}
	mergedAll = dedupe(mergedAll)
	mergedJS = dedupe(mergedJS)
	mergedIntAll = dedupe(mergedIntAll)
	for ext, lst := range mergedIntMap {
		mergedIntMap[ext] = dedupe(lst)
	}

	_ = writeLines(filepath.Join(cfg.OutDir, "ALL_all_urls.txt"), mergedAll)
	_ = writeLines(filepath.Join(cfg.OutDir, "ALL_js_urls.txt"), mergedJS)
	_ = writeLines(filepath.Join(cfg.OutDir, "ALL_interesting_files.txt"), mergedIntAll)

	allByExtDir := filepath.Join(cfg.OutDir, "ALL_by_ext")
	mustMkdir(allByExtDir)
	for ext, lst := range mergedIntMap {
		if len(lst) == 0 {
			continue
		}
		_ = writeLines(filepath.Join(allByExtDir, "interesting_"+ext+".txt"), lst)
	}

	fmt.Fprintf(os.Stderr, "\nDone. Domains: %d | ALL urls: %d | JS urls: %d | Interesting files: %d\n",
		len(aggAll), len(mergedAll), len(mergedJS), len(mergedIntAll))
}

func writeFindings(path string, finds []Finding) error {
	var b strings.Builder
	for _, f := range finds {
		fmt.Fprintf(&b, "[%s] %s  (%s)\n", f.Source, f.Pattern, f.URL)
		if f.Match != "" {
			fmt.Fprintf(&b, "  match: %s\n", f.Match)
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func sanitize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "://", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	return s
}
