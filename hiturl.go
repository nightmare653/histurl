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

	// ---- credential helpers (for URL parsing only) ----
	rePasswordParamName = regexp.MustCompile(`(?i)^(password|passwd|pass|pwd|pword|secret|pw|login_password)$`)
	reEmailParamName    = regexp.MustCompile(`(?i)^(email|e|user|username|login|userid|user_id|mail)$`)

	// default HTTP client with standard timeout
	defaultHTTPClient = &http.Client{
		Timeout: 20 * time.Second,
	}
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
	OutputFormat string // "text" or "json"
	Verbose      bool
	ConfigFile   string // Load settings from JSON/YAML file

	// Web Archive hardening
	WATimeoutSec int // per-request timeout for Web Archive
	WARetries    int // retries for Web Archive
	WALimit      int // per-page limit for CDX pagination

	// Credentials extraction (URL-only)
	ExtractCreds bool
	CredsOutFile string
}

// parseFlags parses and validates command-line arguments, with config file support.
func parseFlags() Config {
	var cfg Config
	flag.StringVar(&cfg.Domain, "domain", "", "Single domain (e.g. example.com)")
	flag.StringVar(&cfg.DomainsFile, "domains-file", "", "File with one domain per line")
	flag.StringVar(&cfg.OutDir, "out", "results", "Output directory")
	flag.IntVar(&cfg.Concurrency, "P", 6, "Concurrency for per-domain collectors")
	flag.BoolVar(&cfg.FetchContent, "fetch-content", false, "Fetch page content for findings scan (slower, be polite)")
	flag.IntVar(&cfg.DelayMS, "delay-ms", 200, "Politeness delay (ms) between remote requests (per collector)")
	flag.StringVar(&cfg.UserAgent, "ua", "ReconURLCollector/1.0 (+https://example)", "HTTP User-Agent")
	flag.IntVar(&cfg.WATimeoutSec, "wa-timeout", 120, "Web Archive request timeout in seconds")
	flag.IntVar(&cfg.WARetries, "wa-retries", 4, "Web Archive retries on failure (5xx/network)")
	flag.IntVar(&cfg.WALimit, "wa-limit", 10000, "Web Archive CDX page size (with showResumeKey)")
	flag.StringVar(&cfg.OutputFormat, "format", "text", "Output format: text or json")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output")
	flag.StringVar(&cfg.ConfigFile, "config", "", "Configuration file (JSON or YAML format)")

	// creds
	flag.BoolVar(&cfg.ExtractCreds, "extract-creds", false, "Attempt to extract email+password pairs from URL querystrings (opt-in)")
	flag.StringVar(&cfg.CredsOutFile, "creds-out", "", "Optional prefix/path for credential output files (default: per-domain in out dir)")

	flag.Parse()

	// Load config file if provided
	if cfg.ConfigFile != "" {
		if err := loadConfigFile(&cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config file: %v\n", err)
			os.Exit(2)
		}
	}

	// Validate inputs
	if err := validateConfig(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(2)
	}

	return cfg
}

// loadConfigFile loads configuration from JSON or YAML file.
// YAML files are converted to JSON or parsed manually.
func loadConfigFile(cfg *Config) error {
	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		return fmt.Errorf("cannot read config file: %v", err)
	}

	// Check file extension to determine format
	ext := strings.ToLower(filepath.Ext(cfg.ConfigFile))

	if ext == ".json" {
		if err := json.Unmarshal(data, cfg); err != nil {
			return fmt.Errorf("invalid JSON config: %v", err)
		}
		return nil
	}

	if ext == ".yaml" || ext == ".yml" {
		// For YAML, try parsing as key=value pairs or basic YAML structure
		return parseYAMLConfig(string(data), cfg)
	}

	// Try JSON first, then basic YAML
	if err := json.Unmarshal(data, cfg); err == nil {
		return nil
	}

	return parseYAMLConfig(string(data), cfg)
}

// parseYAMLConfig parses simple YAML format (key: value).
func parseYAMLConfig(content string, cfg *Config) error {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "domain":
			cfg.Domain = value
		case "domains_file", "domains-file":
			cfg.DomainsFile = value
		case "out", "out_dir":
			cfg.OutDir = value
		case "concurrency", "P":
			fmt.Sscanf(value, "%d", &cfg.Concurrency)
		case "fetch_content", "fetch-content":
			cfg.FetchContent = value == "true" || value == "yes" || value == "1"
		case "delay_ms", "delay-ms":
			fmt.Sscanf(value, "%d", &cfg.DelayMS)
		case "user_agent", "ua":
			cfg.UserAgent = value
		case "format", "output_format":
			cfg.OutputFormat = value
		case "verbose", "v":
			cfg.Verbose = value == "true" || value == "yes" || value == "1"
		case "wa_timeout", "wa-timeout":
			fmt.Sscanf(value, "%d", &cfg.WATimeoutSec)
		case "wa_retries", "wa-retries":
			fmt.Sscanf(value, "%d", &cfg.WARetries)
		case "wa_limit", "wa-limit":
			fmt.Sscanf(value, "%d", &cfg.WALimit)
		case "extract_creds", "extract-creds":
			cfg.ExtractCreds = value == "true" || value == "yes" || value == "1"
		case "creds_out", "creds-out":
			cfg.CredsOutFile = value
		}
	}
	return nil
}

// validateConfig validates configuration values.
func validateConfig(cfg *Config) error {
	if cfg.Domain == "" && cfg.DomainsFile == "" {
		return fmt.Errorf("provide -domain or -domains-file")
	}
	if cfg.Concurrency < 1 || cfg.Concurrency > 128 {
		return fmt.Errorf("concurrency must be between 1 and 128")
	}
	if cfg.DelayMS < 0 || cfg.DelayMS > 60000 {
		return fmt.Errorf("delay-ms must be between 0 and 60000")
	}
	if cfg.WATimeoutSec < 5 || cfg.WATimeoutSec > 600 {
		return fmt.Errorf("wa-timeout must be between 5 and 600")
	}
	if cfg.WARetries < 0 || cfg.WARetries > 10 {
		return fmt.Errorf("wa-retries must be between 0 and 10")
	}
	if cfg.OutputFormat != "text" && cfg.OutputFormat != "json" {
		return fmt.Errorf("format must be 'text' or 'json'")
	}
	if cfg.DomainsFile != "" {
		if _, err := os.Stat(cfg.DomainsFile); err != nil {
			return fmt.Errorf("domains-file not readable: %v", err)
		}
	}
	return nil
}

// ---------- util ----------

// mustMkdir creates a directory with error handling.
func mustMkdir(dir string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create directory %s: %v\n", dir, err)
		os.Exit(1)
	}
}

// getVirusTotalAPIKey retrieves the hardcoded API key for VirusTotal.
func getVirusTotalAPIKey() string {
	// Hardcoded API key as requested
	return "83c834350a8e02d1ee621cb042508f15f1c91be662cdc6a600aded2d4992b659"
}

// linesFromFile reads lines from a file, ignoring comments and empty lines.
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

// dedupe removes duplicate strings from a slice.
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

// dedupeAsMap returns a map of unique strings for faster membership checking.
func dedupeAsMap(in []string) map[string]struct{} {
	seen := make(map[string]struct{}, len(in))
	for _, u := range in {
		u = strings.TrimSpace(u)
		if u != "" {
			seen[u] = struct{}{}
		}
	}
	return seen
}

// writeLines writes strings to a file, sorted and deduplicated.
func writeLines(path string, lines []string) error {
	lines = dedupe(lines)
	sort.Strings(lines)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 64*1024) // Use larger buffer for better performance
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to write %s: %v", path, err)
	}
	return nil
}

// politeSleep pauses execution for the specified milliseconds.
func politeSleep(ms int) { time.Sleep(time.Duration(ms) * time.Millisecond) }

// vlogf prints verbose log messages if verbose flag is enabled.
func vlogf(verbose bool, format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[verbose] "+format+"\n", args...)
	}
}

// httpGetWithRetry performs an HTTP request with exponential backoff retry logic.
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
		if i < retries {
			time.Sleep(baseDelay * time.Duration(i+1))
		}
	}
	return nil, lastErr
}

// ---------- external tool runners ----------

// runCmdCollect executes an external command and collects URL output lines.
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

// runCmdCollectStdin executes an external command with stdin input and collects URL output.
func runCmdCollectStdin(cmdName string, stdinText string, args ...string) ([]string, error) {
	cmd := exec.Command(cmdName, args...)
	cmd.Stdin = strings.NewReader(stdinText + "\n")
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

// collectWayback retrieves URLs from Wayback Machine via waybackurls tool.
func collectWayback(domain string) ([]string, error) {
	return runCmdCollect("waybackurls", domain)
}

// collectGAU retrieves URLs from Wayback Machine via gau or gauplus tool.
func collectGAU(domain string) ([]string, error) {
	// prefer gauplus; try argv -subs then stdin fallback
	if _, err := exec.LookPath("gauplus"); err == nil {
		if urls, err2 := runCmdCollect("gauplus", "-subs", domain); err2 == nil && len(urls) > 0 {
			return urls, nil
		}
		if urls, err2 := runCmdCollectStdin("gauplus", domain, "-subs"); err2 == nil && len(urls) > 0 {
			return urls, nil
		}
		if urls, err2 := runCmdCollect("gauplus", domain); err2 == nil && len(urls) > 0 {
			return urls, nil
		}
	}
	if _, err := exec.LookPath("gau"); err == nil {
		if urls, err2 := runCmdCollect("gau", "-subs", domain); err2 == nil && len(urls) > 0 {
			return urls, nil
		}
		if urls, err2 := runCmdCollectStdin("gau", domain, "-subs"); err2 == nil && len(urls) > 0 {
			return urls, nil
		}
		if urls, err2 := runCmdCollect("gau", domain); err2 == nil && len(urls) > 0 {
			return urls, nil
		}
	}
	return nil, nil
}

// ---------- Web Archive CDX (paged with showResumeKey) ----------

// collectWebArchiveCDX retrieves URLs from Web Archive CDX API with pagination.
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

// otxURLListResp represents the response from AlienVault OTX API.
type otxURLListResp struct {
	HasMore bool `json:"has_more"`
	URLList []struct {
		URL string `json:"url"`
	} `json:"url_list"`
}

// collectOTX retrieves URLs from AlienVault OTX API.
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

// urlscanSearchResp represents the response from urlscan.io search API.
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

// collectUrlscan retrieves URLs from urlscan.io search API.
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
		resp, err := defaultHTTPClient.Do(req)
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

// collectVirusTotalV2 fetches URLs from VirusTotal API v2.
func collectVirusTotalV2(ctx context.Context, cfg Config, domain string) ([]string, error) {
	apiKey := getVirusTotalAPIKey()
	if apiKey == "" {
		return nil, nil // Skip if no API key
	}

	politeSleep(cfg.DelayMS)
	endpoint := "https://www.virustotal.com/vtapi/v2/domain/report?apikey=" +
		apiKey +
		"&domain=" + url.QueryEscape(domain)

	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := httpGetWithRetry(client, req, 2, 1500*time.Millisecond)
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

// collectVirusTotal is a wrapper for VirusTotal collection.
func collectVirusTotal(ctx context.Context, cfg Config, domain string) ([]string, error) {
	return collectVirusTotalV2(ctx, cfg, domain)
}

// ---------- Findings scan ----------

// Finding represents a potential security finding in a URL or content.
type Finding struct {
	URL     string
	Match   string
	Pattern string
	Source  string // "url" or "content"
}

// scanURLString scans a URL string for sensitive patterns.
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

// ---------- Credentials (URL-only) ----------

// Credential represents extracted email and password pairs from URLs.
type Credential struct {
	URL      string
	Email    string
	Password string
	Source   string // "url"
}

// looksLikePassword checks if a string is likely a password based on format heuristics.
func looksLikePassword(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 4 || len(s) > 512 {
		return false
	}
	// skip long hex-ish tokens
	if matched, _ := regexp.MatchString(`^[a-fA-F0-9]{20,}$`, s); matched {
		return false
	}
	// skip tokens with path-ish chars
	if strings.ContainsAny(s, "/:") {
		return false
	}
	return true
}

// scanURLForCreds extracts email and password pairs from URL query parameters.
func scanURLForCreds(rawurl string) *Credential {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil
	}
	q := u.Query()
	var foundEmail, foundPass string

	// try param name matching first
	for k, vals := range q {
		if len(vals) == 0 {
			continue
		}
		v := strings.TrimSpace(vals[0])
		if reEmailParamName.MatchString(k) && reEmail.MatchString(v) {
			foundEmail = v
		}
		if rePasswordParamName.MatchString(k) && v != "" && looksLikePassword(v) {
			foundPass = v
		}
	}

	// fallback: any param value that looks like an email
	if foundEmail == "" {
		for _, vals := range q {
			if len(vals) == 0 {
				continue
			}
			if reEmail.MatchString(vals[0]) {
				foundEmail = vals[0]
				break
			}
		}
	}

	// fallback: any param value that looks like a password
	if foundPass == "" {
		for k, vals := range q {
			if len(vals) == 0 {
				continue
			}
			v := vals[0]
			if len(v) >= 4 && (rePasswordParamName.MatchString(k) || looksLikePassword(v)) {
				foundPass = v
				break
			}
		}
	}

	if foundEmail != "" && foundPass != "" {
		return &Credential{URL: rawurl, Email: foundEmail, Password: foundPass, Source: "url"}
	}
	return nil
}

// fetchAndScanContent fetches a URL and scans content for sensitive patterns.
func fetchAndScanContent(ctx context.Context, cfg Config, u string) (finds []Finding) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := defaultHTTPClient.Do(req)
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

// classifyInterestingURLs categorizes URLs by file extension.
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

// processDomain orchestrates the collection and analysis pipeline for a single domain.
// Uses concurrent deduplication with sync.Map for better performance on large datasets.
func processDomain(ctx context.Context, cfg Config, domain string) (allURLs, jsURLs []string, findings []Finding, creds []Credential, err error) {
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use sync.Map for concurrent deduplication
	urlMap := &sync.Map{}

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

	// Process results with concurrent deduplication
	for r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "[%s] error: %v\n", r.name, r.err)
		} else {
			fmt.Fprintf(os.Stderr, "[%s] collected: %d\n", r.name, len(r.urls))
			// Add URLs to sync.Map for concurrent dedup
			for _, u := range r.urls {
				u = strings.TrimSpace(u)
				if u != "" {
					urlMap.Store(u, struct{}{})
				}
			}
		}
	}

	// Convert sync.Map back to slice
	fmt.Fprintln(os.Stderr, "[info] Deduplicating and processing URLs...")
	urlMap.Range(func(key, value interface{}) bool {
		allURLs = append(allURLs, key.(string))
		return true
	})
	sort.Strings(allURLs)
	fmt.Fprintf(os.Stderr, "[info] After dedup: %d unique URLs from %d collectors\n", len(allURLs), len(collectors))

	// Extract JS urls and URL-only creds here
	jsSet := &sync.Map{}

	fmt.Fprintln(os.Stderr, "[info] Extracting JS URLs and credentials...")
	for _, u := range allURLs {
		if reJSFile.MatchString(u) {
			jsSet.Store(u, struct{}{})
		}
		if cfg.ExtractCreds {
			if c := scanURLForCreds(u); c != nil {
				creds = append(creds, *c)
			}
		}
	}

	// Convert js set to slice
	jsSet.Range(func(key, value interface{}) bool {
		jsURLs = append(jsURLs, key.(string))
		return true
	})
	sort.Strings(jsURLs)
	vlogf(cfg.Verbose, "Extracted %d JS URLs, %d credential pairs", len(jsURLs), len(creds))

	// Scan URL strings for other findings (separate from creds)
	for _, u := range allURLs {
		finds := scanURLString(u)
		if len(finds) > 0 {
			mu.Lock()
			findings = append(findings, finds...)
			mu.Unlock()
		}
	}

	// If content scan enabled, fetch pages and scan for findings (no credential extraction)
	if cfg.FetchContent {
		fmt.Fprintln(os.Stderr, "[scan] fetching content for possible secrets (limited)…")
		type cjob struct{ u string }
		jobs := make(chan cjob, len(allURLs))
		for _, u := range allURLs {
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

	return allURLs, jsURLs, findings, creds, nil
}

// loadEnvFile loads environment variables from .env file if it exists.
func loadEnvFile() error {
	envFiles := []string{".env", ".env.local"}
	for _, envFile := range envFiles {
		if _, err := os.Stat(envFile); err == nil {
			file, err := os.Open(envFile)
			if err != nil {
				return fmt.Errorf("failed to open %s: %v", envFile, err)
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				// Skip empty lines and comments
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				// Parse KEY=VALUE format
				if idx := strings.Index(line, "="); idx > 0 {
					key := strings.TrimSpace(line[:idx])
					value := strings.TrimSpace(line[idx+1:])
					// Remove surrounding quotes if present
					if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') ||
						(value[0] == '\'' && value[len(value)-1] == '\'')) {
						value = value[1 : len(value)-1]
					}
					os.Setenv(key, value)
				}
			}

			if err := scanner.Err(); err != nil {
				return fmt.Errorf("error reading %s: %v", envFile, err)
			}

			fmt.Fprintf(os.Stderr, "[info] Loaded environment variables from %s\n", envFile)
			break // Load only the first found .env file
		}
	}
	return nil
}

func main() {
	// Load environment variables from .env file
	if err := loadEnvFile(); err != nil {
		fmt.Fprintf(os.Stderr, "[warn] Failed to load .env file: %v\n", err)
	}

	cfg := parseFlags()

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
		all    []string
		js     []string
		intAll []string
		intMap map[string][]string
		creds  []Credential
	}
	aggAll := make(map[string]*agg)
	var aggMu sync.Mutex // guard aggAll writes

	// Use context with timeout for large domain collection (30 minutes per domain)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

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
			all, js, finds, creds, err := processDomain(ctx, cfg, dom)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[error] %s: process error: %v\n", dom, err)
				return
			}
			// classify interesting files
			fmt.Fprintf(os.Stderr, "[info] Classifying interesting files for %s...\n", dom)
			intAll, intMap := classifyInterestingURLs(all)

			// write per-domain files
			dout := filepath.Join(cfg.OutDir, sanitize(dom))
			mustMkdir(dout)
			fmt.Fprintf(os.Stderr, "[info] Writing results to %s/\n", sanitize(dom))
			_ = writeLines(filepath.Join(dout, "all_urls.txt"), all)
			fmt.Fprintf(os.Stderr, "[info]   ✓ all_urls.txt (%d URLs)\n", len(all))
			_ = writeLines(filepath.Join(dout, "js_urls.txt"), js)
			fmt.Fprintf(os.Stderr, "[info]   ✓ js_urls.txt (%d URLs)\n", len(js))
			_ = writeLines(filepath.Join(dout, "interesting_files.txt"), intAll)
			fmt.Fprintf(os.Stderr, "[info]   ✓ interesting_files.txt (%d files)\n", len(intAll))

			byExtDir := filepath.Join(dout, "by_ext")
			mustMkdir(byExtDir)
			for ext, lst := range intMap {
				if len(lst) == 0 {
					continue
				}
				_ = writeLines(filepath.Join(byExtDir, "interesting_"+ext+".txt"), lst)
			}

			if len(finds) > 0 {
				_ = writeFindings(filepath.Join(dout, "findings.txt"), finds)
			} else {
				_ = os.WriteFile(filepath.Join(dout, "findings.txt"), []byte("No findings from regex scan on URLs.\n"), 0o644)
			}

			if cfg.ExtractCreds {
				credPath := filepath.Join(dout, "credentials.txt")
				if cfg.CredsOutFile != "" {
					credPath = cfg.CredsOutFile + "_" + sanitize(dom) + "_credentials.txt"
				}
				if len(creds) > 0 {
					_ = writeCredentials(credPath, creds)
				} else {
					_ = os.WriteFile(credPath, []byte("No credentials found.\n"), 0o600)
				}
			}

			aggMu.Lock()
			aggAll[dom] = &agg{all: all, js: js, intAll: intAll, intMap: intMap, creds: creds}
			aggMu.Unlock()
		}(domain)
	}
	wg.Wait()

	// Completion message
	fmt.Fprintf(os.Stderr, "\n[info] ✓ All domains processed successfully!\n")
	fmt.Fprintf(os.Stderr, "[info] Results saved to: %s/\n", cfg.OutDir)
}

// writeFindings writes findings to a text file.
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

// writeCredentials writes extracted credentials to a file with restricted permissions.
func writeCredentials(path string, creds []Credential) error {
	var b strings.Builder
	for _, c := range creds {
		fmt.Fprintf(&b, "%s\t%s\t%s\t(%s)\n", c.URL, c.Email, c.Password, c.Source)
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// sanitize converts a domain name to a filesystem-safe directory name.
func sanitize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "://", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	return s
}
