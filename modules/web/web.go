// Package web implements web application reconnaissance.
// nikto, whatweb, header analizi, WAF tespiti, screenshot, JS dosya analizi.
package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sahin-security/sahin/core/engine"
	"github.com/sahin-security/sahin/core/runner"
)

func init() {
	runner.Register("web", func(ctx context.Context, sc *engine.ScanContext) error {
		return (&WebModule{}).Run(ctx, sc)
	})
}

type WebModule struct{}

func (m *WebModule) Run(ctx context.Context, sc *engine.ScanContext) error {
	target := sc.Target
	color.Cyan("\n[WEB] Web uygulama analizi başlatıldı: %s\n", target)

	// Hedef URL'leri oluştur
	urls := buildURLs(target)
	color.White("  [i] Test edilecek URL'ler: %s", strings.Join(urls, ", "))

	webDir := filepath.Join(sc.OutputDir, sc.Workspace, "web")
	_ = os.MkdirAll(webDir, 0755)

	steps := []struct {
		name string
		fn   func(context.Context, string, string, *engine.ScanContext) ([]string, error)
	}{
		{"HTTP Header Analizi", runHeaderAnalysis},
		{"WAF / CDN Tespiti", runWAFDetection},
		{"Teknoloji Tespiti (whatweb)", runWhatWeb},
		{"Nikto Web Taraması", runNikto},
		{"JavaScript Dosya Analizi", runJSAnalysis},
		{"Dizin Keşfi (ffuf)", runDirBrute},
		{"Screenshot (gowitness)", runScreenshot},
	}

	for _, step := range steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Her step için birincil URL'yi kullan
		primaryURL := urls[0]

		color.White("  [→] %s...", step.name)
		start := time.Now()
		results, err := step.fn(ctx, primaryURL, webDir, sc)
		elapsed := time.Since(start).Round(time.Millisecond)

		if err != nil {
			color.Yellow("  [!] %s: %v", step.name, err)
			continue
		}

		color.Green("  [✓] %s (%v) — %d bulgu", step.name, elapsed, len(results))
		for _, r := range results {
			sev := classifyWebSeverity(r)
			sc.Results <- engine.Result{
				Module:   "web",
				Step:     step.name,
				Output:   r,
				Severity: sev,
			}
		}

		// Dosyaya kaydet
		safe := sanitize(step.name)
		outFile := filepath.Join(webDir, safe+".txt")
		_ = os.WriteFile(outFile, []byte(strings.Join(results, "\n")), 0644)
	}

	return nil
}

// ── HTTP Header Analizi ───────────────────────────────────────────────────────
// Güvenlik headerlarını kontrol et, eksik olanları raporla.

func runHeaderAnalysis(ctx context.Context, targetURL, _ string, _ *engine.ScanContext) ([]string, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // redirect takip etme
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Sahin-Scanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bağlantı hatası: %w", err)
	}
	defer resp.Body.Close()

	var results []string

	// ── Sunucu bilgisi ────────────────────────────────────────────────────
	results = append(results, fmt.Sprintf("[header] Status: %d %s", resp.StatusCode, resp.Status))

	if server := resp.Header.Get("Server"); server != "" {
		results = append(results, fmt.Sprintf("[header] Server: %s (medium)", server))
	}
	if xpowered := resp.Header.Get("X-Powered-By"); xpowered != "" {
		results = append(results, fmt.Sprintf("[header] X-Powered-By: %s (medium) — versiyon bilgisi açık", xpowered))
	}

	// ── Güvenlik headerları kontrol ───────────────────────────────────────
	secHeaders := map[string]struct {
		missing string
		sev     string
	}{
		"Strict-Transport-Security": {"HSTS eksik — SSL stripping saldırısı mümkün (medium)", "medium"},
		"X-Frame-Options":           {"X-Frame-Options eksik — Clickjacking riski (medium)", "medium"},
		"X-Content-Type-Options":    {"X-Content-Type-Options eksik — MIME sniffing riski (low)", "low"},
		"Content-Security-Policy":   {"CSP eksik — XSS koruması zayıf (medium)", "medium"},
		"X-XSS-Protection":          {"X-XSS-Protection eksik (low)", "low"},
		"Referrer-Policy":           {"Referrer-Policy eksik (info)", "info"},
		"Permissions-Policy":        {"Permissions-Policy eksik (info)", "info"},
	}

	for header, info := range secHeaders {
		val := resp.Header.Get(header)
		if val == "" {
			results = append(results, fmt.Sprintf("[header-missing] %s", info.missing))
		} else {
			results = append(results, fmt.Sprintf("[header] %s: %s", header, val))
		}
	}

	// ── Cookie güvenliği ──────────────────────────────────────────────────
	for _, cookie := range resp.Cookies() {
		issues := []string{}
		if !cookie.Secure {
			issues = append(issues, "Secure flag eksik")
		}
		if !cookie.HttpOnly {
			issues = append(issues, "HttpOnly flag eksik")
		}
		if cookie.SameSite == http.SameSiteDefaultMode {
			issues = append(issues, "SameSite belirtilmemiş")
		}
		if len(issues) > 0 {
			results = append(results, fmt.Sprintf(
				"[cookie] %s: %s (medium)",
				cookie.Name, strings.Join(issues, ", "),
			))
		}
	}

	// ── Redirect kontrolü ─────────────────────────────────────────────────
	if loc := resp.Header.Get("Location"); loc != "" {
		results = append(results, fmt.Sprintf("[redirect] → %s", loc))
	}

	return results, nil
}

// ── WAF / CDN Tespiti ─────────────────────────────────────────────────────────

func runWAFDetection(ctx context.Context, targetURL, _ string, _ *engine.ScanContext) ([]string, error) {
	// wafw00f varsa kullan
	if path, err := exec.LookPath("wafw00f"); err == nil {
		_ = path
		cmd := exec.CommandContext(ctx, "wafw00f", targetURL, "-o", "-", "-f", "json")
		out, err := cmd.Output()
		if err == nil && len(out) > 0 {
			return []string{fmt.Sprintf("[waf] wafw00f: %s", strings.TrimSpace(string(out)))}, nil
		}
	}

	// wafw00f yoksa manuel header tabanlı tespit
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Kasıtlı kötü istek gönder — WAF tepkisini gözlemle
	badURL := targetURL + "/?q=<script>alert(1)</script>&id=1'+OR+'1'='1"
	req, _ := http.NewRequestWithContext(ctx, "GET", badURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("WAF testi yapılamadı: %w", err)
	}
	defer resp.Body.Close()

	var results []string

	// WAF imzaları — header bazlı
	wafSignatures := map[string]string{
		"cf-ray":             "Cloudflare",
		"x-sucuri-id":        "Sucuri",
		"x-fw-hash":          "Fortinet FortiWeb",
		"x-denied-reason":    "Akamai",
		"x-cdnjs-id":         "CDN.js",
		"x-cache":            "CDN (genel)",
		"x-amz-cf-id":        "AWS CloudFront",
		"x-azure-ref":        "Azure CDN",
		"server: cloudflare": "Cloudflare",
		"server: awselb":     "AWS ELB",
	}

	foundWAF := ""
	for header, wafName := range wafSignatures {
		parts := strings.SplitN(header, ": ", 2)
		var val string
		if len(parts) == 2 {
			val = resp.Header.Get(parts[0])
			if strings.Contains(strings.ToLower(val), strings.ToLower(parts[1])) {
				foundWAF = wafName
				break
			}
		} else {
			if resp.Header.Get(parts[0]) != "" {
				foundWAF = wafName
				break
			}
		}
		_ = val
	}

	if foundWAF != "" {
		results = append(results, fmt.Sprintf("[waf] WAF/CDN tespit edildi: %s (info)", foundWAF))
	} else if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
		results = append(results, fmt.Sprintf("[waf] Olası WAF/güvenlik önlemi (HTTP %d döndü) (info)", resp.StatusCode))
	} else {
		results = append(results, "[waf] WAF tespit edilemedi — doğrudan erişim olabilir (info)")
	}

	// Tüm response headerlarını kaydet
	for key, vals := range resp.Header {
		results = append(results, fmt.Sprintf("[waf-header] %s: %s", key, strings.Join(vals, ", ")))
	}

	return results, nil
}

// ── WhatWeb Teknoloji Tespiti ─────────────────────────────────────────────────

func runWhatWeb(ctx context.Context, targetURL, webDir string, _ *engine.ScanContext) ([]string, error) {
	if _, err := exec.LookPath("whatweb"); err != nil {
		// whatweb yoksa Go ile basit teknoloji tespiti
		return detectTechManually(ctx, targetURL)
	}

	outFile := filepath.Join(webDir, "whatweb.json")
	cmd := exec.CommandContext(ctx, "whatweb",
		"--log-json="+outFile,
		"--quiet",
		"--aggression", "1",
		targetURL,
	)
	out, _ := cmd.CombinedOutput()

	var results []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			results = append(results, fmt.Sprintf("[tech] %s", line))
		}
	}
	if len(results) == 0 {
		results = append(results, "[tech] whatweb çalıştı — JSON çıktı: "+outFile)
	}
	return results, nil
}

// detectTechManually whatweb olmadan basit teknoloji tespiti yapar.
func detectTechManually(ctx context.Context, targetURL string) ([]string, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 500*1024)) // 500KB
	bodyStr := strings.ToLower(string(body))

	var results []string
	techs := map[string]string{
		"wp-content":  "WordPress",
		"joomla":      "Joomla",
		"drupal":      "Drupal",
		"jquery":      "jQuery",
		"react":       "React",
		"vue.js":      "Vue.js",
		"angular":     "Angular",
		"bootstrap":   "Bootstrap",
		"laravel":     "Laravel",
		"django":      "Django",
		"rails":       "Ruby on Rails",
		"aspnetcore":  "ASP.NET Core",
		"__viewstate": "ASP.NET WebForms",
		"jsp":         "Java/JSP",
		"phpsessid":   "PHP",
		"x-generator": "Generator header",
		"shopify":     "Shopify",
		"wix.com":     "Wix",
	}

	for pattern, tech := range techs {
		if strings.Contains(bodyStr, pattern) {
			results = append(results, fmt.Sprintf("[tech] %s tespit edildi (info)", tech))
		}
	}

	// Header tabanlı
	if server := resp.Header.Get("Server"); server != "" {
		results = append(results, fmt.Sprintf("[tech] Server: %s", server))
	}
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		results = append(results, fmt.Sprintf("[tech] X-Powered-By: %s (medium)", powered))
	}

	if len(results) == 0 {
		results = append(results, "[tech] Teknoloji tespit edilemedi")
	}
	return results, nil
}

// ── Nikto ─────────────────────────────────────────────────────────────────────

func runNikto(ctx context.Context, targetURL, webDir string, sc *engine.ScanContext) ([]string, error) {
	if _, err := exec.LookPath("nikto"); err != nil {
		return []string{"[nikto] Kurulu değil — 'apt-get install nikto' ile kur"}, nil
	}

	outFile := filepath.Join(webDir, "nikto.txt")

	args := []string{
		"-h", targetURL,
		"-o", outFile,
		"-Format", "txt",
		"-nointeractive",
		"-timeout", "10",
	}

	if sc.Stealth {
		args = append(args, "-Pause", "2") // stealth modda yavaşla
	}

	// Nikto uzun sürebilir, timeout ekle
	niktoCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(niktoCtx, "nikto", args...)
	out, _ := cmd.CombinedOutput()

	var results []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "+") == false {
			continue
		}
		// Sadece + ile başlayan bulgu satırları
		results = append(results, fmt.Sprintf("[nikto] %s", strings.TrimPrefix(line, "+ ")))
	}

	if len(results) == 0 {
		return []string{fmt.Sprintf("[nikto] Tamamlandı — detay: %s", outFile)}, nil
	}
	return results, nil
}

// ── JavaScript Analizi ────────────────────────────────────────────────────────
// JS dosyalarında API key, token, endpoint, versiyon bilgisi ara.

func runJSAnalysis(ctx context.Context, targetURL, webDir string, _ *engine.ScanContext) ([]string, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	bodyStr := string(body)

	// JS dosyalarını topla
	jsFiles := extractJSFiles(bodyStr, targetURL)

	var results []string
	results = append(results, fmt.Sprintf("[js] %d JS dosyası tespit edildi", len(jsFiles)))

	// Her JS dosyasında hassas pattern ara
	sensitivePatterns := map[string]string{
		"api_key":           "API Key",
		"apikey":            "API Key",
		"api-key":           "API Key",
		"secret_key":        "Secret Key",
		"access_token":      "Access Token",
		"authorization":     "Authorization token",
		"password":          "Hardcoded password",
		"aws_access_key_id": "AWS Access Key",
		"private_key":       "Private Key",
		"s3.amazonaws.com":  "S3 Bucket",
		"mongodb://":        "MongoDB connection string",
		"mysql://":          "MySQL connection string",
		"postgresql://":     "PostgreSQL connection string",
		"redis://":          "Redis connection string",
		"/api/v1":           "API endpoint",
		"/api/v2":           "API endpoint",
		"localhost":         "Localhost reference",
		"192.168.":          "Internal IP",
		"10.0.":             "Internal IP",
		"172.16.":           "Internal IP",
	}

	for _, jsURL := range jsFiles {
		jsReq, _ := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
		jsResp, err := client.Do(jsReq)
		if err != nil {
			continue
		}
		jsBody, _ := io.ReadAll(io.LimitReader(jsResp.Body, 500*1024))
		jsResp.Body.Close()
		jsStr := strings.ToLower(string(jsBody))

		for pattern, label := range sensitivePatterns {
			if strings.Contains(jsStr, pattern) {
				sev := "medium"
				if strings.Contains(label, "Key") || strings.Contains(label, "token") ||
					strings.Contains(label, "password") || strings.Contains(label, "connection") {
					sev = "high"
				}
				results = append(results, fmt.Sprintf(
					"[js-secret] %s: '%s' pattern tespit edildi → %s (%s)",
					jsURL, pattern, label, sev,
				))
			}
		}
	}

	// Sonuçları dosyaya kaydet
	_ = os.WriteFile(filepath.Join(webDir, "js-files.txt"),
		[]byte(strings.Join(jsFiles, "\n")), 0644)

	return results, nil
}

// extractJSFiles HTML'den JS dosya URL'lerini çıkarır.
func extractJSFiles(html, baseURL string) []string {
	var jsFiles []string
	seen := map[string]bool{}

	parts := strings.Split(html, "src=")
	for _, part := range parts[1:] {
		// src="..." veya src='...' pattern
		var end int
		var jsURL string
		if strings.HasPrefix(part, `"`) {
			end = strings.Index(part[1:], `"`)
			if end > 0 {
				jsURL = part[1 : end+1]
			}
		} else if strings.HasPrefix(part, `'`) {
			end = strings.Index(part[1:], `'`)
			if end > 0 {
				jsURL = part[1 : end+1]
			}
		}

		if !strings.HasSuffix(jsURL, ".js") {
			continue
		}

		if strings.HasPrefix(jsURL, "//") {
			jsURL = "https:" + jsURL
		} else if strings.HasPrefix(jsURL, "/") {
			// Relative URL → absolute
			base := strings.TrimRight(baseURL, "/")
			jsURL = base + jsURL
		} else if !strings.HasPrefix(jsURL, "http") {
			continue
		}

		if !seen[jsURL] {
			seen[jsURL] = true
			jsFiles = append(jsFiles, jsURL)
		}
	}
	return jsFiles
}

// ── Dir Brute Force (ffuf) ────────────────────────────────────────────────────

func runDirBrute(ctx context.Context, targetURL, webDir string, sc *engine.ScanContext) ([]string, error) {
	if _, err := exec.LookPath("ffuf"); err != nil {
		return []string{"[ffuf] Kurulu değil — 'go install github.com/ffuf/ffuf@latest' ile kur"}, nil
	}

	// Wordlist kontrol
	wordlists := []string{
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
	}

	wordlist := ""
	for _, wl := range wordlists {
		if _, err := os.Stat(wl); err == nil {
			wordlist = wl
			break
		}
	}

	if wordlist == "" {
		return []string{"[ffuf] Wordlist bulunamadı — /usr/share/wordlists/dirb/common.txt gerekli"}, nil
	}

	outFile := filepath.Join(webDir, "ffuf.json")
	args := []string{
		"-u", targetURL + "/FUZZ",
		"-w", wordlist,
		"-o", outFile,
		"-of", "json",
		"-mc", "200,201,204,301,302,307,401,403",
		"-t", "50",
		"-timeout", "10",
		"-s", // silent
	}

	if sc.Stealth {
		// Stealth modda yavaşla
		args = append(args, "-rate", "10")
	}

	ffufCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ffufCtx, "ffuf", args...)
	out, _ := cmd.CombinedOutput()

	var results []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "[") {
			results = append(results, fmt.Sprintf("[dir] %s", line))
		}
	}

	if len(results) == 0 {
		results = append(results, fmt.Sprintf("[dir] ffuf tamamlandı — JSON: %s", outFile))
	}
	return results, nil
}

// ── Screenshot (gowitness) ────────────────────────────────────────────────────

func runScreenshot(ctx context.Context, targetURL, webDir string, _ *engine.ScanContext) ([]string, error) {
	if _, err := exec.LookPath("gowitness"); err != nil {
		// gowitness yoksa chromium/chrome ile dene
		return []string{"[screenshot] gowitness kurulu değil — 'go install github.com/sensepost/gowitness@latest'"}, nil
	}

	ssDir := filepath.Join(webDir, "screenshots")
	_ = os.MkdirAll(ssDir, 0755)

	cmd := exec.CommandContext(ctx, "gowitness",
		"single",
		"--url", targetURL,
		"--screenshot-path", ssDir,
		"--timeout", "15",
		"--disable-db",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return []string{fmt.Sprintf("[screenshot] gowitness hatası: %v", err)}, nil
	}

	return []string{fmt.Sprintf("[screenshot] Kaydedildi: %s — %s", ssDir, strings.TrimSpace(string(out)))}, nil
}

// ── Yardımcı ──────────────────────────────────────────────────────────────────

func buildURLs(target string) []string {
	if strings.HasPrefix(target, "http") {
		return []string{target}
	}
	return []string{
		"https://" + target,
		"http://" + target,
	}
}

func sanitize(s string) string {
	r := strings.NewReplacer(" ", "-", "/", "-", "(", "", ")", "", ".", "-")
	return strings.ToLower(r.Replace(s))
}

func classifyWebSeverity(result string) string {
	lower := strings.ToLower(result)
	switch {
	case strings.Contains(lower, "critical") ||
		strings.Contains(lower, "sql injection") ||
		strings.Contains(lower, "rce"):
		return "critical"
	case strings.Contains(lower, "high") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "api key") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "private key") ||
		strings.Contains(lower, "connection string"):
		return "high"
	case strings.Contains(lower, "medium") ||
		strings.Contains(lower, "hsts eksik") ||
		strings.Contains(lower, "clickjacking") ||
		strings.Contains(lower, "csp eksik") ||
		strings.Contains(lower, "x-powered-by") ||
		strings.Contains(lower, "cookie"):
		return "medium"
	default:
		return "info"
	}
}
