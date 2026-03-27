// Package osint implements OSINT reconnaissance.
// theHarvester, e-posta toplama, metadata, GitHub dork, breach kontrolü.
package osint

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
	runner.Register("osint", func(ctx context.Context, sc *engine.ScanContext) error {
		return (&OSINTModule{}).Run(ctx, sc)
	})
}

type OSINTModule struct{}

func (m *OSINTModule) Run(ctx context.Context, sc *engine.ScanContext) error {
	target := sc.Target
	color.Cyan("\n[OSINT] Başlatıldı: %s\n", target)

	osintDir := filepath.Join(sc.OutputDir, sc.Workspace, "osint")
	_ = os.MkdirAll(osintDir, 0755)

	steps := []struct {
		name string
		fn   func(context.Context, string, string, *engine.ScanContext) ([]string, error)
	}{
		{"theHarvester (e-posta & subdomain)", runTheHarvester},
		{"E-posta Format Tahmini", runEmailFormat},
		{"GitHub Dork Taraması", runGitHubDork},
		{"Google Dork Linkleri", runGoogleDorks},
		{"Shodan Sorgusu", runShodan},
		{"LinkedIn Çalışan Tespiti", runLinkedIn},
		{"Wayback Machine (geçmiş URL'ler)", runWayback},
		{"Breached Credential Kontrolü", runBreachCheck},
	}

	for _, step := range steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		color.White("  [→] %s...", step.name)
		start := time.Now()
		results, err := step.fn(ctx, target, osintDir, sc)
		elapsed := time.Since(start).Round(time.Millisecond)

		if err != nil {
			color.Yellow("  [!] %s: %v", step.name, err)
			continue
		}

		color.Green("  [✓] %s (%v) — %d bulgu", step.name, elapsed, len(results))
		for _, r := range results {
			sev := classifyOSINTSeverity(r)
			sc.Results <- engine.Result{
				Module:   "osint",
				Step:     step.name,
				Output:   r,
				Severity: sev,
			}
		}

		// Dosyaya kaydet
		safe := sanitize(step.name)
		_ = os.WriteFile(
			filepath.Join(osintDir, safe+".txt"),
			[]byte(strings.Join(results, "\n")),
			0644,
		)
	}

	return nil
}

// ── theHarvester ──────────────────────────────────────────────────────────────

func runTheHarvester(ctx context.Context, target, osintDir string, _ *engine.ScanContext) ([]string, error) {
	harvesterNames := []string{"theHarvester", "theharvester"}
	harvesterBin := ""
	for _, name := range harvesterNames {
		if _, err := exec.LookPath(name); err == nil {
			harvesterBin = name
			break
		}
	}

	if harvesterBin == "" {
		return []string{"[harvester] Kurulu değil — 'apt-get install theharvester' ile kur"}, nil
	}

	outFile := filepath.Join(osintDir, "harvester.xml")
	cmd := exec.CommandContext(ctx,
		harvesterBin,
		"-d", target,
		"-b", "bing,duckduckgo,crtsh,otx,threatminer",
		"-f", outFile,
		"-l", "200",
	)

	harvestCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	_ = harvestCtx

	out, _ := cmd.CombinedOutput()

	var results []string
	var inEmails, inHosts bool
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Emails found") {
			inEmails = true
			inHosts = false
			continue
		}
		if strings.Contains(line, "Hosts found") {
			inHosts = true
			inEmails = false
			continue
		}
		if strings.HasPrefix(line, "---") || line == "" {
			continue
		}
		if inEmails && strings.Contains(line, "@") {
			results = append(results, fmt.Sprintf("[email] %s", line))
		}
		if inHosts && strings.Contains(line, ".") {
			results = append(results, fmt.Sprintf("[host] %s", line))
		}
	}

	if len(results) == 0 {
		results = append(results, fmt.Sprintf("[harvester] Tamamlandı — detay: %s", outFile))
	}
	return results, nil
}

// ── E-posta Format Tahmini ────────────────────────────────────────────────────
// Kurumun e-posta formatını tahmin et (ad.soyad@, a.soyad@, asoyad@ vb.)

func runEmailFormat(ctx context.Context, target, _ string, _ *engine.ScanContext) ([]string, error) {
	// email-format.com API
	url := fmt.Sprintf("https://api.email-format.com/v1/search/?domain=%s&apikey=none", target)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Sahin-Scanner/1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return emailFormatGuess(target), nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	var result struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.Format == "" {
		return emailFormatGuess(target), nil
	}

	return []string{
		fmt.Sprintf("[email-format] %s kurumunun e-posta formatı: %s (info)", target, result.Format),
		fmt.Sprintf("[email-format] Örnek: %s@%s", formatExample(result.Format), target),
	}, nil
}

func emailFormatGuess(target string) []string {
	return []string{
		fmt.Sprintf("[email-format] Tahmin — yaygın formatlar: ad.soyad@%s, asoyad@%s, a.soyad@%s", target, target, target),
	}
}

func formatExample(format string) string {
	replacer := strings.NewReplacer(
		"{first}", "ahmet",
		"{last}", "yilmaz",
		"{f}", "a",
		"{l}", "y",
	)
	return replacer.Replace(format)
}

// ── GitHub Dork ───────────────────────────────────────────────────────────────
// GitHub'da hedef domain ile ilgili credential/secret sızdıran repo ara.

func runGitHubDork(ctx context.Context, target, _ string, sc *engine.ScanContext) ([]string, error) {
	// GitHub API token varsa kullan
	token := sc.Params["github_token"]

	dorks := []struct {
		query string
		label string
	}{
		{fmt.Sprintf("%s password", target), "password"},
		{fmt.Sprintf("%s secret", target), "secret"},
		{fmt.Sprintf("%s api_key", target), "api_key"},
		{fmt.Sprintf("%s token", target), "token"},
		{fmt.Sprintf("%s smtp", target), "SMTP credentials"},
		{fmt.Sprintf("%s database connection", target), "DB connection"},
		{fmt.Sprintf("site:%s", target), "site reference"},
	}

	var results []string

	// GitHub Search API
	client := &http.Client{Timeout: 10 * time.Second}

	for _, dork := range dorks {
		apiURL := fmt.Sprintf(
			"https://api.github.com/search/code?q=%s&per_page=5",
			strings.ReplaceAll(dork.query, " ", "+"),
		)

		req, _ := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("User-Agent", "Sahin-Scanner/1.0")
		if token != "" {
			req.Header.Set("Authorization", "token "+token)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		var searchResult struct {
			TotalCount int `json:"total_count"`
			Items      []struct {
				Name       string `json:"name"`
				HTMLURL    string `json:"html_url"`
				Repository struct {
					FullName string `json:"full_name"`
				} `json:"repository"`
			} `json:"items"`
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
		resp.Body.Close()

		if err := json.Unmarshal(body, &searchResult); err != nil {
			continue
		}

		if searchResult.TotalCount > 0 {
			results = append(results, fmt.Sprintf(
				"[github-dork] '%s' → %d sonuç (high)",
				dork.query, searchResult.TotalCount,
			))
			for _, item := range searchResult.Items {
				results = append(results, fmt.Sprintf(
					"[github-leak] %s / %s → %s",
					item.Repository.FullName, item.Name, item.HTMLURL,
				))
			}
		}

		// Rate limit aşmamak için bekle
		time.Sleep(500 * time.Millisecond)
	}

	if len(results) == 0 {
		results = append(results, fmt.Sprintf("[github-dork] %s için GitHub'da sızdırılmış bilgi bulunamadı (info)", target))
	}

	// Manuel dork URL'leri de ekle (tarayıcıda açılabilir)
	results = append(results, fmt.Sprintf(
		"[github-manual] Manuel: https://github.com/search?q=%s+password&type=code",
		strings.ReplaceAll(target, ".", "%2E"),
	))

	return results, nil
}

// ── Google Dork Linkleri ──────────────────────────────────────────────────────
// Hazır Google dork URL'leri üret (manuel araştırma için)

func runGoogleDorks(_ context.Context, target, _ string, _ *engine.ScanContext) ([]string, error) {
	dorks := []struct {
		dork  string
		label string
	}{
		{fmt.Sprintf("site:%s filetype:pdf", target), "PDF dosyaları"},
		{fmt.Sprintf("site:%s filetype:doc OR filetype:docx", target), "Word belgeler"},
		{fmt.Sprintf("site:%s filetype:xls OR filetype:xlsx", target), "Excel dosyaları"},
		{fmt.Sprintf("site:%s filetype:sql", target), "SQL dump dosyaları"},
		{fmt.Sprintf("site:%s inurl:admin", target), "Admin panelleri"},
		{fmt.Sprintf("site:%s inurl:login", target), "Giriş sayfaları"},
		{fmt.Sprintf("site:%s inurl:upload", target), "Upload sayfaları"},
		{fmt.Sprintf("site:%s intext:password", target), "Şifre içeren sayfalar"},
		{fmt.Sprintf("site:%s intext:\"internal use only\"", target), "Dahili belgeler"},
		{fmt.Sprintf("\"%s\" site:pastebin.com", target), "Pastebin sızıntıları"},
		{fmt.Sprintf("\"%s\" site:trello.com", target), "Trello board sızıntıları"},
	}

	var results []string
	for _, d := range dorks {
		encoded := strings.ReplaceAll(d.dork, " ", "+")
		googleURL := fmt.Sprintf("https://www.google.com/search?q=%s", encoded)
		results = append(results, fmt.Sprintf(
			"[google-dork] %s → %s",
			d.label, googleURL,
		))
	}

	return results, nil
}

// ── Shodan Sorgusu ────────────────────────────────────────────────────────────

func runShodan(ctx context.Context, target, _ string, sc *engine.ScanContext) ([]string, error) {
	apiKey := sc.Params["shodan_api_key"]
	if apiKey == "" {
		return []string{fmt.Sprintf(
			"[shodan] API key yok — manuel: https://www.shodan.io/search?query=hostname:%s",
			target,
		)}, nil
	}

	url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=hostname:%s", apiKey, target)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Shodan API hatası: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Total   int `json:"total"`
		Matches []struct {
			IP        string   `json:"ip_str"`
			Ports     []int    `json:"ports"`
			Hostnames []string `json:"hostnames"`
			Org       string   `json:"org"`
			OS        string   `json:"os"`
		} `json:"matches"`
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 500*1024))
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var results []string
	results = append(results, fmt.Sprintf("[shodan] Toplam Shodan kaydı: %d", result.Total))
	for _, m := range result.Matches {
		results = append(results, fmt.Sprintf(
			"[shodan] %s (%s) — portlar: %v",
			m.IP, m.Org, m.Ports,
		))
		if m.OS != "" {
			results = append(results, fmt.Sprintf("[shodan] OS: %s", m.OS))
		}
	}
	return results, nil
}

// ── LinkedIn Çalışan Tespiti ──────────────────────────────────────────────────

func runLinkedIn(_ context.Context, target, _ string, _ *engine.ScanContext) ([]string, error) {
	// LinkedIn'e doğrudan API erişimi yok,
	// Google dork ile LinkedIn profil linkleri üret
	domain := strings.TrimPrefix(target, "www.")
	orgName := strings.Split(domain, ".")[0]

	results := []string{
		fmt.Sprintf("[linkedin] Çalışan araması: https://www.linkedin.com/search/results/people/?keywords=%s", orgName),
		fmt.Sprintf("[linkedin] Google dork: site:linkedin.com/in \"%s\"", orgName),
		fmt.Sprintf("[linkedin] Şirket sayfası: https://www.linkedin.com/company/%s", orgName),
	}
	return results, nil
}

// ── Wayback Machine ───────────────────────────────────────────────────────────

func runWayback(ctx context.Context, target, osintDir string, _ *engine.ScanContext) ([]string, error) {
	// Wayback Machine CDX API
	url := fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original,statuscode,timestamp&limit=100&collapse=urlkey",
		target,
	)

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Wayback Machine erişilemedi: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))

	var entries [][]string
	if err := json.Unmarshal(body, &entries); err != nil || len(entries) < 2 {
		return []string{fmt.Sprintf("[wayback] %s için arşiv bulunamadı", target)}, nil
	}

	// İlk satır header
	var results []string
	var allURLs []string
	interesting := []string{".pdf", ".sql", ".bak", ".zip", ".tar", ".env",
		"admin", "login", "upload", "api", "config", "backup"}

	for _, entry := range entries[1:] { // header'ı atla
		if len(entry) < 2 {
			continue
		}
		origURL := entry[0]
		allURLs = append(allURLs, origURL)

		lower := strings.ToLower(origURL)
		for _, pattern := range interesting {
			if strings.Contains(lower, pattern) {
				results = append(results, fmt.Sprintf("[wayback] %s", origURL))
				break
			}
		}
	}

	// Tüm URL'leri kaydet
	_ = os.WriteFile(
		filepath.Join(osintDir, "wayback-urls.txt"),
		[]byte(strings.Join(allURLs, "\n")),
		0644,
	)

	if len(results) == 0 {
		results = append(results, fmt.Sprintf("[wayback] %d URL bulundu — kaydet: wayback-urls.txt", len(allURLs)))
	} else {
		results = append(results, fmt.Sprintf("[wayback] %d ilginç URL, %d toplam", len(results), len(allURLs)))
	}

	return results, nil
}

// ── Breach Credential Kontrolü ────────────────────────────────────────────────

func runBreachCheck(ctx context.Context, target, _ string, _ *engine.ScanContext) ([]string, error) {
	// HIBP domain search (public API)
	url := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breacheddomain/%s", target)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Sahin-Scanner/1.0 (security research)")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{fmt.Sprintf("[breach] HIBP erişilemedi — manuel: https://haveibeenpwned.com/DomainSearch")}, nil
	}
	defer resp.Body.Close()

	var results []string

	switch resp.StatusCode {
	case 200:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
		var breaches []struct {
			Name        string   `json:"Name"`
			BreachDate  string   `json:"BreachDate"`
			PwnCount    int      `json:"PwnCount"`
			DataClasses []string `json:"DataClasses"`
		}
		if err := json.Unmarshal(body, &breaches); err == nil {
			for _, b := range breaches {
				results = append(results, fmt.Sprintf(
					"[breach] %s ihlali: %s tarihinde %d hesap sızdı — %s (high)",
					b.Name, b.BreachDate, b.PwnCount, strings.Join(b.DataClasses, ", "),
				))
			}
		}
	case 404:
		results = append(results, fmt.Sprintf("[breach] %s HIBP'de kayıtlı ihlal bulunamadı (info)", target))
	default:
		results = append(results, fmt.Sprintf("[breach] HIBP API yanıtı: HTTP %d — API key gerekebilir", resp.StatusCode))
	}

	// DeHashed manual link
	results = append(results, fmt.Sprintf("[breach] Manuel kontrol: https://dehashed.com/search?query=%s", target))
	results = append(results, fmt.Sprintf("[breach] Manuel kontrol: https://intelx.io/?s=%s", target))

	return results, nil
}

// ── Yardımcı ──────────────────────────────────────────────────────────────────

func sanitize(s string) string {
	r := strings.NewReplacer(" ", "-", "/", "-", "(", "", ")", "", "'", "", "&", "ve")
	return strings.ToLower(r.Replace(s))
}

func classifyOSINTSeverity(result string) string {
	lower := strings.ToLower(result)
	switch {
	case strings.Contains(lower, "critical") ||
		strings.Contains(lower, "breach") ||
		strings.Contains(lower, "ihlali") ||
		strings.Contains(lower, "sızdı"):
		return "high"
	case strings.Contains(lower, "high") ||
		strings.Contains(lower, "leak") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "github-leak"):
		return "high"
	case strings.Contains(lower, "medium") ||
		strings.Contains(lower, "dork"):
		return "medium"
	default:
		return "info"
	}
}
