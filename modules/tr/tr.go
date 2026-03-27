package tr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sahin-security/sahin/core/engine"
	"github.com/sahin-security/sahin/core/runner"
	"github.com/sahin-security/sahin/internal/report"
)

func init() {
	runner.Register("tr", func(ctx context.Context, sc *engine.ScanContext) error {
		return (&TRModule{}).Run(ctx, sc)
	})
}

type TRModule struct{}

func (m *TRModule) Run(ctx context.Context, sc *engine.ScanContext) error {
	target := sc.Target
	color.Cyan("\n[TR] Türkiye odaklı recon başlatıldı: %s\n", target)

	// Rapor başlat
	rep := report.New(target, sc.Workspace)

	steps := []struct {
		name string
		fn   func(context.Context, string) ([]string, error)
	}{
		{"Whois sorgusu", runWhois},
		{"DNS kayıtları (A/MX/NS/TXT)", runDNS},
		{"Certificate Transparency (crt.sh)", runCRTSH},
		{"Subdomain Takeover kontrolü", runTakeoverCheck},
		{".gov.tr / .edu.tr subdomain tespiti", runGovTREnum},
		{"USOM zararlı liste kontrolü", runUSOMCheck},
	}

	// Tüm adımları çalıştır
	for _, step := range steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		color.White("  [→] %s...", step.name)
		start := time.Now()
		results, err := step.fn(ctx, target)
		elapsed := time.Since(start).Round(time.Millisecond)

		if err != nil {
			color.Yellow("  [!] %s: %v", step.name, err)
			continue
		}

		color.Green("  [✓] %s (%v) — %d sonuç", step.name, elapsed, len(results))

		for _, r := range results {
			sev := classifySeverity(r)
			rep.Add("tr", step.name, r, sev)
			sc.Results <- engine.Result{
				Module:   "tr",
				Step:     step.name,
				Output:   r,
				Severity: sev,
			}
		}

		// Her adımın çıktısını dosyaya yaz
		saveStepOutput(sc, step.name, results)

		// Raporu kaydet (HTML + PDF + DOCX)
		reportsDir := filepath.Join(sc.OutputDir, sc.Workspace, "reports")
		scriptDir := "scripts" // proje kök dizini
		result := rep.SaveAll(reportsDir, scriptDir)

		if result.PDF != "" {
			color.Green("[*] PDF Rapor  : %s", result.PDF)
		}
		if result.DOCX != "" {
			color.Green("[*] DOCX Rapor : %s", result.DOCX)
		}
	}

	// Raporu bitir ve HTML olarak kaydet
	rep.Finish()
	reportPath := filepath.Join(sc.OutputDir, sc.Workspace, "reports",
		fmt.Sprintf("sahin-%s-%s.html", target, time.Now().Format("20060102-1504")))

	if err := rep.SaveHTML(reportPath); err != nil {
		color.Yellow("  [!] Rapor kaydedilemedi: %v", err)
	} else {
		color.Cyan("\n[*] HTML Rapor: %s", reportPath)
	}

	return nil
}

// saveStepOutput adım çıktısını tr/ dizinine yazar.
func saveStepOutput(sc *engine.ScanContext, stepName string, results []string) {
	safe := strings.ReplaceAll(strings.ToLower(stepName), " ", "-")
	safe = strings.ReplaceAll(safe, "/", "-")
	safe = strings.ReplaceAll(safe, "(", "")
	safe = strings.ReplaceAll(safe, ")", "")
	outFile := filepath.Join(sc.OutputDir, sc.Workspace, "tr", safe+".txt")
	_ = os.WriteFile(outFile, []byte(strings.Join(results, "\n")), 0644)
}

// ── Whois ─────────────────────────────────────────────────────────────────────

func runWhois(ctx context.Context, target string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "whois", target)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("whois çalıştırılamadı: %w", err)
	}
	var results []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		for _, kw := range []string{"registrant", "registrar", "created", "expires",
			"updated", "name server", "nserver", "organization", "org:", "e-mail", "status"} {
			if strings.Contains(lower, kw) {
				results = append(results, "[whois] "+line)
				break
			}
		}
	}
	if len(results) == 0 {
		results = append(results, "[whois] Sorgu tamamlandı")
	}
	return results, nil
}

// ── DNS ───────────────────────────────────────────────────────────────────────

func runDNS(ctx context.Context, target string) ([]string, error) {
	var results []string

	addrs, err := net.DefaultResolver.LookupHost(ctx, target)
	if err == nil {
		for _, addr := range addrs {
			results = append(results, fmt.Sprintf("[dns:A] %s → %s", target, addr))
		}
	}
	mxs, _ := net.DefaultResolver.LookupMX(ctx, target)
	for _, mx := range mxs {
		results = append(results, fmt.Sprintf("[dns:MX] %s → %s (öncelik: %d)", target, mx.Host, mx.Pref))
	}
	nss, _ := net.DefaultResolver.LookupNS(ctx, target)
	for _, ns := range nss {
		results = append(results, fmt.Sprintf("[dns:NS] %s → %s", target, ns.Host))
	}
	txts, _ := net.DefaultResolver.LookupTXT(ctx, target)
	for _, txt := range txts {
		results = append(results, fmt.Sprintf("[dns:TXT] %s", txt))
	}
	dmarcTxts, _ := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+target)
	if len(dmarcTxts) == 0 {
		results = append(results, "[dns:DMARC] DMARC kaydı YOK — e-posta spoofing mümkün olabilir (medium)")
	} else {
		for _, d := range dmarcTxts {
			results = append(results, fmt.Sprintf("[dns:DMARC] %s", d))
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("DNS çözümlenemedi: %s", target)
	}
	return results, nil
}

// ── crt.sh ────────────────────────────────────────────────────────────────────

func runCRTSH(ctx context.Context, target string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Sahin-Security/1.0")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh ulaşılamadı: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parse hatası: %w", err)
	}
	seen := map[string]bool{}
	var results []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimPrefix(strings.TrimSpace(name), "*.")
			if name != "" && strings.Contains(name, target) && !seen[name] {
				seen[name] = true
				results = append(results, fmt.Sprintf("[crt.sh] %s", name))
			}
		}
	}
	return results, nil
}

// ── Takeover ──────────────────────────────────────────────────────────────────

var takeoverPatterns = []string{
	"amazonaws.com", "cloudfront.net", "elasticbeanstalk.com",
	"github.io", "heroku.com", "wordpress.com", "wpengine.com",
	"shopify.com", "fastly.net", "ghost.io",
	"azurewebsites.net", "cloudapp.net", "trafficmanager.net",
	"superonline.net", "turktelekom.com.tr",
}

func runTakeoverCheck(ctx context.Context, target string) ([]string, error) {
	crtResults, err := runCRTSH(ctx, target)
	if err != nil || len(crtResults) == 0 {
		return nil, fmt.Errorf("subdomain listesi boş")
	}
	var results []string
	checked := 0
	for _, line := range crtResults {
		subdomain := strings.TrimPrefix(line, "[crt.sh] ")
		if subdomain == target {
			continue
		}
		cname, err := net.LookupCNAME(subdomain)
		if err != nil {
			continue
		}
		cname = strings.ToLower(strings.TrimSuffix(cname, "."))
		checked++
		found := false
		for _, pat := range takeoverPatterns {
			if strings.Contains(cname, pat) {
				msg := fmt.Sprintf("[TAKEOVER] %s → %s (%s pattern) — YÜKSEK RİSK (high)", subdomain, cname, pat)
				results = append(results, msg)
				color.Red("  [!!!] %s", msg)
				found = true
				break
			}
		}
		_ = found
		if checked >= 30 {
			break
		}
	}
	if len(results) == 0 {
		results = append(results, fmt.Sprintf("[takeover] %d subdomain kontrol edildi — tespit edilmedi", checked))
	}
	return results, nil
}

// ── .gov.tr enum ──────────────────────────────────────────────────────────────

func runGovTREnum(_ context.Context, target string) ([]string, error) {
	isGov := strings.HasSuffix(target, ".gov.tr") ||
		strings.HasSuffix(target, ".edu.tr") ||
		strings.HasSuffix(target, ".bel.tr") ||
		strings.HasSuffix(target, ".k12.tr")
	if !isGov {
		return []string{fmt.Sprintf("[gov.tr] %s TR kamu TLD'si değil — atlandı", target)}, nil
	}
	govSubs := []string{
		"www", "mail", "webmail", "posta", "vpn", "remote",
		"portal", "sso", "login", "auth", "api",
		"edevlet", "vatandas", "basvuru", "bilgi",
		"otomasyon", "intranet", "test", "dev",
		"sgk", "vergi", "ihale", "ftp", "exchange",
	}
	var results []string
	for _, sub := range govSubs {
		fqdn := fmt.Sprintf("%s.%s", sub, target)
		addrs, err := net.LookupHost(fqdn)
		if err == nil && len(addrs) > 0 {
			results = append(results, fmt.Sprintf("[gov.tr] AÇIK: %s → %s", fqdn, strings.Join(addrs, ", ")))
		}
	}
	if len(results) == 0 {
		return []string{fmt.Sprintf("[gov.tr] %d subdomain denendi — bulunamadı", len(govSubs))}, nil
	}
	return results, nil
}

// ── USOM ──────────────────────────────────────────────────────────────────────

func runUSOMCheck(ctx context.Context, target string) ([]string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.usom.gov.tr/url-list.txt", nil)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{"[usom] USOM listesine erişilemedi"}, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	lines := strings.Split(string(body), "\n")
	var matches []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, target) {
			matches = append(matches, fmt.Sprintf("[usom] ZARARLIL LİSTESİNDE: %s (critical)", line))
		}
	}
	if len(matches) == 0 {
		return []string{fmt.Sprintf("[usom] %s USOM zararlı listesinde bulunamadı (%d kayıt tarandı)", target, len(lines))}, nil
	}
	return matches, nil
}

// ── Severity ──────────────────────────────────────────────────────────────────

func classifySeverity(result string) string {
	lower := strings.ToLower(result)
	switch {
	case strings.Contains(lower, "critical") || strings.Contains(lower, "zararlı"):
		return "critical"
	case strings.Contains(lower, "high") || strings.Contains(lower, "takeover") || strings.Contains(lower, "yüksek"):
		return "high"
	case strings.Contains(lower, "medium") || strings.Contains(lower, "dmarc") || strings.Contains(lower, "spoofing"):
		return "medium"
	default:
		return "info"
	}
}
