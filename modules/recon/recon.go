// Package recon implements the subdomain and DNS reconnaissance module.
// Sn1per'ın recon.sh'indeki mantığı (amass, subfinder, crt.sh, zone transfer,
// subdomain takeover tespiti) Go'ya taşır ve genişletir.
package recon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sahin-security/sahin/core/engine"
	"github.com/sahin-security/sahin/internal/config"
	"github.com/sahin-security/sahin/internal/workspace"
)

// Module recon modülü.
type Module struct {
	cfg *config.Config
	ws  *workspace.Workspace
}

func New(cfg *config.Config, ws *workspace.Workspace) *Module {
	return &Module{cfg: cfg, ws: ws}
}

func (m *Module) Name() string        { return "recon" }
func (m *Module) Description() string { return "DNS enum, subdomain keşfi, zone transfer, takeover tespiti" }
func (m *Module) Category() string    { return "recon" }
func (m *Module) Requires() []string  { return []string{"subfinder", "dnsx", "whois"} }

// Run recon pipeline'ını çalıştırır.
// Sn1per sırası: DNS info → takeover check → subfinder → amass → crt.sh → zone transfer
func (m *Module) Run(ctx context.Context, sc *engine.ScanContext) error {
	target := sc.Target
	color.Cyan("\n[RECON] Başlatıldı: %s", target)

	steps := []struct {
		name string
		fn   func(context.Context, string) ([]string, error)
	}{
		{"Whois & DNS", m.runWhois},
		{"Certificate Transparency (crt.sh)", m.runCRTSH},
		{"Subfinder", m.runSubfinder},
		{"Zone Transfer Denemesi", m.runZoneTransfer},
		{"Subdomain Takeover Tespiti", m.runTakeoverCheck},
		{"HTTP Probe (httpx)", m.runHTTPX},
	}

	var allDomains []string

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

		color.Green("  [✓] %s (%v) — %d bulgu", step.name, elapsed, len(results))

		for _, r := range results {
			allDomains = append(allDomains, r)
			sc.Results <- engine.Result{
				Module:   "recon",
				Step:     step.name,
				Output:   r,
				Severity: "info",
			}
		}
	}

	// Tüm domainleri birleştir ve kaydet
	return m.saveDomains(allDomains, "all")
}

// ── Whois & DNS ───────────────────────────────────────────────────────────────
// Sn1per: dig all +short $TARGET → $LOOT_DIR/nmap/dns-$TARGET.txt

func (m *Module) runWhois(ctx context.Context, target string) ([]string, error) {
	var results []string

	// Whois
	out, err := runCmd(ctx, "whois", target)
	if err == nil {
		outFile := m.ws.IPFile("whois")
		_ = os.WriteFile(outFile, []byte(out), 0644)
		results = append(results, fmt.Sprintf("[whois] %s → kaydedildi", target))
	}

	// DNS A kaydı
	addrs, err := net.DefaultResolver.LookupHost(ctx, target)
	if err == nil {
		ipFile := m.ws.IPFile("dns")
		_ = os.WriteFile(ipFile, []byte(strings.Join(addrs, "\n")), 0644)
		for _, addr := range addrs {
			results = append(results, fmt.Sprintf("[dns] %s → %s", target, addr))
		}
	}

	// MX kayıtları
	mxs, err := net.DefaultResolver.LookupMX(ctx, target)
	if err == nil {
		for _, mx := range mxs {
			results = append(results, fmt.Sprintf("[mx] %s → %s (öncelik: %d)", target, mx.Host, mx.Pref))
		}
	}

	return results, nil
}

// ── Certificate Transparency ──────────────────────────────────────────────────
// Sn1per: curl -s https://crt.sh/?q=%25.$TARGET | grep ...

func (m *Module) runCRTSH(ctx context.Context, target string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Sahin-Security-Scanner/1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh ulaşılamadı: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB limit
	if err != nil {
		return nil, err
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh JSON parse hatası: %w", err)
	}

	seen := map[string]bool{}
	var domains []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimPrefix(strings.TrimSpace(name), "*.")
			if name != "" && strings.Contains(name, target) && !seen[name] {
				seen[name] = true
				domains = append(domains, name)
			}
		}
	}

	// Kaydet
	outFile := m.ws.DomainFile("crtsh")
	_ = os.WriteFile(outFile, []byte(strings.Join(domains, "\n")), 0644)

	return domains, nil
}

// ── Subfinder ─────────────────────────────────────────────────────────────────
// Sn1per: subfinder -o $LOOT_DIR/domains/domains-$TARGET-subfinder.txt -d $TARGET -nW -t $THREADS

func (m *Module) runSubfinder(ctx context.Context, target string) ([]string, error) {
	outFile := m.ws.DomainFile("subfinder")

	_, err := exec.LookPath("subfinder")
	if err != nil {
		return nil, fmt.Errorf("subfinder kurulu değil")
	}

	cmd := exec.CommandContext(ctx,
		"subfinder",
		"-d", target,
		"-o", outFile,
		"-silent",
		"-t", "50",
	)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("subfinder hatası: %w", err)
	}

	return readLines(outFile)
}

// ── Zone Transfer ─────────────────────────────────────────────────────────────
// Sn1per'da da var: dig axfr @ns1... $TARGET

func (m *Module) runZoneTransfer(ctx context.Context, target string) ([]string, error) {
	// NS kayıtlarını bul
	nss, err := net.DefaultResolver.LookupNS(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("NS kaydı bulunamadı: %w", err)
	}

	var findings []string
	for _, ns := range nss {
		cmd := exec.CommandContext(ctx, "dig", "axfr", fmt.Sprintf("@%s", ns.Host), target)
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		output := string(out)
		// Zone transfer başarılı mı?
		if strings.Contains(output, "XFR size:") || strings.Contains(output, "Transfer failed") == false {
			findings = append(findings,
				fmt.Sprintf("[ZoneTransfer] BAŞARILI: %s üzerinden %s zone transfer!", ns.Host, target),
			)
			// Kaydet
			outFile := m.ws.DomainFile(fmt.Sprintf("zonetransfer-%s", ns.Host))
			_ = os.WriteFile(outFile, out, 0644)
		}
	}

	if len(findings) == 0 {
		return nil, fmt.Errorf("zone transfer başarısız (normal)")
	}
	return findings, nil
}

// ── Subdomain Takeover Tespiti ────────────────────────────────────────────────
// Sn1per: cat dns-$TARGET.txt | egrep -i "wordpress|heroku|github|..."
// Şahin: config.TakeoverPatterns listesi + TR CDN'leri

func (m *Module) runTakeoverCheck(_ context.Context, target string) ([]string, error) {
	domains, err := m.ws.ReadDomains()
	if err != nil || len(domains) == 0 {
		return nil, fmt.Errorf("domain listesi boş — önce recon çalıştır")
	}

	var vulnerable []string
	for _, domain := range domains {
		// CNAME kontrol
		cnames, err := net.LookupCNAME(domain)
		if err != nil {
			continue
		}
		cnames = strings.ToLower(cnames)

		for _, pattern := range config.TakeoverPatterns {
			if strings.Contains(cnames, strings.ToLower(pattern)) {
				finding := fmt.Sprintf(
					"[TAKEOVER] %s → %s (%s pattern tespit edildi)",
					domain, cnames, pattern,
				)
				vulnerable = append(vulnerable, finding)
				color.Red("  [!!!] %s", finding)
				break
			}
		}
	}

	// Takeover bulgularını kaydet
	if len(vulnerable) > 0 {
		outFile := m.ws.TakeoverFile()
		_ = os.WriteFile(outFile, []byte(strings.Join(vulnerable, "\n")), 0644)
	}

	return vulnerable, nil
}

// ── HTTP Probe ────────────────────────────────────────────────────────────────
// Sn1per'da httpx yoktu — bu Şahin'in eklediği özellik.
// Canlı domain'leri filtreler, status code ve teknoloji bilgisi toplar.

func (m *Module) runHTTPX(ctx context.Context, _ string) ([]string, error) {
	domains, err := m.ws.ReadDomains()
	if err != nil || len(domains) == 0 {
		return nil, fmt.Errorf("domain listesi boş")
	}

	if _, err := exec.LookPath("httpx"); err != nil {
		return nil, fmt.Errorf("httpx kurulu değil")
	}

	// Domain listesini temp dosyaya yaz
	tmpFile := m.ws.DomainFile("all")
	_ = os.WriteFile(tmpFile, []byte(strings.Join(domains, "\n")), 0644)

	outFile := m.ws.DomainFile("httpx-live")

	cmd := exec.CommandContext(ctx,
		"httpx",
		"-l", tmpFile,
		"-o", outFile,
		"-silent",
		"-status-code",
		"-title",
		"-tech-detect",
		"-follow-redirects",
	)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("httpx hatası: %w", err)
	}

	return readLines(outFile)
}

// ── Domain Kaydetme ───────────────────────────────────────────────────────────

func (m *Module) saveDomains(domains []string, source string) error {
	if len(domains) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var unique []string
	for _, d := range domains {
		if !seen[d] {
			seen[d] = true
			unique = append(unique, d)
		}
	}
	outFile := m.ws.DomainFile(source)
	return os.WriteFile(outFile, []byte(strings.Join(unique, "\n")), 0644)
}

// ── Yardımcı ──────────────────────────────────────────────────────────────────

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	return string(out), err
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
