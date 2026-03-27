// Package tools manages external binary dependencies and their installation.
// Sn1per'ın install.sh'indeki tool listesini Go'ya taşır.
package tools

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/fatih/color"
)

// Tool bir harici binary'nin tanımı.
type Tool struct {
	Name        string
	Binary      string // çalıştırılabilir dosya adı
	InstallCmd  string // go install / apt / pip
	Category    string // recon | portscan | web | osint | vuln | tr
	Required    bool   // false ise opsiyonel
}

// Registry Sn1per'ın go_tools + apt_packages listesinden türetildi.
// ProjectDiscovery araçları ağırlıklı, Şahin'de TR araçları da var.
var Registry = []Tool{
	// ── Recon ─────────────────────────────────────────────────────────
	{
		Name:       "subfinder",
		Binary:     "subfinder",
		InstallCmd: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		Category:   "recon",
		Required:   true,
	},
	{
		Name:       "amass",
		Binary:     "amass",
		InstallCmd: "go install -v github.com/OWASP/Amass/v3/...@master",
		Category:   "recon",
		Required:   false,
	},
	{
		Name:       "puredns",
		Binary:     "puredns",
		InstallCmd: "go install -v github.com/d3mondev/puredns/v2@latest",
		Category:   "recon",
		Required:   false,
	},
	{
		Name:       "dnsx",
		Binary:     "dnsx",
		InstallCmd: "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		Category:   "recon",
		Required:   true,
	},
	{
		Name:       "asnip",
		Binary:     "asnip",
		InstallCmd: "go install -v github.com/harleo/asnip@latest",
		Category:   "recon",
		Required:   false,
	},
	// ── Port Scan ─────────────────────────────────────────────────────
	{
		Name:       "nmap",
		Binary:     "nmap",
		InstallCmd: "apt-get install -y nmap",
		Category:   "portscan",
		Required:   true,
	},
	{
		Name:       "masscan",
		Binary:     "masscan",
		InstallCmd: "apt-get install -y masscan",
		Category:   "portscan",
		Required:   false,
	},
	// ── Web ───────────────────────────────────────────────────────────
	{
		Name:       "httpx",
		Binary:     "httpx",
		InstallCmd: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
		Category:   "web",
		Required:   true,
	},
	{
		Name:       "ffuf",
		Binary:     "ffuf",
		InstallCmd: "go install -v github.com/ffuf/ffuf@latest",
		Category:   "web",
		Required:   true,
	},
	{
		Name:       "nikto",
		Binary:     "nikto",
		InstallCmd: "apt-get install -y nikto",
		Category:   "web",
		Required:   false,
	},
	{
		Name:       "wafw00f",
		Binary:     "wafw00f",
		InstallCmd: "pip3 install wafw00f",
		Category:   "web",
		Required:   false,
	},
	{
		Name:       "gowitness",
		Binary:     "gowitness",
		InstallCmd: "go install -v github.com/sensepost/gowitness@latest",
		Category:   "web",
		Required:   false,
	},
	// ── OSINT ─────────────────────────────────────────────────────────
	{
		Name:       "theHarvester",
		Binary:     "theHarvester",
		InstallCmd: "apt-get install -y theharvester",
		Category:   "osint",
		Required:   false,
	},
	{
		Name:       "gau",
		Binary:     "gau",
		InstallCmd: "go install -v github.com/lc/gau@latest",
		Category:   "osint",
		Required:   false,
	},
	{
		Name:       "github-endpoints",
		Binary:     "github-endpoints",
		InstallCmd: "go install -v github.com/gwen001/github-endpoints@latest",
		Category:   "osint",
		Required:   false,
	},
	// ── Vuln ──────────────────────────────────────────────────────────
	{
		Name:       "nuclei",
		Binary:     "nuclei",
		InstallCmd: "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
		Category:   "vuln",
		Required:   true,
	},
	{
		Name:       "subjack",
		Binary:     "subjack",
		InstallCmd: "go install -v github.com/haccer/subjack@latest",
		Category:   "vuln",
		Required:   false,
	},
	// ── Temel Araçlar ─────────────────────────────────────────────────
	{
		Name:       "whois",
		Binary:     "whois",
		InstallCmd: "apt-get install -y whois",
		Category:   "recon",
		Required:   true,
	},
	{
		Name:       "curl",
		Binary:     "curl",
		InstallCmd: "apt-get install -y curl",
		Category:   "recon",
		Required:   true,
	},
}

// CheckResult bir aracın kontrol sonucu.
type CheckResult struct {
	Tool     Tool
	Found    bool
	Path     string
	Missing  bool
}

// CheckAll tüm araçların kurulu olup olmadığını kontrol eder.
func CheckAll() []CheckResult {
	var results []CheckResult
	for _, t := range Registry {
		path, err := exec.LookPath(t.Binary)
		results = append(results, CheckResult{
			Tool:    t,
			Found:   err == nil,
			Path:    path,
			Missing: err != nil,
		})
	}
	return results
}

// CheckRequired sadece Required=true araçları kontrol eder.
// Tarama başlamadan önce çağrılır.
func CheckRequired() ([]string, error) {
	var missing []string
	for _, t := range Registry {
		if !t.Required {
			continue
		}
		if _, err := exec.LookPath(t.Binary); err != nil {
			missing = append(missing, t.Binary)
		}
	}
	if len(missing) > 0 {
		return missing, fmt.Errorf("gerekli araçlar eksik: %s", strings.Join(missing, ", "))
	}
	return nil, nil
}

// PrintStatus araç durumunu CLI'da gösterir.
func PrintStatus() {
	results := CheckAll()

	categories := map[string][]CheckResult{}
	for _, r := range results {
		categories[r.Tool.Category] = append(categories[r.Tool.Category], r)
	}

	order := []string{"recon", "portscan", "web", "osint", "vuln"}
	for _, cat := range order {
		color.Cyan("\n  [%s]", strings.ToUpper(cat))
		for _, r := range categories[cat] {
			if r.Found {
				color.Green("    ✓ %-20s %s", r.Tool.Name, r.Path)
			} else if r.Tool.Required {
				color.Red("    ✗ %-20s EKSİK (gerekli)", r.Tool.Name)
			} else {
				color.Yellow("    - %-20s kurulu değil (opsiyonel)", r.Tool.Name)
			}
		}
	}
}

// InstallHint eksik araç için kurulum komutunu döner.
func InstallHint(binaryName string) string {
	for _, t := range Registry {
		if t.Binary == binaryName {
			return t.InstallCmd
		}
	}
	return ""
}
