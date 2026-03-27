// Package workspace manages the scan output directory structure.
// Sn1per'ın loot/ mantığını alır, yapılandırılmış, DB-destekli bir
// workspace sistemine dönüştürür.
package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Workspace bir pentest engagement'ının tüm çıktısını tutar.
// Sn1per'ın düz loot/ klasörünün aksine bu yapı tip-güvenli ve
// DB ile senkronize çalışır.
type Workspace struct {
	Name      string
	Target    string
	BaseDir   string
	CreatedAt time.Time
	Dirs      DirLayout
}

// DirLayout Sn1per'ın loot alt dizinlerini Go struct'a taşır.
// Sn1per: domains/ ips/ nmap/ output/ scans/ web/
// Şahin: bunları genişletip osint/ vulns/ tr/ reports/ ekler.
type DirLayout struct {
	Domains string // subdomain listeleri, zone transfer çıktısı
	IPs     string // keşfedilen IP'ler
	Ports   string // nmap XML/TXT çıktıları (Sn1per'da nmap/ dizini)
	Web     string // screenshot, header, teknoloji tespiti
	OSINT   string // whois, e-posta, metadata, theHarvester
	Scans   string // görev logları, running_*.txt takibi
	Output  string // ham araç çıktıları
	Vulns   string // zafiyet raporları, nuclei çıktıları
	TR      string // TR'ye özel modül çıktıları (BTK, gov.tr, USOM)
	Reports string // HTML/PDF raporlar
}

// New bir workspace oluşturur. Dizinler henüz yaratılmaz — Init() çağrısına kadar bekler.
func New(name, target, baseDir string) *Workspace {
	if name == "" {
		// Sn1per gibi hedeften workspace adı üret
		name = sanitizeName(target)
	}
	wsDir := filepath.Join(baseDir, name)
	return &Workspace{
		Name:      name,
		Target:    target,
		BaseDir:   baseDir,
		CreatedAt: time.Now(),
		Dirs:      buildLayout(wsDir),
	}
}

// Init tüm dizin ağacını oluşturur.
func (ws *Workspace) Init() error {
	dirs := []string{
		ws.Dirs.Domains,
		ws.Dirs.IPs,
		ws.Dirs.Ports,
		ws.Dirs.Web,
		ws.Dirs.OSINT,
		ws.Dirs.Scans,
		ws.Dirs.Output,
		ws.Dirs.Vulns,
		ws.Dirs.TR,
		ws.Dirs.Reports,
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("dizin oluşturulamadı %s: %w", d, err)
		}
	}
	// Sn1per gibi scan başlangıcını logla
	return ws.LogTask(fmt.Sprintf("workspace başlatıldı: %s (%s)", ws.Name, ws.Target))
}

// LogTask Sn1per'ın scans/tasks.txt mantığını uygular.
func (ws *Workspace) LogTask(msg string) error {
	path := filepath.Join(ws.Dirs.Scans, "tasks.txt")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
	return err
}

// DomainFile belirli bir kaynak için domain çıktı dosyası yolunu döner.
// Sn1per: $LOOT_DIR/domains/domains-$TARGET-subfinder.txt
// Şahin: domains/<target>-<source>.txt
func (ws *Workspace) DomainFile(source string) string {
	return filepath.Join(ws.Dirs.Domains, fmt.Sprintf("%s-%s.txt", ws.Target, source))
}

// IPFile IP listesi dosyası yolunu döner.
func (ws *Workspace) IPFile(source string) string {
	return filepath.Join(ws.Dirs.IPs, fmt.Sprintf("%s-%s.txt", ws.Target, source))
}

// NmapFile nmap çıktı dosyası yolunu döner (XML ve TXT).
func (ws *Workspace) NmapFile(ext string) string {
	return filepath.Join(ws.Dirs.Ports, fmt.Sprintf("nmap-%s.%s", ws.Target, ext))
}

// TakeoverFile subdomain takeover tespiti için dosya yolu.
// Sn1per: $LOOT_DIR/nmap/takeovers-$TARGET.txt
func (ws *Workspace) TakeoverFile() string {
	return filepath.Join(ws.Dirs.Domains, fmt.Sprintf("takeovers-%s.txt", ws.Target))
}

// FindingFile zafiyet bulgularını saklar.
func (ws *Workspace) FindingFile(module, severity string) string {
	return filepath.Join(ws.Dirs.Vulns, fmt.Sprintf("%s-%s-%s.txt", module, ws.Target, severity))
}

// TRFile TR modülü çıktısı için dosya yolu.
func (ws *Workspace) TRFile(submodule string) string {
	return filepath.Join(ws.Dirs.TR, fmt.Sprintf("%s-%s.txt", submodule, ws.Target))
}

// ReportFile final rapor dosyası yolu.
func (ws *Workspace) ReportFile(format string) string {
	ts := time.Now().Format("20060102-1504")
	return filepath.Join(ws.Dirs.Reports, fmt.Sprintf("sahin-%s-%s.%s", ws.Target, ts, format))
}

// ReadDomains tüm kaynaklardan birleştirilmiş, deduplicated domain listesi döner.
func (ws *Workspace) ReadDomains() ([]string, error) {
	pattern := filepath.Join(ws.Dirs.Domains, ws.Target+"-*.txt")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var domains []string
	for _, f := range files {
		// takeover ve port dosyalarını atla
		if strings.Contains(f, "takeover") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !seen[line] {
				seen[line] = true
				domains = append(domains, line)
			}
		}
	}
	return domains, nil
}

// ── Yardımcı Fonksiyonlar ─────────────────────────────────────────────────────

func buildLayout(wsDir string) DirLayout {
	return DirLayout{
		Domains: filepath.Join(wsDir, "domains"),
		IPs:     filepath.Join(wsDir, "ips"),
		Ports:   filepath.Join(wsDir, "ports"),   // Sn1per'da "nmap" idi
		Web:     filepath.Join(wsDir, "web"),
		OSINT:   filepath.Join(wsDir, "osint"),
		Scans:   filepath.Join(wsDir, "scans"),
		Output:  filepath.Join(wsDir, "output"),
		Vulns:   filepath.Join(wsDir, "vulns"),   // Sn1per'da yoktu
		TR:      filepath.Join(wsDir, "tr"),      // Türkiye'ye özel
		Reports: filepath.Join(wsDir, "reports"),
	}
}

func sanitizeName(target string) string {
	r := strings.NewReplacer(
		"https://", "",
		"http://", "",
		"/", "_",
		":", "_",
		"*", "all",
	)
	return r.Replace(target)
}
