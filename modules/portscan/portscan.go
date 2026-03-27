// Package portscan implements the port scanning module.
// nmap'i Go'dan çalıştırır, XML çıktısını parse eder,
// açık portları DB'ye kaydeder ve önceki taramayla diff yapar.
package portscan

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sahin-security/sahin/core/engine"
	"github.com/sahin-security/sahin/core/runner"
)

func init() {
	runner.Register("portscan", func(ctx context.Context, sc *engine.ScanContext) error {
		return (&PortscanModule{}).Run(ctx, sc)
	})
}

// ── Nmap XML structs ───────────────────────────────────────────────────────────

type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

type NmapHost struct {
	Status    NmapStatus     `xml:"status"`
	Addresses []NmapAddress  `xml:"address"`
	Hostnames []NmapHostname `xml:"hostnames>hostname"`
	Ports     []NmapPort     `xml:"ports>port"`
	OS        NmapOS         `xml:"os"`
}

type NmapStatus struct {
	State string `xml:"state,attr"`
}

type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type NmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type NmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    NmapState    `xml:"state"`
	Service  NmapService  `xml:"service"`
	Scripts  []NmapScript `xml:"script"`
}

type NmapState struct {
	State string `xml:"state,attr"`
}

type NmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Tunnel    string `xml:"tunnel,attr"` // ssl
	CPE       string `xml:"cpe"`
}

type NmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type NmapOS struct {
	Matches []NmapOSMatch `xml:"osmatch"`
}

type NmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// ── OpenPort sonuç struct ─────────────────────────────────────────────────────

type OpenPort struct {
	Port     int
	Protocol string
	Service  string
	Product  string
	Version  string
	State    string
	SSL      bool
	Scripts  []string
}

func (p OpenPort) String() string {
	svc := p.Service
	if p.Product != "" {
		svc = p.Product
		if p.Version != "" {
			svc += " " + p.Version
		}
	}
	ssl := ""
	if p.SSL {
		ssl = " [SSL/TLS]"
	}
	return fmt.Sprintf("%d/%s  %-12s  %s%s", p.Port, p.Protocol, p.State, svc, ssl)
}

// ── PortscanModule ────────────────────────────────────────────────────────────

type PortscanModule struct{}

func (m *PortscanModule) Run(ctx context.Context, sc *engine.ScanContext) error {
	target := sc.Target
	color.Cyan("\n[PORTSCAN] Başlatıldı: %s\n", target)

	// Port profili seç
	ports := sc.Params["ports"]
	if ports == "" {
		if sc.Stealth {
			// Stealth modda sadece kritik portlar
			ports = "21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,8080,8443"
		} else {
			// Normal modda yaygın portlar
			ports = "21,22,23,25,53,80,110,111,135,137-139,143,161,443,445,512-514,993,995,1099,1433,1521,1723,2049,2181,3000,3306,3389,4444,4848,5000,5432,5555,5900,5985,6379,6443,7001,7070,8000,8008,8080,8081,8443,8888,9000,9090,9200,9300,9443,10000,10250,11211,27017,49152"
		}
	}

	// Nmap var mı kontrol et
	if _, err := exec.LookPath("nmap"); err != nil {
		return fmt.Errorf("nmap kurulu değil — 'apt-get install nmap' ile kur")
	}

	// Workspace dizinleri
	portsDir := filepath.Join(sc.OutputDir, sc.Workspace, "ports")
	_ = os.MkdirAll(portsDir, 0755)

	xmlOut := filepath.Join(portsDir, fmt.Sprintf("nmap-%s.xml", target))
	txtOut := filepath.Join(portsDir, fmt.Sprintf("nmap-%s.txt", target))
	oldPorts := filepath.Join(portsDir, fmt.Sprintf("ports-%s.old", target))
	curPorts := filepath.Join(portsDir, fmt.Sprintf("ports-%s.txt", target))

	// Önceki port listesini yedekle (diff için)
	if _, err := os.Stat(curPorts); err == nil {
		data, _ := os.ReadFile(curPorts)
		_ = os.WriteFile(oldPorts, data, 0644)
	}

	// ── Nmap çalıştır ────────────────────────────────────────────────────
	nmapArgs := buildNmapArgs(target, ports, xmlOut, sc.Stealth)
	color.White("  [→] Nmap çalışıyor: nmap %s", strings.Join(nmapArgs, " "))

	start := time.Now()
	cmd := exec.CommandContext(ctx, "nmap", nmapArgs...)
	txtData, err := cmd.CombinedOutput()
	elapsed := time.Since(start).Round(time.Second)

	// TXT çıktıyı kaydet
	_ = os.WriteFile(txtOut, txtData, 0644)

	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}

	// ── XML Parse ────────────────────────────────────────────────────────
	xmlData, err := os.ReadFile(xmlOut)
	if err != nil {
		return fmt.Errorf("nmap XML okunamadı: %w", err)
	}

	var nmapRun NmapRun
	if err := xml.Unmarshal(xmlData, &nmapRun); err != nil {
		return fmt.Errorf("nmap XML parse hatası: %w", err)
	}

	// ── Sonuçları işle ───────────────────────────────────────────────────
	var openPorts []OpenPort
	var portLines []string
	osGuess := ""

	for _, host := range nmapRun.Hosts {
		if host.Status.State != "up" {
			continue
		}

		// IP adresi
		hostIP := ""
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				hostIP = addr.Addr
			}
		}

		// OS tespiti
		if len(host.OS.Matches) > 0 {
			osGuess = fmt.Sprintf("%s (%s%% doğruluk)",
				host.OS.Matches[0].Name,
				host.OS.Matches[0].Accuracy,
			)
		}

		// Açık portlar
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}
			op := OpenPort{
				Port:     port.PortID,
				Protocol: port.Protocol,
				Service:  port.Service.Name,
				Product:  port.Service.Product,
				Version:  port.Service.Version,
				State:    "open",
				SSL:      port.Service.Tunnel == "ssl",
			}
			for _, script := range port.Scripts {
				op.Scripts = append(op.Scripts, fmt.Sprintf("%s: %s", script.ID, script.Output))
			}
			openPorts = append(openPorts, op)
			portLines = append(portLines, strconv.Itoa(port.PortID))
		}

		color.Green("  [✓] Host: %s — %d açık port (%v)", hostIP, len(openPorts), elapsed)
	}

	if len(openPorts) == 0 {
		color.Yellow("  [!] Açık port bulunamadı")
		return nil
	}

	// ── Sonuçları terminale bas ───────────────────────────────────────────
	color.Cyan("\n  PORT        DURUM        SERVİS")
	color.Cyan("  " + strings.Repeat("─", 60))

	for _, p := range openPorts {
		sev := classifyPortSeverity(p)
		line := fmt.Sprintf("  %s", p.String())
		switch sev {
		case "critical", "high":
			color.Red(line)
		case "medium":
			color.Yellow(line)
		default:
			color.White(line)
		}

		// Script çıktıları
		for _, script := range p.Scripts {
			color.HiBlack("    └─ %s", script)
		}

		// sc.Results'a gönder
		sc.Results <- engine.Result{
			Module:   "portscan",
			Step:     "nmap",
			Output:   fmt.Sprintf("[port] %s", p.String()),
			Severity: sev,
		}
	}

	// OS bilgisi
	if osGuess != "" {
		color.Cyan("\n  [OS] %s", osGuess)
		sc.Results <- engine.Result{
			Module:   "portscan",
			Step:     "os-detection",
			Output:   fmt.Sprintf("[os] %s", osGuess),
			Severity: "info",
		}
	}

	// ── Port listesini kaydet ─────────────────────────────────────────────
	_ = os.WriteFile(curPorts, []byte(strings.Join(portLines, "\n")), 0644)

	// ── Port diff (değişiklik tespiti) ────────────────────────────────────
	checkPortDiff(oldPorts, curPorts, target, sc)

	// ── Dikkat çeken servisleri özetle ───────────────────────────────────
	summarizeFindings(openPorts, sc)

	color.Green("\n  [✓] Port taraması tamamlandı — %d açık port", len(openPorts))
	return nil
}

// ── Nmap argümanları ──────────────────────────────────────────────────────────

func buildNmapArgs(target, ports, xmlOut string, stealth bool) []string {
	args := []string{
		"-p", ports,
		"--open",
		"-oX", xmlOut,
		"-oN", strings.Replace(xmlOut, ".xml", ".txt", 1),
	}

	if stealth {
		// Stealth: yavaş, SYN scan, OS tespiti yok
		args = append(args,
			"-sS", "-Pn", "-T2", "-n",
			"--max-retries", "1",
			"--min-rate", "100", "--max-rate", "300",
		)
	} else {
		// Normal: servis/versiyon tespiti, OS tahmini, NSE scriptler
		args = append(args,
			"-sV", "-sC", "-Pn", "-O", "--osscan-guess",
			"--max-os-tries", "1",
			"-T4", "-n",
			"--max-retries", "3",
			"--min-rate", "300", "--max-rate", "3000",
			"--script", "vuln,default",
			"--script-timeout", "60",
		)
	}

	args = append(args, target)
	return args
}

// ── Port diff tespiti ─────────────────────────────────────────────────────────
// Sn1per'ın port diff mantığının Go karşılığı

func checkPortDiff(oldFile, newFile, target string, sc *engine.ScanContext) {
	oldData, err1 := os.ReadFile(oldFile)
	newData, err2 := os.ReadFile(newFile)
	if err1 != nil || err2 != nil {
		return
	}

	oldPorts := toSet(strings.Split(string(oldData), "\n"))
	newPorts := toSet(strings.Split(string(newData), "\n"))

	// Yeni açılan portlar
	for p := range newPorts {
		if p == "" {
			continue
		}
		if !oldPorts[p] {
			msg := fmt.Sprintf("[port-diff] YENİ PORT AÇILDI: %s/%s — dikkat! (high)", p, target)
			color.Red("  [!!!] %s", msg)
			sc.Results <- engine.Result{
				Module:   "portscan",
				Step:     "port-diff",
				Output:   msg,
				Severity: "high",
			}
		}
	}

	// Kapanan portlar
	for p := range oldPorts {
		if p == "" {
			continue
		}
		if !newPorts[p] {
			msg := fmt.Sprintf("[port-diff] Port kapandı: %s/%s", p, target)
			color.Yellow("  [~] %s", msg)
			sc.Results <- engine.Result{
				Module:   "portscan",
				Step:     "port-diff",
				Output:   msg,
				Severity: "info",
			}
		}
	}
}

// ── Dikkat çeken servis özeti ─────────────────────────────────────────────────

type interestingService struct {
	ports   []int
	name    string
	finding string
	sev     string
}

func summarizeFindings(ports []OpenPort, sc *engine.ScanContext) {
	// Dikkat çeken port → servis eşleşmeleri
	dangerous := map[int]struct {
		name    string
		finding string
		sev     string
	}{
		21:    {"FTP", "FTP açık — anonim giriş denenebilir", "high"},
		23:    {"Telnet", "Telnet açık — şifresiz protokol!", "critical"},
		445:   {"SMB", "SMB açık — EternalBlue/ransomware riski", "high"},
		3389:  {"RDP", "RDP açık — brute force hedefi olabilir", "high"},
		5900:  {"VNC", "VNC açık — authentication kontrol et", "high"},
		6379:  {"Redis", "Redis açık — authentication olmadan erişilebilir olabilir", "critical"},
		9200:  {"Elasticsearch", "Elasticsearch açık — veri sızıntısı riski", "critical"},
		27017: {"MongoDB", "MongoDB açık — authentication kontrol et", "critical"},
		2375:  {"Docker API", "Docker API açık — container escape riski!", "critical"},
		10250: {"Kubelet", "Kubelet API açık — K8s node erişimi riski", "critical"},
		5432:  {"PostgreSQL", "PostgreSQL dışarıya açık", "high"},
		3306:  {"MySQL", "MySQL dışarıya açık", "high"},
		1433:  {"MSSQL", "MSSQL dışarıya açık", "high"},
		11211: {"Memcached", "Memcached açık — DRDoS amplification riski", "high"},
		161:   {"SNMP", "SNMP açık — community string brute force", "medium"},
		512:   {"rexec", "rexec açık — eski Unix uzak komut servisi", "critical"},
		513:   {"rlogin", "rlogin açık — şifresiz uzak giriş!", "critical"},
	}

	color.Cyan("\n  [*] Dikkat Çeken Servisler:")
	found := false

	for _, p := range ports {
		if info, ok := dangerous[p.Port]; ok {
			found = true
			msg := fmt.Sprintf("[!] Port %d (%s): %s", p.Port, info.name, info.finding)
			switch info.sev {
			case "critical":
				color.Red("    %s", msg)
			case "high":
				color.Yellow("    %s", msg)
			default:
				color.White("    %s", msg)
			}
			sc.Results <- engine.Result{
				Module:   "portscan",
				Step:     "service-analysis",
				Output:   msg,
				Severity: info.sev,
			}
		}
	}

	if !found {
		color.White("    Kritik servis tespit edilmedi")
	}
}

// ── Severity ──────────────────────────────────────────────────────────────────

func classifyPortSeverity(p OpenPort) string {
	critical := map[int]bool{23: true, 512: true, 513: true, 6379: true, 9200: true, 27017: true, 2375: true, 10250: true}
	high := map[int]bool{21: true, 445: true, 3389: true, 5900: true, 5432: true, 3306: true, 1433: true, 11211: true}
	medium := map[int]bool{161: true, 162: true, 1521: true, 5000: true, 8080: true, 8443: true}

	if critical[p.Port] {
		return "critical"
	}
	if high[p.Port] {
		return "high"
	}
	if medium[p.Port] {
		return "medium"
	}
	return "info"
}

// ── Yardımcı ──────────────────────────────────────────────────────────────────

func toSet(lines []string) map[string]bool {
	s := map[string]bool{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			s[l] = true
		}
	}
	return s
}
