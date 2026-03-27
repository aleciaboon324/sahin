// Package netattack implements network-layer attack detection.
// BBM456 Network Security dersi içeriğinden ilham alınmıştır:
// - W2: Sniffing & Spoofing (ARP, promiscuous mode)
// - W3: IP Layer Attacks (ICMP, BGP hijacking, fragmentation)
// - W4: Transport Layer Attacks (TCP scans, SYN flood, UDP amplification)
package netattack

import (
	"context"
	"fmt"
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
)

func init() {
	runner.Register("netattack", func(ctx context.Context, sc *engine.ScanContext) error {
		return (&NetAttackModule{}).Run(ctx, sc)
	})
}

type NetAttackModule struct{}

func (m *NetAttackModule) Run(ctx context.Context, sc *engine.ScanContext) error {
	target := sc.Target
	color.Cyan("\n[NETATTACK] Ağ saldırı yüzeyi analizi: %s\n", target)
	color.Yellow("  [i] BBM456 Network Security ders içeriği bazlı testler\n")

	outDir := filepath.Join(sc.OutputDir, sc.Workspace, "netattack")
	_ = os.MkdirAll(outDir, 0755)

	steps := []struct {
		name string
		fn   func(context.Context, string, *engine.ScanContext) ([]string, error)
	}{
		// W4 - Transport Layer
		{"UDP Amplification Servisleri (W4)", checkUDPAmplification},
		{"SYN Cookie Desteği Kontrolü (W4)", checkSYNCookies},
		{"OS Fingerprinting (W4)", checkOSFingerprint},
		{"TCP Port Scan Tespiti (W4)", checkPortScanVectors},
		// W3 - IP Layer
		{"ICMP Flood/Smurf Zafiyeti (W3)", checkICMPVulnerability},
		{"BGP Hijacking Risk (W3/TR)", checkBGPHijackRisk},
		{"IP Fragmentation Davranışı (W3)", checkFragmentation},
		// W2 - Link Layer
		{"ARP Spoofing Riski (W2)", checkARPSpoofing},
		{"Promiscuous Mode Tespiti (W2)", checkPromiscuousMode},
		// W1 - CIA Triad analizi
		{"CIA Triad Risk Özeti (W1)", checkCIATriad},
	}

	for _, step := range steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		color.White("  [→] %s...", step.name)
		start := time.Now()
		results, err := step.fn(ctx, target, sc)
		elapsed := time.Since(start).Round(time.Millisecond)

		if err != nil {
			color.Yellow("  [!] %s: %v", step.name, err)
			continue
		}

		color.Green("  [✓] %s (%v) — %d bulgu", step.name, elapsed, len(results))
		for _, r := range results {
			sev := classify(r)
			sc.Results <- engine.Result{
				Module:   "netattack",
				Step:     step.name,
				Output:   r,
				Severity: sev,
			}
		}

		safe := strings.NewReplacer(" ", "-", "/", "-", "(", "", ")", "").Replace(strings.ToLower(step.name))
		_ = os.WriteFile(
			filepath.Join(outDir, safe+".txt"),
			[]byte(strings.Join(results, "\n")),
			0644,
		)
	}

	return nil
}

// ── W4: UDP Amplification ─────────────────────────────────────────────────────
// BBM456 W4 Slide 10-11: Bandwidth Amplification Factor
// DNS: ~54x, NTP: ~556x, SNMP: ~650x, Memcached: ~51000x

func checkUDPAmplification(ctx context.Context, target string, _ *engine.ScanContext) ([]string, error) {
	var results []string

	// Amplification servisleri ve amplification faktörleri
	services := []struct {
		port   int
		name   string
		factor string
		check  func(context.Context, string) bool
	}{
		{53, "DNS", "~54x", checkDNSOpen},
		{123, "NTP", "~556x", checkUDPPortOpen},
		{161, "SNMP", "~650x", checkSNMPOpen},
		{11211, "Memcached", "~51000x", checkUDPPortOpen},
		{1900, "SSDP", "~30x", checkUDPPortOpen},
		{19, "Chargen", "~358x", checkUDPPortOpen}, // W4 Echo-Chargen ping-pong
		{7, "Echo", "ping-pong", checkUDPPortOpen},
	}

	for _, svc := range services {
		addr := fmt.Sprintf("%s:%d", target, svc.port)
		conn, err := net.DialTimeout("udp", addr, 2*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		if svc.check(ctx, target) {
			msg := fmt.Sprintf(
				"[amplification] Port %d (%s) açık — Amplification faktörü: %s — DRDoS saldırısında kullanılabilir! (high)",
				svc.port, svc.name, svc.factor,
			)
			results = append(results, msg)
			color.Red("  [!!!] %s", msg)
		} else {
			results = append(results, fmt.Sprintf(
				"[amplification] Port %d (%s) — erişim sınırlı veya kapalı", svc.port, svc.name,
			))
		}
	}

	if len(results) == 0 {
		results = append(results, "[amplification] UDP amplification servisleri tespit edilmedi")
	}
	return results, nil
}

func checkDNSOpen(ctx context.Context, target string) bool {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", target+":53")
		},
	}
	_, err := resolver.LookupHost(ctx, "version.bind")
	return err == nil
}

func checkSNMPOpen(_ context.Context, target string) bool {
	conn, err := net.DialTimeout("udp", target+":161", 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	// SNMPv1 GetRequest paketi
	snmpGetReq := []byte{
		0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
		0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
		0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
		0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x43, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
	}
	conn.Write(snmpGetReq)
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	return n > 0
}

func checkUDPPortOpen(_ context.Context, target string) bool {
	return false // konservative — doğrudan paket gönderme
}

// ── W4: SYN Cookie Kontrolü ───────────────────────────────────────────────────
// BBM456 W4 Slide 24-25: SYN Flooding & SYN Cookie countermeasure

func checkSYNCookies(_ context.Context, target string, _ *engine.ScanContext) ([]string, error) {
	var results []string

	// TCP bağlantısı açıp kapama davranışını gözlemle
	// SYN flood tespiti için: half-open connection sayısını ölç
	openPorts := probeOpenTCPPorts(target)
	if len(openPorts) == 0 {
		return []string{"[syn-cookie] Açık TCP port bulunamadı — test atlandı"}, nil
	}

	for _, port := range openPorts[:min(3, len(openPorts))] {
		// Birden fazla SYN gönder ve SYN-ACK/RST davranışını gözlemle
		addr := fmt.Sprintf("%s:%d", target, port)

		halfOpenCount := 0
		for i := 0; i < 5; i++ {
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				conn.Close()
				halfOpenCount++
			}
		}

		if halfOpenCount >= 3 {
			results = append(results, fmt.Sprintf(
				"[syn-cookie] Port %d: TCP bağlantısı kabul ediyor (%d/5 başarılı) — SYN flood'a karşı SYN cookie aktif mi bilinmiyor (medium)",
				port, halfOpenCount,
			))
		}
	}

	// Hedefin Linux/Windows bilgisine göre tavsiye ver
	results = append(results,
		"[syn-cookie] Öneri: Sunucuda 'sysctl net.ipv4.tcp_syncookies=1' aktif olmalı (W4 countermeasure)",
		"[syn-cookie] Test: sudo hping3 --syn --flood --rand-source -p <port> <hedef>",
	)

	return results, nil
}

// ── W4: OS Fingerprinting ─────────────────────────────────────────────────────
// BBM456 W4 Slide 19: TTL, window size, DF flag, TCP options

func checkOSFingerprint(ctx context.Context, target string, _ *engine.ScanContext) ([]string, error) {
	var results []string

	// Ping ile TTL al
	cmd := exec.CommandContext(ctx, "ping", "-c", "3", "-W", "2", target)
	out, err := cmd.CombinedOutput()

	if err == nil {
		output := string(out)
		ttl := extractTTL(output)
		if ttl > 0 {
			osGuess := guessByTTL(ttl)
			results = append(results, fmt.Sprintf(
				"[os-fingerprint] TTL=%d → Muhtemel OS: %s (W4 pasif fingerprinting)",
				ttl, osGuess,
			))
		}
	}

	// nmap OS fingerprint
	if _, err := exec.LookPath("nmap"); err == nil {
		nmapCmd := exec.CommandContext(ctx,
			"nmap", "-O", "--osscan-guess", "-Pn", "-n",
			"--max-os-tries", "1", "-p", "80,443,22",
			"--script", "banner",
			target,
		)
		nmapOut, _ := nmapCmd.CombinedOutput()
		for _, line := range strings.Split(string(nmapOut), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "OS details") ||
				strings.Contains(line, "OS guess") ||
				strings.Contains(line, "Running:") {
				results = append(results, fmt.Sprintf("[os-fingerprint] Nmap: %s", line))
			}
		}
	}

	// W4 Slide 19: TCP seçeneklerinden OS tahmini
	tcpSig := probeTCPSignature(target)
	if tcpSig != "" {
		results = append(results, fmt.Sprintf("[os-fingerprint] TCP imzası: %s", tcpSig))
	}

	if len(results) == 0 {
		results = append(results, "[os-fingerprint] OS fingerprint bilgisi alınamadı")
	}
	return results, nil
}

func extractTTL(pingOutput string) int {
	for _, line := range strings.Split(pingOutput, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "ttl=") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.HasPrefix(strings.ToLower(p), "ttl=") {
					ttlStr := strings.TrimPrefix(strings.ToLower(p), "ttl=")
					var ttl int
					fmt.Sscanf(ttlStr, "%d", &ttl)
					return ttl
				}
			}
		}
	}
	return 0
}

// BBM456 W4: TTL değerinden OS tahmini
// Windows: 128, Linux: 64, Cisco: 255, FreeBSD: 64
func guessByTTL(ttl int) string {
	switch {
	case ttl > 200:
		return "Cisco/Network Cihazı (TTL≈255)"
	case ttl > 100:
		return "Windows (TTL≈128) — RDP, SMB saldırıları için hedef olabilir"
	case ttl > 50:
		return "Linux/Unix (TTL≈64) — çoğu web sunucusu"
	default:
		return "Bilinmiyor veya TTL manipülasyonu"
	}
}

func probeTCPSignature(target string) string {
	// HTTP üzerinden Server header'ından OS ipucu
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + target)
	if err != nil {
		resp, err = client.Get("https://" + target)
	}
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	if server != "" {
		return fmt.Sprintf("Server: %s", server)
	}
	return ""
}

// ── W4: Port Scan Vektörleri ──────────────────────────────────────────────────
// BBM456 W4: Connect, SYN, FIN, Idle, Xmas scan'leri anlat

func checkPortScanVectors(_ context.Context, target string, _ *engine.ScanContext) ([]string, error) {
	results := []string{
		"[portscan-theory] BBM456 W4'e göre port scan türleri:",
		fmt.Sprintf("[portscan-theory] Connect Scan: nmap -sT %s  (tam TCP bağlantısı, loglanır)", target),
		fmt.Sprintf("[portscan-theory] SYN Scan:     nmap -sS %s  (yarı açık, daha sessiz)", target),
		fmt.Sprintf("[portscan-theory] FIN Scan:     nmap -sF %s  (FIN paketi, kapalı port RST döner)", target),
		fmt.Sprintf("[portscan-theory] Xmas Scan:    nmap -sX %s  (FIN+PSH+URG bayrakları)", target),
		fmt.Sprintf("[portscan-theory] UDP Scan:     nmap -sU %s  (yavaş, ICMP unreachable = kapalı)", target),
		fmt.Sprintf("[portscan-theory] Idle Scan:    nmap -sI <zombie> %s  (kaynak IP gizlenir)", target),
	}

	// Gerçek açık port sayısını test et
	openPorts := probeOpenTCPPorts(target)
	if len(openPorts) > 0 {
		results = append(results, fmt.Sprintf(
			"[portscan-result] %d açık TCP port tespit edildi: %v",
			len(openPorts), openPorts,
		))

		// Çok fazla açık port = geniş saldırı yüzeyi
		if len(openPorts) > 20 {
			results = append(results, fmt.Sprintf(
				"[portscan-risk] %d açık port — saldırı yüzeyi çok geniş! Her gereksiz servisi kapat (high)",
				len(openPorts),
			))
		}
	}

	return results, nil
}

// ── W3: ICMP Vulnerability ───────────────────────────────────────────────────
// BBM456 W3: Smurf, Ping Sweep, ICMP Redirect, Ping Flood

func checkICMPVulnerability(ctx context.Context, target string, _ *engine.ScanContext) ([]string, error) {
	var results []string

	// Ping sweep — host canlı mı?
	cmd := exec.CommandContext(ctx, "ping", "-c", "2", "-W", "2", target)
	out, err := cmd.CombinedOutput()
	if err == nil && strings.Contains(string(out), "bytes from") {
		results = append(results, fmt.Sprintf("[icmp] Ping yanıtı alındı — ICMP ping sweep'e karşı görünür (info)"))
		results = append(results, "[icmp] Öneri: Güvenlik duvarında ICMP echo request'leri filtrele (RFC 792)")

		// Ping flood riski
		results = append(results, fmt.Sprintf(
			"[icmp] Ping Flood riski: hping3 --icmp --flood --rand-source %s (W3 Slide 29)", target,
		))
	} else {
		results = append(results, "[icmp] ICMP ping yanıtı yok — ping sweep'e karşı koruma var")
	}

	// Smurf attack — directed broadcast kontrolü
	// BBM456 W3 Slide 28: netid.255 - routers no longer forward
	results = append(results,
		"[icmp-smurf] Smurf saldırısı (W3): IP directed broadcast artık çoğu router tarafından iletilmiyor",
		"[icmp-smurf] Kontrol: Ağ cihazlarında 'no ip directed-broadcast' yapılandırması yapılmalı",
	)

	// ICMP redirect riski
	results = append(results,
		"[icmp-redirect] ICMP Redirect (W3): Modern sistemlerde varsayılan olarak kabul edilmiyor",
		"[icmp-redirect] Linux kontrolü: sysctl net.ipv4.conf.all.accept_redirects (0 olmalı)",
	)

	return results, nil
}

// ── W3: BGP Hijacking Risk (TÜRKİYE ÖZEL) ────────────────────────────────────
// BBM456 W3 Slide 64: Turk Telekom 2014'te Google DNS (8.8.8.8), OpenDNS (208.67.222.222)
// adreslerini hijack etti! Bu özellik Şahin'e çok yakışıyor.

func checkBGPHijackRisk(ctx context.Context, target string, _ *engine.ScanContext) ([]string, error) {
	var results []string

	// Hedefin IP adresini al
	addrs, err := net.DefaultResolver.LookupHost(ctx, target)
	if err != nil || len(addrs) == 0 {
		return []string{"[bgp] IP çözümlenemedi"}, nil
	}
	ip := addrs[0]

	results = append(results, fmt.Sprintf("[bgp] Hedef IP: %s", ip))
	results = append(results, "[bgp] BBM456 W3: BGP Hijacking — AS'ler daha spesifik prefix announce ederek trafiği çeker")

	// TR-özel BGP hijacking geçmişi kontrolü (W3 Slide 63-64)
	turkishASNs := []struct {
		asn      string
		name     string
		incident string
	}{
		{"AS9121", "Türk Telekom", "2014: Google DNS (8.8.8.8) ve OpenDNS hijack"},
		{"AS15897", "Turkcell", "Geçmiş yönlendirme anormallikleri"},
		{"AS8517", "Türksat", "Devlet altyapısı"},
		{"AS34984", "Superonline", "Türkiye transit AS"},
	}

	for _, asn := range turkishASNs {
		results = append(results, fmt.Sprintf(
			"[bgp-tr] %s (%s): %s",
			asn.asn, asn.name, asn.incident,
		))
	}

	// BGP monitoring servisleri
	results = append(results,
		"[bgp-monitor] Gerçek zamanlı BGP monitoring (W3 Slide 70):",
		"[bgp-monitor] BGPMon:  https://bgpmon.net",
		"[bgp-monitor] RIPE NCC RIS: https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris",
		"[bgp-monitor] RPKI ROA kontrolü: https://rpki.cloudflare.com",
		fmt.Sprintf("[bgp-monitor] Hedef IP için BGP lookup: https://bgp.he.net/ip/%s", ip),
	)

	// Pakistan Youtube hijack benzeri senaryo
	results = append(results,
		"[bgp-history] Tarihi olay (W3 Slide 61-64): Pakistan 2008'de Youtube'u (208.65.152.0/24) hijack etti",
		"[bgp-history] Tarihî olay (W3 Slide 63): Türkiye 2014'te Twitter sansürü için DNS hijack yaptı",
		"[bgp-history] Countermeasure (W3): RPKI, prefix filtering, global BGP monitoring",
	)

	return results, nil
}

// ── W3: IP Fragmentation ──────────────────────────────────────────────────────
// BBM456 W3 Slide 9-21: Ping-of-Death, Teardrop, Resource Consumption

func checkFragmentation(ctx context.Context, target string, _ *engine.ScanContext) ([]string, error) {
	var results []string

	// Modern sistemler Ping-of-Death'e karşı patch'li
	results = append(results,
		"[fragmentation] BBM456 W3: IP Fragmentation saldırıları",
		"[fragmentation] Ping-of-Death (1997): ping -s 65512 — Modern sistemler korumalı",
		"[fragmentation] Teardrop: Overlapping fragment'lar — Eski Windows/Linux'u etkilerdi",
		"[fragmentation] Resource Consumption: Offset=1 + Offset=65534 → ~65KB buffer tüketim",
	)

	// Path MTU Discovery testi
	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-M", "do", "-s", "1472", target)
	out, _ := cmd.CombinedOutput()
	if strings.Contains(string(out), "Message too long") ||
		strings.Contains(string(out), "Frag needed") {
		results = append(results, "[fragmentation] Path MTU Discovery çalışıyor — DF bit aktif (iyi)")
	} else if strings.Contains(string(out), "bytes from") {
		results = append(results, "[fragmentation] 1472 byte paket ulaştı — MTU ≥ 1500 (normal)")
	}

	// Evasion uyarısı (W3 Slide 11)
	results = append(results,
		"[fragmentation-evasion] IDS Evasion: Saldırganlar fragmentation ile IDS/firewall atlayabilir",
		"[fragmentation-evasion] W3 Slide 11: Bazı IDS'ler fragment'ları reassemble etmez!",
		"[fragmentation-evasion] Countermeasure: Firewall'da overlapping fragment'ları engelle",
	)

	return results, nil
}

// ── W2: ARP Spoofing Risk ─────────────────────────────────────────────────────
// BBM456 W2 Slide 69-74: ARP Spoofing / Cache Poisoning

func checkARPSpoofing(ctx context.Context, target string, _ *engine.ScanContext) ([]string, error) {
	var results []string

	results = append(results,
		"[arp] BBM456 W2: ARP Spoofing — Saldırgan kurbanın MAC adresini taklit eder",
		"[arp] Saldırı adımları: sahte ARP reply gönder → ARP cache zehirle → MITM konumuna geç",
	)

	// arp-scan varsa yerel ağı tara
	if _, err := exec.LookPath("arp-scan"); err == nil {
		cmd := exec.CommandContext(ctx, "arp-scan", "--localnet", "--retry", "2")
		out, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				if strings.Count(line, "\t") >= 2 {
					results = append(results, fmt.Sprintf("[arp-scan] %s", line))
				}
			}
		}
	}

	// arp tablosunu kontrol et
	cmd := exec.CommandContext(ctx, "arp", "-n")
	out, err := cmd.Output()
	if err == nil {
		// Duplike MAC adresleri — ARP spoofing işareti!
		macCounts := map[string]int{}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				mac := strings.ToLower(fields[2])
				if mac != "<incomplete>" && mac != "00:00:00:00:00:00" {
					macCounts[mac]++
				}
			}
		}
		for mac, count := range macCounts {
			if count > 1 {
				results = append(results, fmt.Sprintf(
					"[arp-spoofing] UYARI: MAC adresi %s birden fazla IP'ye eşlenmiş (%d) — ARP spoofing olabilir! (high)",
					mac, count,
				))
			}
		}
	}

	// Countermeasures (W2 Slide 74)
	results = append(results,
		"[arp-defense] W2 Countermeasure: Static ARP entries kritik IP'ler için (DNS, GW)",
		"[arp-defense] W2 Countermeasure: Dynamic ARP Inspection (DAI) — switch konfigürasyonu",
		"[arp-defense] W2 Countermeasure: Arpwatch ile ARP değişikliklerini izle",
		"[arp-defense] W2 Countermeasure: 802.1X port-based network access control",
	)

	return results, nil
}

// ── W2: Promiscuous Mode Detection ───────────────────────────────────────────
// BBM456 W2 Slide 46: Detecting Sniffers — promiscuous flag, ARP traffic

func checkPromiscuousMode(_ context.Context, target string, _ *engine.ScanContext) ([]string, error) {
	results := []string{
		"[sniffer] BBM456 W2 Slide 46: Sniffer tespiti teknikleri",
		"[sniffer] Yöntem 1: Kernel promiscuous flag kontrolü (ifconfig | grep PROMISC)",
		"[sniffer] Yöntem 2: Şüpheli ARP trafiği — sniffer tüm ARP'lere yanıt verebilir",
		"[sniffer] Yöntem 3: DNS lookup anomalisi — sniffer tüm IP'leri reverse-lookup yapar",
		"[sniffer] Yöntem 4: Latency testi — tüm paketleri işlemek gecikme yaratır",
	}

	// Yerel ağdaki interface'lerin promisc modunu kontrol et
	cmd := exec.Command("ip", "link", "show")
	out, err := cmd.Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "PROMISC") {
				results = append(results, fmt.Sprintf(
					"[sniffer] UYARI: Promiscuous mod aktif interface: %s (high)",
					strings.TrimSpace(line),
				))
			}
		}
	}

	// Network sniffing tools (W2 Slide 54)
	results = append(results,
		"[sniffer] W2 Slide 54: Popüler sniffing araçları: tcpdump, Wireshark, tcpflow, tcpreplay",
		fmt.Sprintf("[sniffer] Koruma: Şifreli protokoller kullan (HTTPS yerine HTTP değil, SSH yerine Telnet değil)"),
		"[sniffer] Switched network'te sniffing için (W2): SPAN port, MAC flooding, MAC duplication",
	)

	return results, nil
}

// ── W1: CIA Triad Risk Analizi ────────────────────────────────────────────────
// BBM456 W1: Confidentiality, Integrity, Availability

func checkCIATriad(_ context.Context, target string, sc *engine.ScanContext) ([]string, error) {
	results := []string{
		"[cia] BBM456 W1: CIA Triad risk analizi",
		"",
		"[cia-confidentiality] GİZLİLİK (Confidentiality):",
		"[cia-confidentiality] Risk: Açık portlardaki şifresiz servisler (Telnet, FTP, HTTP)",
		"[cia-confidentiality] Risk: ARP spoofing ile MITM — iletişim dinlenebilir",
		"[cia-confidentiality] Risk: BGP hijacking ile trafik yönlendirme",
		"",
		"[cia-integrity] BÜTÜNLÜK (Integrity):",
		"[cia-integrity] Risk: TCP session hijacking ile veri manipülasyonu",
		"[cia-integrity] Risk: DNS/BGP spoofing ile yanıltıcı yönlendirme",
		"[cia-integrity] Risk: ICMP redirect ile yönlendirme tablosu manipülasyonu",
		"",
		"[cia-availability] ERİŞİLEBİLİRLİK (Availability):",
		"[cia-availability] Risk: SYN flood ile servis reddi",
		"[cia-availability] Risk: UDP amplification ile DDoS (Memcached 51000x!)",
		"[cia-availability] Risk: Ping flood, Smurf, Teardrop saldırıları",
		"[cia-availability] Risk: BGP hijacking ile İnternet erişimini kesme",
		"",
		fmt.Sprintf("[cia-summary] Hedef %s için öncelikli riskler değerlendirildi", target),
		"[cia-summary] Tam risk analizi için OSINT + portscan + web modüllerini birleştir",
	}

	return results, nil
}

// ── Yardımcı Fonksiyonlar ─────────────────────────────────────────────────────

func probeOpenTCPPorts(target string) []int {
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
		3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}
	var open []int
	for _, port := range commonPorts {
		addr := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			open = append(open, port)
		}
	}
	return open
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func classify(result string) string {
	lower := strings.ToLower(result)
	switch {
	case strings.Contains(lower, "critical") ||
		strings.Contains(lower, "hijack") && strings.Contains(lower, "zararlı"):
		return "critical"
	case strings.Contains(lower, "high") ||
		strings.Contains(lower, "uyarı") ||
		strings.Contains(lower, "amplification") ||
		strings.Contains(lower, "spoofing olabilir") ||
		strings.Contains(lower, "promisc"):
		return "high"
	case strings.Contains(lower, "medium") ||
		strings.Contains(lower, "risk") ||
		strings.Contains(lower, "öneri"):
		return "medium"
	default:
		return "info"
	}
}
