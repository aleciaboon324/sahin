// Package config provides the full typed configuration system for Şahin.
// Sn1per'ın conf/default dosyasındaki 177 değişkenin Go karşılığı —
// ama YAML-native, tip güvenli ve profil destekli.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration object loaded from ~/.sahin/config.yaml
// or the path given via --config flag.
type Config struct {
	// ── Genel Ayarlar ─────────────────────────────────────────────────
	InstallDir  string `yaml:"install_dir"`
	WorkspaceDir string `yaml:"workspace_dir"`
	LogLevel    string `yaml:"log_level"` // debug | info | warn | error

	// ── Tarama Davranışı ──────────────────────────────────────────────
	Scan ScanConfig `yaml:"scan"`

	// ── API Anahtarları ───────────────────────────────────────────────
	APIs APIConfig `yaml:"apis"`

	// ── Entegrasyonlar ────────────────────────────────────────────────
	Integrations IntegrationConfig `yaml:"integrations"`

	// ── Bildirimler ───────────────────────────────────────────────────
	Notify NotifyConfig `yaml:"notify"`

	// ── Türkiye'ye Özel ───────────────────────────────────────────────
	TR TRConfig `yaml:"tr"`
}

// ScanConfig tarama davranışını kontrol eder.
type ScanConfig struct {
	// Port Profilleri (Sn1per'dan alındı ve genişletildi)
	QuickPorts    string `yaml:"quick_ports"`    // ~50 kritik port
	DefaultPorts  string `yaml:"default_ports"`  // ~500 yaygın port
	FullPorts     string `yaml:"full_ports"`     // 1-65535
	WebPorts      string `yaml:"web_ports"`      // 80,443,8080,8443,...
	UDPPorts      string `yaml:"udp_ports"`

	// Nmap Seçenekleri (Sn1per'ın NMAP_OPTIONS'ından türetildi)
	NmapOptionsNormal  string `yaml:"nmap_options_normal"`
	NmapOptionsStealth string `yaml:"nmap_options_stealth"`
	NmapOptionsFast    string `yaml:"nmap_options_fast"`

	// Brute Force
	AutoBrute       bool   `yaml:"auto_brute"`
	WebBruteExtensions string `yaml:"web_brute_extensions"`

	// Özellik Bayrakları
	AutoVulnScan    bool `yaml:"auto_vulnscan"`
	FullNmapScan    bool `yaml:"full_nmap_scan"`
	OSINT           bool `yaml:"osint"`
	Recon           bool `yaml:"recon"`
	EnableUpdates   bool `yaml:"enable_updates"`
	Screenshot      bool `yaml:"screenshot"`
	JavaScriptAnalysis bool `yaml:"javascript_analysis"`

	// Zamanaşımı & Hız
	MaxThreads    int    `yaml:"max_threads"`
	MaxHosts      int    `yaml:"max_hosts"`     // Sn1per'da MAX_HOSTS=2000
	Timeout       string `yaml:"timeout"`        // e.g. "30m"

	// Kapsam Dışı (Out of Scope)
	OutOfScope []string `yaml:"out_of_scope"`
}

// APIConfig harici servis API anahtarlarını tutar.
type APIConfig struct {
	ShodanKey     string `yaml:"shodan"`
	CensysID      string `yaml:"censys_id"`
	CensysSecret  string `yaml:"censys_secret"`
	HunterIO      string `yaml:"hunterio"`
	GithubToken   string `yaml:"github"`
	VirusTotal    string `yaml:"virustotal"`
}

// IntegrationConfig opsiyonel araç entegrasyonlarını tutar.
type IntegrationConfig struct {
	// Vulnerability Scanners
	OpenVAS  OpenVASConfig  `yaml:"openvas"`
	Nessus   NessusConfig   `yaml:"nessus"`
	Burp     BurpConfig     `yaml:"burp"`

	// Exploitation
	Metasploit MetasploitConfig `yaml:"metasploit"`
}

type OpenVASConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type NessusConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Host      string `yaml:"host"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	PolicyID  string `yaml:"policy_id"`
}

type BurpConfig struct {
	Enabled bool   `yaml:"enabled"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
}

type MetasploitConfig struct {
	Import bool   `yaml:"import"`
	LHost  string `yaml:"lhost"`
	LPort  int    `yaml:"lport"`
}

// NotifyConfig bildirim ayarlarını tutar.
// Sn1per'ın per-event Slack toggle'larını daha temiz bir yapıya çevirir.
type NotifyConfig struct {
	Slack   SlackConfig   `yaml:"slack"`
	Webhook WebhookConfig `yaml:"webhook"`

	// Hangi eventler bildirim tetikler
	Events NotifyEvents `yaml:"events"`
}

type SlackConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
	Channel string `yaml:"channel"`
}

type WebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
}

// NotifyEvents Sn1per'ın SLACK_NOTIFICATIONS_* değişkenlerinin karşılığı.
type NotifyEvents struct {
	ScanStart    bool `yaml:"scan_start"`
	ScanFinish   bool `yaml:"scan_finish"`
	NewDomain    bool `yaml:"new_domain"`    // SLACK_NOTIFICATIONS_DOMAINS_NEW
	PortChange   bool `yaml:"port_change"`   // SLACK_NOTIFICATIONS_NMAP_DIFF
	Takeover     bool `yaml:"takeover"`      // SLACK_NOTIFICATIONS_TAKEOVERS_NEW
	NewFinding   bool `yaml:"new_finding"`
	CriticalOnly bool `yaml:"critical_only"` // sadece critical/high bildirimleri gönder
}

// TRConfig Türkiye'ye özel modül ayarları.
type TRConfig struct {
	BTKEnabled    bool   `yaml:"btk_enabled"`
	GovTREnum     bool   `yaml:"gov_tr_enum"`
	ShodanTRASNs  bool   `yaml:"shodan_tr_asns"`
	TRCERTFeed    bool   `yaml:"trcert_feed"`
	USOMCheck     bool   `yaml:"usom_check"`

	// Türk CDN/hosting sağlayıcıları subdomain takeover için
	TRTakeoverPatterns []string `yaml:"tr_takeover_patterns"`
}

// ── Port Profil Sabitleri (Sn1per kaynaklı, Şahin'de genişletildi) ─────────

const (
	// Sn1per QUICK_PORTS'tan alındı — kritik ~50 port
	PortsQuick = "21,22,23,25,53,80,110,111,135,137-139,143,161,162,443,445,512-514,993,995,1099,1433,1723,3306,3389,4444,5000,5432,5800,5900,6443,7001,8080,8081,8443,8888,9080,9200,9443,10000,10250"

	// Sn1per DEFAULT_PORTS'tan türetildi — ~500 yaygın port
	PortsDefault = "1,7,9,13,19,21-23,25,53,80,81,88,110-111,135,137-139,143,161,443-446,500,512-515,548,587,623,631,873,902,993,995,1433,1521,1720,1723,2049,2181,2375,2376,3000,3306,3389,4444,4848,5000,5432,5555,5900,6379,6443,7001,7070,8000,8008,8080-8083,8443,8888,9000,9090,9200,9300,9443,10000,10250,11211,27017,49152,50000"

	// Web-odaklı port listesi
	PortsWeb = "80,443,591,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000-8001,8008,8014,8042,8069,8080-8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090-9091,9200,9443,9800,9981,10000,10243,10443,12443,16080,18091,18092,20720,28017"

	// UDP portları
	PortsUDP = "53,67-69,88,123,135,137-139,161-162,389,445,500,514,520,631,1434,1900,2049,4500,5353,49152"

	// Full scan
	PortsFull = "T:1-65535,U:53,U:67-69,U:88,U:123,U:137-139,U:161-162,U:500,U:514,U:5353"
)

// TakeoverPatterns Sn1per'dan genişletildi + Türk sağlayıcılar eklendi.
var TakeoverPatterns = []string{
	// Global (Sn1per kaynaklı)
	"amazonaws", "cloudfront", "elasticbeanstalk", "s3.amazonaws",
	"github.io", "github.com", "bitbucket.io",
	"heroku.com", "herokudns.com",
	"wordpress.com", "wpengine.com",
	"squarespace.com", "tumblr.com",
	"shopify.com",
	"fastly.net", "fastlylb.net",
	"hubspot.net", "hubspotpagebuilder.com",
	"pantheon.io", "pantheonsite.io",
	"ghost.io",
	"helpscoutdocs.com",
	"statuspage.io",
	"desk.com",
	"zendesk.com",
	"teamwork.com",
	"uservoice.com",
	"surveygizmo.com",
	"pingdom.com",
	"unbounce.com",
	"instapage.com",
	"cargocollective.com",
	"azurewebsites.net", "cloudapp.net", "azureedge.net",
	"azure-api.net",
	"trafficmanager.net",
	"blob.core.windows.net",
	// Türkiye'ye özel
	"superonline.net",
	"turktelekom.com.tr",
	"turkcell.com.tr",
}

// ── Varsayılan Konfigürasyon ──────────────────────────────────────────────────

func Default() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		InstallDir:   filepath.Join(home, ".sahin"),
		WorkspaceDir: filepath.Join(home, ".sahin", "workspaces"),
		LogLevel:     "info",
		Scan: ScanConfig{
			QuickPorts:     PortsQuick,
			DefaultPorts:   PortsDefault,
			FullPorts:      PortsFull,
			WebPorts:       PortsWeb,
			UDPPorts:       PortsUDP,
			NmapOptionsNormal:  "-sV -Pn -O --osscan-guess --max-os-tries 1 -n -PE -v --max-retries 3 --min-rtt-timeout 500ms --max-rtt-timeout 3000ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000",
			NmapOptionsStealth: "-sS -Pn -T2 -n --max-retries 1 --min-rate 100 --max-rate 500",
			NmapOptionsFast:    "-sV -Pn -T4 -n --min-rate 1000 --max-rate 5000",
			WebBruteExtensions: "htm,html,asp,aspx,php,jsp,action,do,war,cfm,bak,cfg,sql,txt,md,zip,jar,conf,swp,xml,ini,yml,cgi,pl,js,json",
			MaxThreads:         10,
			MaxHosts:           2000,
			Timeout:            "60m",
			Screenshot:         true,
			JavaScriptAnalysis: true,
			OutOfScope:         []string{},
		},
		Notify: NotifyConfig{
			Events: NotifyEvents{
				ScanStart:   true,
				ScanFinish:  true,
				NewDomain:   true,
				PortChange:  true,
				Takeover:    true,
				NewFinding:  true,
				CriticalOnly: false,
			},
		},
		TR: TRConfig{
			BTKEnabled:         true,
			GovTREnum:          true,
			ShodanTRASNs:       true,
			TRCERTFeed:         true,
			USOMCheck:          true,
			TRTakeoverPatterns: TakeoverPatterns[len(TakeoverPatterns)-2:],
		},
	}
}

// Load config dosyasını okur. Dosya yoksa default döner.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".sahin", "config.yaml")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // default ile devam
		}
		return nil, fmt.Errorf("config okunamadı: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config parse hatası: %w", err)
	}
	return cfg, nil
}

// Save konfigürasyonu diske yazar.
func Save(cfg *Config, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
