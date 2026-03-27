package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"net/http"

	"github.com/fatih/color"
	"github.com/sahin-security/sahin/api"
	"github.com/sahin-security/sahin/core/engine"
	"github.com/sahin-security/sahin/core/runner"
	"github.com/sahin-security/sahin/internal/workspace"
	_ "github.com/sahin-security/sahin/modules/netattack"
	_ "github.com/sahin-security/sahin/modules/osint"
	_ "github.com/sahin-security/sahin/modules/portscan"
	_ "github.com/sahin-security/sahin/modules/tr"
	_ "github.com/sahin-security/sahin/modules/web"
	"github.com/spf13/cobra"
)

var (
	target, workflow, module, ws, output string
	threads                              int
	verbose, stealth                     bool
)

var rootCmd = &cobra.Command{
	Use:   "sahin",
	Short: "Şahin — Türkiye odaklı pentest otomasyon motoru",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Hedefe karşı workflow veya modül çalıştır",
	Example: `  sahin scan -t tcdd.gov.tr -m tr
  sahin scan -t kurum.gov.tr -w workflows/tr-gov.yaml --stealth`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("hedef belirtilmedi: -t <hedef>")
		}
		if workflow == "" && module == "" {
			return fmt.Errorf("workflow (-w) veya modül (-m) belirtilmeli")
		}

		color.Cyan(`
 ██████╗  █████╗ ██╗  ██╗██╗███╗   ██╗
██╔════╝ ██╔══██╗██║  ██║██║████╗  ██║
╚█████╗  ███████║███████║██║██╔██╗ ██║
 ╚═══██╗ ██╔══██║██╔══██║██║██║╚██╗██║
██████╔╝ ██║  ██║██║  ██║██║██║ ╚████║
╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
`)
		color.Green("[+] Hedef    : %s", target)
		if module != "" {
			color.Green("[+] Modül    : %s", module)
		}
		if workflow != "" {
			color.Green("[+] Workflow : %s", workflow)
		}
		color.Green("[+] Threads  : %d", threads)
		if stealth {
			color.Yellow("[!] Stealth mod aktif")
		}

		// Workspace
		homeDir, _ := os.UserHomeDir()
		wsBaseDir := filepath.Join(homeDir, ".sahin", "workspaces")
		wsName := ws
		if wsName == "" {
			wsName = target
		}

		w := workspace.New(wsName, target, wsBaseDir)
		if err := w.Init(); err != nil {
			return fmt.Errorf("workspace oluşturulamadı: %w", err)
		}
		color.Cyan("[*] Workspace : %s", filepath.Join(wsBaseDir, wsName))

		// ScanContext
		sc := engine.NewScanContext(target, wsName, w.BaseDir)
		sc.Threads = threads
		sc.Stealth = stealth
		sc.Verbose = verbose

		// Result toplayıcı
		done := make(chan struct{})
		go func() {
			defer close(done)
			for result := range sc.Results {
				if result.Error != nil {
					color.Red("  [!] %s: %v", result.Step, result.Error)
					continue
				}
				switch result.Severity {
				case "critical", "high":
					color.Red("  [!!!] %s", result.Output)
				case "medium":
					color.Yellow("  [!]  %s", result.Output)
				default:
					color.White("  [+]  %s", result.Output)
				}
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
		defer cancel()

		r := runner.New(sc)
		start := time.Now()

		var runErr error
		if module != "" {
			color.Cyan("\n[*] Modül çalıştırılıyor: %s\n", module)
			runErr = r.RunModule(ctx, module)
		} else {
			wf, err := engine.ParseWorkflow(workflow)
			if err != nil {
				return fmt.Errorf("workflow parse hatası: %w", err)
			}
			runErr = r.RunWorkflow(ctx, wf)
		}

		close(sc.Results)
		<-done

		elapsed := time.Since(start).Round(time.Second)
		if runErr != nil {
			color.Red("\n[!] Hata (%v): %v", elapsed, runErr)
			return runErr
		}
		color.Green("\n[✓] Tarama tamamlandı (%v)", elapsed)
		color.Cyan("[*] Sonuçlar: %s", filepath.Join(wsBaseDir, wsName))
		return nil
	},
}

var runCmd = &cobra.Command{Use: "run", Short: "scan alias", RunE: scanCmd.RunE}

var listCmd = &cobra.Command{Use: "list", Short: "Modül ve workflow'ları listele"}

var listModulesCmd = &cobra.Command{
	Use: "modules", Short: "Modülleri listele",
	Run: func(cmd *cobra.Command, args []string) {
		color.Cyan("\n[*] Mevcut modüller:\n")
		mods := []struct{ name, desc string }{
			{"recon", "Whois, DNS enum, subdomain keşfi, zone transfer"},
			{"portscan", "Nmap/masscan port taraması, servis fingerprint"},
			{"web", "Nikto, whatweb, wafw00f, screenshot, dir bruteforce"},
			{"osint", "theHarvester, e-posta/metadata toplama"},
			{"netattack", "BBM456 bazlı: UDP amp, BGP hijack, ARP spoof, ICMP, OS fingerprint"},
			{"tr", "BTK sorgulama, .gov.tr enum, Shodan TR, TR-CERT, USOM"},
		}
		for _, m := range mods {
			fmt.Printf("  %-12s %s\n", color.GreenString(m.name), m.desc)
		}
	},
}

var listWorkflowsCmd = &cobra.Command{
	Use: "workflows", Short: "Workflow'ları listele",
	Run: func(cmd *cobra.Command, args []string) {
		color.Cyan("\n[*] Mevcut workflow'lar:\n")
		flows := []struct{ file, desc string }{
			{"workflows/full-pentest.yaml", "Tam pentest (recon → port → web → vuln)"},
			{"workflows/tr-gov.yaml", "Türk kamu kurumlarına özel tarama"},
			{"workflows/quick-recon.yaml", "Hızlı keşif (stealth, 10 dk)"},
		}
		for _, f := range flows {
			fmt.Printf("  %-38s %s\n", color.GreenString(f.file), f.desc)
		}
	},
}

var versionCmd = &cobra.Command{
	Use: "version", Short: "Versiyon bilgisi",
	Run: func(cmd *cobra.Command, args []string) {
		color.Cyan("Şahin v0.1.0 — github.com/sahin-security/sahin")
		color.White("Build: dev | Go: 1.22")
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&target, "target", "t", "", "Hedef alan adı veya IP")
	rootCmd.PersistentFlags().StringVarP(&workflow, "workflow", "w", "", "YAML workflow dosyası")
	rootCmd.PersistentFlags().StringVarP(&module, "module", "m", "", "Tekil modül adı")
	rootCmd.PersistentFlags().StringVarP(&ws, "workspace", "s", "", "Workspace adı")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "Çıktı dizini")
	rootCmd.PersistentFlags().IntVarP(&threads, "threads", "c", 5, "Paralel goroutine sayısı")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Detaylı çıktı")
	rootCmd.PersistentFlags().BoolVar(&stealth, "stealth", false, "Stealth mod")

	rootCmd.AddCommand(scanCmd, runCmd, listCmd, versionCmd)
	listCmd.AddCommand(listModulesCmd, listWorkflowsCmd)
}

// ── serve komutu ─────────────────────────────────────────────────────────────

var servePort string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Web UI ve REST API sunucusunu başlat",
	Example: `  sahin serve
  sahin serve --port 8080`,
	RunE: func(cmd *cobra.Command, args []string) error {
		homeDir, _ := os.UserHomeDir()
		wsBaseDir := filepath.Join(homeDir, ".sahin", "workspaces")

		mux := http.NewServeMux()
		api.SetupRoutes(mux, wsBaseDir)

		addr := ":" + servePort
		color.Cyan("🦅 Şahin Web UI başlatıldı")
		color.Green("[*] Dashboard : http://localhost%s", addr)
		color.Green("[*] API       : http://localhost%s/api/", addr)
		color.White("[*] Durdurmak için Ctrl+C\n")

		return http.ListenAndServe(addr, mux)
	},
}

func init() {
	serveCmd.Flags().StringVar(&servePort, "port", "3000", "Web UI port numarası")
	rootCmd.AddCommand(serveCmd)
}
