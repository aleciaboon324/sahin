// Package notify implements the notification system.
// Sn1per'ın SLACK_NOTIFICATIONS_* değişkenlerinin temiz karşılığı.
// Desteklenen: Slack webhook, generic webhook (Discord, Teams vb.), dosya log.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/sahin-security/sahin/internal/config"
)

// EventType bildirim tetikleyen event tipleri.
// Sn1per'ın SLACK_NOTIFICATIONS_* değişkenlerinden türetildi.
type EventType string

const (
	EventScanStart   EventType = "scan_start"
	EventScanFinish  EventType = "scan_finish"
	EventNewDomain   EventType = "new_domain"    // SLACK_NOTIFICATIONS_DOMAINS_NEW
	EventPortChange  EventType = "port_change"   // SLACK_NOTIFICATIONS_NMAP_DIFF
	EventTakeover    EventType = "takeover"      // SLACK_NOTIFICATIONS_TAKEOVERS_NEW
	EventNewFinding  EventType = "new_finding"
	EventNewSubdomain EventType = "new_subdomain" // SLACK_NOTIFICATIONS_DIRSEARCH_NEW
)

// Notification gönderilecek bir bildirimi temsil eder.
type Notification struct {
	Event     EventType
	Target    string
	Message   string
	Severity  string
	Timestamp time.Time
}

// Notifier bildirim gönderir.
type Notifier struct {
	cfg     config.NotifyConfig
	logPath string
}

func New(cfg config.NotifyConfig, workspaceDir string) *Notifier {
	return &Notifier{
		cfg:     cfg,
		logPath: filepath.Join(workspaceDir, "scans", "notifications.txt"),
	}
}

// Send bir bildirimi yapılandırılmış tüm kanallara gönderir.
func (n *Notifier) Send(notif Notification) {
	notif.Timestamp = time.Now()

	// Event filtresi
	if !n.shouldSend(notif) {
		return
	}

	// Dosya log (her zaman)
	n.logToFile(notif)

	// Slack
	if n.cfg.Slack.Enabled && n.cfg.Slack.Token != "" {
		if err := n.sendSlack(notif); err != nil {
			color.Yellow("[notify] Slack hatası: %v", err)
		}
	}

	// Generic webhook (Discord, Teams, vb.)
	if n.cfg.Webhook.Enabled && n.cfg.Webhook.URL != "" {
		if err := n.sendWebhook(notif); err != nil {
			color.Yellow("[notify] Webhook hatası: %v", err)
		}
	}
}

// shouldSend event konfigürasyonuna göre gönderim kararı verir.
func (n *Notifier) shouldSend(notif Notification) bool {
	events := n.cfg.Events

	if events.CriticalOnly &&
		notif.Severity != "critical" &&
		notif.Severity != "high" {
		return false
	}

	switch notif.Event {
	case EventScanStart:
		return events.ScanStart
	case EventScanFinish:
		return events.ScanFinish
	case EventNewDomain, EventNewSubdomain:
		return events.NewDomain
	case EventPortChange:
		return events.PortChange
	case EventTakeover:
		return true // takeover her zaman bildirilir
	case EventNewFinding:
		return events.NewFinding
	}
	return true
}

// logToFile Sn1per'ın notifications_new.txt formatını taklit eder.
func (n *Notifier) logToFile(notif Notification) {
	if n.logPath == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(n.logPath), 0755)
	f, err := os.OpenFile(n.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	// Sn1per formatı: [sahin] •?((¯°·._.• Event: target (timestamp) •._.·°¯))؟•
	fmt.Fprintf(f, "[sahin] •?((¯°·._.• %s: %s (%s) •._.·°¯))؟•\n",
		notif.Event, notif.Target, notif.Timestamp.Format("2006-01-02 15:04"),
	)
	if notif.Message != "" {
		fmt.Fprintf(f, "  → %s\n", notif.Message)
	}
}

// sendSlack Slack Incoming Webhook'a mesaj gönderir.
func (n *Notifier) sendSlack(notif Notification) error {
	emoji := eventEmoji(notif.Event)
	text := fmt.Sprintf("%s *[%s]* `%s` — %s",
		emoji, notif.Event, notif.Target, notif.Message,
	)
	payload := map[string]string{"text": text}
	data, _ := json.Marshal(payload)

	resp, err := http.Post(
		fmt.Sprintf("https://hooks.slack.com/services/%s", n.cfg.Slack.Token),
		"application/json",
		bytes.NewReader(data),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// sendWebhook Discord/Teams/generic webhook'a mesaj gönderir.
func (n *Notifier) sendWebhook(notif Notification) error {
	payload := map[string]interface{}{
		"event":     notif.Event,
		"target":    notif.Target,
		"message":   notif.Message,
		"severity":  notif.Severity,
		"timestamp": notif.Timestamp.Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)

	resp, err := http.Post(n.cfg.Webhook.URL, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func eventEmoji(e EventType) string {
	switch e {
	case EventScanStart:
		return "🚀"
	case EventScanFinish:
		return "✅"
	case EventTakeover:
		return "🚨"
	case EventNewFinding:
		return "🔍"
	case EventPortChange:
		return "⚡"
	default:
		return "📡"
	}
}
