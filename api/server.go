package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/sahin-security/sahin/core/engine"
	"github.com/sahin-security/sahin/core/runner"
	"github.com/sahin-security/sahin/internal/workspace"
)

// ── ScanJob ───────────────────────────────────────────────────────────────────

type ScanJob struct {
	ID         string       `json:"id"`
	Target     string       `json:"target"`
	Module     string       `json:"module,omitempty"`
	Workflow   string       `json:"workflow,omitempty"`
	Status     string       `json:"status"`
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt *time.Time   `json:"finished_at,omitempty"`
	Results    []ResultJSON `json:"results"` // her zaman array, asla null
	mu         sync.Mutex
}

// ResultJSON JSON-safe sonuç (engine.Result'un hata alanı olmadan)
type ResultJSON struct {
	Module   string `json:"module"`
	Step     string `json:"step"`
	Output   string `json:"output"`
	Severity string `json:"severity"`
}

func toJSON(r engine.Result) ResultJSON {
	return ResultJSON{
		Module:   r.Module,
		Step:     r.Step,
		Output:   r.Output,
		Severity: r.Severity,
	}
}

func (j *ScanJob) addResult(r engine.Result) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Results = append(j.Results, toJSON(r))
}

func (j *ScanJob) setStatus(s string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Status = s
}

func (j *ScanJob) finish(err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	j.FinishedAt = &now
	if err != nil {
		j.Status = "failed"
	} else {
		j.Status = "done"
	}
}

// ── Job Store ─────────────────────────────────────────────────────────────────

type JobStore struct {
	mu   sync.RWMutex
	jobs map[string]*ScanJob
}

var Store = &JobStore{jobs: map[string]*ScanJob{}}

func (s *JobStore) Add(job *ScanJob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[job.ID] = job
}

func (s *JobStore) Get(id string) (*ScanJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	return j, ok
}

func (s *JobStore) List() []*ScanJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	jobs := make([]*ScanJob, 0, len(s.jobs))
	for _, j := range s.jobs {
		jobs = append(jobs, j)
	}
	return jobs
}

// ── SSE Hub ───────────────────────────────────────────────────────────────────

type SSEClient struct {
	jobID string
	ch    chan string
}

type SSEHub struct {
	mu      sync.Mutex
	clients map[string][]*SSEClient
}

var Hub = &SSEHub{clients: map[string][]*SSEClient{}}

func (h *SSEHub) Subscribe(jobID string) *SSEClient {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := &SSEClient{jobID: jobID, ch: make(chan string, 256)}
	h.clients[jobID] = append(h.clients[jobID], c)
	return c
}

func (h *SSEHub) Unsubscribe(c *SSEClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	list := h.clients[c.jobID]
	for i, cl := range list {
		if cl == c {
			h.clients[c.jobID] = append(list[:i], list[i+1:]...)
			break
		}
	}
}

func (h *SSEHub) Broadcast(jobID string, r ResultJSON) {
	h.mu.Lock()
	defer h.mu.Unlock()
	data, _ := json.Marshal(r)
	msg := fmt.Sprintf("data: %s\n\n", data)
	for _, c := range h.clients[jobID] {
		select {
		case c.ch <- msg:
		default:
		}
	}
}

// ── Routes ────────────────────────────────────────────────────────────────────

func SetupRoutes(mux *http.ServeMux, wsBaseDir string) {
	cors := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == "OPTIONS" {
				w.WriteHeader(204)
				return
			}
			h(w, r)
		}
	}

	mux.HandleFunc("/api/scan/start", cors(handleStartScan(wsBaseDir)))
	mux.HandleFunc("/api/scan/list", cors(handleListScans))
	mux.HandleFunc("/api/scan/", cors(handleGetScan))
	mux.HandleFunc("/api/workspaces", cors(handleListWorkspaces(wsBaseDir)))
	mux.HandleFunc("/api/modules", cors(handleListModules))
	mux.HandleFunc("/api/events/", handleSSE)
	mux.HandleFunc("/", handleUI)
}

// ── POST /api/scan/start ──────────────────────────────────────────────────────

func handleStartScan(wsBaseDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}

		var req struct {
			Target   string `json:"target"`
			Module   string `json:"module"`
			Workflow string `json:"workflow"`
			Stealth  bool   `json:"stealth"`
			Threads  int    `json:"threads"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		if req.Target == "" {
			http.Error(w, "target gerekli", 400)
			return
		}
		if req.Module == "" && req.Workflow == "" {
			http.Error(w, "module veya workflow gerekli", 400)
			return
		}
		if req.Threads == 0 {
			req.Threads = 5
		}

		// Job oluştur — Results her zaman boş slice (asla nil)
		jobID := fmt.Sprintf("%s-%d",
			strings.NewReplacer(".", "-", "/", "-").Replace(req.Target),
			time.Now().Unix(),
		)
		job := &ScanJob{
			ID:        jobID,
			Target:    req.Target,
			Module:    req.Module,
			Workflow:  req.Workflow,
			Status:    "pending",
			StartedAt: time.Now(),
			Results:   []ResultJSON{}, // boş slice, asla null
		}
		Store.Add(job)

		// Workspace
		ws := workspace.New(req.Target, req.Target, wsBaseDir)
		_ = ws.Init()

		// ScanContext
		sc := engine.NewScanContext(req.Target, req.Target, wsBaseDir)
		sc.Stealth = req.Stealth
		sc.Threads = req.Threads

		// Arka planda çalıştır
		go func() {
			job.setStatus("running")

			// Result toplayıcı — ayrı goroutine, done kanalıyla senkronize
			collectorDone := make(chan struct{})
			go func() {
				defer close(collectorDone)
				for result := range sc.Results {
					job.addResult(result)
					rj := toJSON(result)
					Hub.Broadcast(jobID, rj)
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
			defer cancel()

			r2 := runner.New(sc)
			var runErr error

			if req.Module != "" {
				runErr = r2.RunModule(ctx, req.Module)
			} else {
				wf, err := engine.ParseWorkflow(req.Workflow)
				if err != nil {
					runErr = err
				} else {
					runErr = r2.RunWorkflow(ctx, wf)
				}
			}

			// Kanalı kapat ve toplayıcının bitmesini bekle
			close(sc.Results)
			<-collectorDone

			job.finish(runErr)

			// Tamamlandı bildirimi
			Hub.Broadcast(jobID, ResultJSON{
				Module:   "system",
				Step:     "scan-complete",
				Output:   fmt.Sprintf("Tarama tamamlandi — %d bulgu", len(job.Results)),
				Severity: "info",
			})

			color.Green("[API] %s tamamlandi — %d bulgu", jobID, len(job.Results))
		}()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"job_id": jobID,
			"status": "started",
		})
	}
}

// ── GET /api/scan/list ────────────────────────────────────────────────────────

func handleListScans(w http.ResponseWriter, r *http.Request) {
	jobs := Store.List()
	// nil slice yerine boş slice garantisi
	if jobs == nil {
		jobs = []*ScanJob{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jobs)
}

// ── GET /api/scan/<id> ────────────────────────────────────────────────────────

func handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	if id == "" || id == "list" {
		handleListScans(w, r)
		return
	}
	job, ok := Store.Get(id)
	if !ok {
		http.Error(w, "job bulunamadi", 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

// ── GET /api/workspaces ───────────────────────────────────────────────────────

func handleListWorkspaces(wsBaseDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, _ := os.ReadDir(wsBaseDir)
		wss := []map[string]string{}
		for _, e := range entries {
			if e.IsDir() {
				wss = append(wss, map[string]string{"name": e.Name()})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(wss)
	}
}

// ── GET /api/modules ──────────────────────────────────────────────────────────

func handleListModules(w http.ResponseWriter, r *http.Request) {
	mods := []map[string]string{
		{"name": "tr", "desc": "BTK, gov.tr enum, TR-CERT, USOM"},
		{"name": "portscan", "desc": "Nmap port taramasi, servis fingerprint"},
		{"name": "web", "desc": "Header, WAF, nikto, JS analizi, ffuf"},
		{"name": "osint", "desc": "theHarvester, GitHub dork, Wayback, breach"},
		{"name": "recon", "desc": "Subdomain, crt.sh, zone transfer, takeover"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mods)
}

// ── GET /api/events/<jobID> — SSE ────────────────────────────────────────────

func handleSSE(w http.ResponseWriter, r *http.Request) {
	jobID := strings.TrimPrefix(r.URL.Path, "/api/events/")

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE desteklenmiyor", 500)
		return
	}

	// Mevcut sonuçları önce gönder
	if job, exists := Store.Get(jobID); exists {
		job.mu.Lock()
		for _, result := range job.Results {
			data, _ := json.Marshal(result)
			fmt.Fprintf(w, "data: %s\n\n", data)
		}
		// Job bittiyse scan-complete gönder
		if job.Status == "done" || job.Status == "failed" {
			done := ResultJSON{Module: "system", Step: "scan-complete",
				Output: fmt.Sprintf("Tarama tamamlandi — %d bulgu", len(job.Results)), Severity: "info"}
			data, _ := json.Marshal(done)
			fmt.Fprintf(w, "data: %s\n\n", data)
		}
		job.mu.Unlock()
		flusher.Flush()
	}

	client := Hub.Subscribe(jobID)
	defer Hub.Unsubscribe(client)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-client.ch:
			if !ok {
				return
			}
			fmt.Fprint(w, msg)
			flusher.Flush()
		}
	}
}

// ── GET / — UI ────────────────────────────────────────────────────────────────

func handleUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, uiHTML)
}

// ── serve CLI için yardımcı ───────────────────────────────────────────────────

func Serve(addr, wsBaseDir string) error {
	mux := http.NewServeMux()
	SetupRoutes(mux, wsBaseDir)
	color.Cyan("Sahin Web UI: http://localhost%s", addr)
	return http.ListenAndServe(addr, mux)
}

// workspaceDir yardımcı
func workspaceBaseDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sahin", "workspaces")
}
