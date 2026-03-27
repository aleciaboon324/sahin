// Package report generates HTML, PDF, and DOCX reports.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Finding struct {
	Module   string `json:"module"`
	Step     string `json:"step"`
	Output   string `json:"output"`
	Severity string `json:"severity"`
}

type ScanReport struct {
	Target     string    `json:"target"`
	Workspace  string    `json:"workspace"`
	ScanDate   string    `json:"scan_date"`
	Findings   []Finding `json:"findings"`
	startedAt  time.Time
	finishedAt time.Time
}

func New(target, workspace string) *ScanReport {
	return &ScanReport{
		Target:    target,
		Workspace: workspace,
		ScanDate:  time.Now().Format("02.01.2006 15:04"),
		Findings:  []Finding{},
		startedAt: time.Now(),
	}
}

func (r *ScanReport) Add(module, step, output, severity string) {
	r.Findings = append(r.Findings, Finding{Module: module, Step: step, Output: output, Severity: severity})
}

func (r *ScanReport) Finish() { r.finishedAt = time.Now() }

func (r *ScanReport) counts() (critical, high, medium, info int) {
	for _, f := range r.Findings {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		default:
			info++
		}
	}
	return
}

func sanitize(s string) string {
	rep := strings.NewReplacer(".", "-", "/", "-", ":", "-", "*", "all")
	return rep.Replace(s)
}

// ── JSON ──────────────────────────────────────────────────────────────────────

func (r *ScanReport) SaveJSON(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ── PDF ───────────────────────────────────────────────────────────────────────

func (r *ScanReport) SavePDF(outputPath, scriptDir string) error {
	jsonPath := strings.TrimSuffix(outputPath, ".pdf") + "-data.json"
	if err := r.SaveJSON(jsonPath); err != nil {
		return fmt.Errorf("JSON: %w", err)
	}
	scriptPath := filepath.Join(scriptDir, "generate_pdf.py")
	if _, err := os.Stat(scriptPath); err != nil {
		return fmt.Errorf("script bulunamadi: %s", scriptPath)
	}
	python := "python3"
	if _, err := exec.LookPath(python); err != nil {
		python = "python"
	}
	out, err := exec.Command(python, scriptPath, jsonPath, outputPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("PDF hatasi: %v — %s", err, out)
	}
	return nil
}

// ── DOCX ──────────────────────────────────────────────────────────────────────

func (r *ScanReport) SaveDOCX(outputPath, scriptDir string) error {
	jsonPath := strings.TrimSuffix(outputPath, ".docx") + "-data.json"
	if err := r.SaveJSON(jsonPath); err != nil {
		return fmt.Errorf("JSON: %w", err)
	}
	scriptPath := filepath.Join(scriptDir, "generate_docx.js")
	if _, err := os.Stat(scriptPath); err != nil {
		return fmt.Errorf("script bulunamadi: %s", scriptPath)
	}
	if _, err := exec.LookPath("node"); err != nil {
		return fmt.Errorf("node.js bulunamadi")
	}
	out, err := exec.Command("node", scriptPath, jsonPath, outputPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("DOCX hatasi: %v — %s", err, out)
	}
	return nil
}

// ── SaveAll ───────────────────────────────────────────────────────────────────

type SaveResult struct {
	HTML   string
	PDF    string
	DOCX   string
	Errors []string
}

func (r *ScanReport) SaveAll(reportsDir, scriptDir string) SaveResult {
	_ = os.MkdirAll(reportsDir, 0755)
	ts := time.Now().Format("20060102-1504")
	base := fmt.Sprintf("sahin-%s-%s", sanitize(r.Target), ts)
	res := SaveResult{}

	htmlPath := filepath.Join(reportsDir, base+".html")
	if err := r.SaveHTML(htmlPath); err != nil {
		res.Errors = append(res.Errors, "HTML: "+err.Error())
	} else {
		res.HTML = htmlPath
	}

	pdfPath := filepath.Join(reportsDir, base+".pdf")
	if err := r.SavePDF(pdfPath, scriptDir); err != nil {
		res.Errors = append(res.Errors, "PDF: "+err.Error())
	} else {
		res.PDF = pdfPath
	}

	docxPath := filepath.Join(reportsDir, base+".docx")
	if err := r.SaveDOCX(docxPath, scriptDir); err != nil {
		res.Errors = append(res.Errors, "DOCX: "+err.Error())
	} else {
		res.DOCX = docxPath
	}

	return res
}

// ── HTML ──────────────────────────────────────────────────────────────────────

func (r *ScanReport) SaveHTML(outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(outputPath, []byte(r.renderHTML()), 0644)
}

func severityBadge(sev string) string {
	switch sev {
	case "critical":
		return `<span class="badge critical">critical</span>`
	case "high":
		return `<span class="badge high">high</span>`
	case "medium":
		return `<span class="badge medium">medium</span>`
	default:
		return `<span class="badge info">info</span>`
	}
}

func he(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func (r *ScanReport) renderHTML() string {
	critical, high, medium, info := r.counts()
	elapsed := r.finishedAt.Sub(r.startedAt).Round(time.Second)
	var rows, cards strings.Builder
	for _, f := range r.Findings {
		rows.WriteString(fmt.Sprintf(`<tr><td>%s</td><td><code>%s</code></td><td class="out">%s</td><td>%s</td></tr>`,
			he(f.Module), he(f.Step), he(f.Output), severityBadge(f.Severity)))
	}
	mm := map[string][]Finding{}
	for _, f := range r.Findings {
		mm[f.Module] = append(mm[f.Module], f)
	}
	for mod, fs := range mm {
		mc, mh, ms, mi := 0, 0, 0, 0
		for _, f := range fs {
			switch f.Severity {
			case "critical":
				mc++
			case "high":
				mh++
			case "medium":
				ms++
			default:
				mi++
			}
		}
		cards.WriteString(fmt.Sprintf(`<div class="mc"><b class="mn">%s</b><div><span class="badge critical">%d</span><span class="badge high">%d</span><span class="badge medium">%d</span><span class="badge info">%d</span></div><small>%d bulgu</small></div>`, mod, mc, mh, ms, mi, len(fs)))
	}
	return fmt.Sprintf(htmlTmpl, r.Target, r.Target,
		r.startedAt.Format("02.01.2006 15:04"), elapsed, len(r.Findings),
		critical, high, medium, info, len(r.Findings),
		cards.String(), rows.String(), time.Now().Format("02.01.2006 15:04"))
}

const htmlTmpl = `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><title>Sahin — %s</title><style>:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#e6edf3;--text2:#8b949e;--green:#3fb950;--red:#f85149;--orange:#d29922;--yellow:#e3b341;--blue:#58a6ff;--purple:#bc8cff;}*{box-sizing:border-box;margin:0;padding:0;}body{background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;font-size:14px;padding:32px;}.hdr{display:flex;align-items:center;gap:20px;margin-bottom:32px;padding-bottom:24px;border-bottom:1px solid var(--border);}.logo{font-size:26px;font-weight:700;color:var(--blue);}.hdr h1{font-size:20px;font-weight:600;}.meta{color:var(--text2);font-size:13px;margin-top:4px;}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;margin-bottom:32px;}.sc{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:20px;text-align:center;}.sc .n{font-size:36px;font-weight:700;}.sc .l{color:var(--text2);font-size:11px;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px;}.sc.c .n{color:var(--red);}.sc.h .n{color:var(--orange);}.sc.m .n{color:var(--yellow);}.sc.i .n{color:var(--blue);}.sc.t .n{color:var(--green);}.mods{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-bottom:32px;}.mc{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px;}.mn{display:block;font-size:15px;color:var(--blue);margin-bottom:8px;}.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;text-transform:uppercase;margin-right:4px;}.badge.critical{background:rgba(248,81,73,.2);color:#f85149;border:1px solid rgba(248,81,73,.4);}.badge.high{background:rgba(210,153,34,.2);color:#d29922;border:1px solid rgba(210,153,34,.4);}.badge.medium{background:rgba(227,179,65,.2);color:#e3b341;border:1px solid rgba(227,179,65,.4);}.badge.info{background:rgba(88,166,255,.2);color:#58a6ff;border:1px solid rgba(88,166,255,.4);}.fb{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;}.fb input{background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:7px 12px;border-radius:6px;font-size:13px;width:280px;outline:none;}.fb button{background:var(--bg3);border:1px solid var(--border);color:var(--text2);padding:6px 14px;border-radius:6px;cursor:pointer;font-size:13px;}.fb button.a,.fb button:hover{border-color:var(--blue);color:var(--blue);}table{width:100%%;border-collapse:collapse;background:var(--bg2);border:1px solid var(--border);border-radius:8px;overflow:hidden;}th{background:var(--bg3);padding:10px 14px;text-align:left;font-size:12px;text-transform:uppercase;color:var(--text2);border-bottom:1px solid var(--border);}td{padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:top;}tr:hover td{background:rgba(88,166,255,.04);}td.out{font-family:monospace;font-size:12px;color:var(--text2);word-break:break-all;max-width:480px;}code{background:var(--bg3);padding:2px 6px;border-radius:4px;font-size:12px;font-family:monospace;color:var(--purple);}.ftr{margin-top:48px;padding-top:24px;border-top:1px solid var(--border);color:var(--text2);font-size:12px;display:flex;justify-content:space-between;}</style></head><body><div class="hdr"><div class="logo">Sahin</div><div><h1>%s</h1><div class="meta">Tarama: %s | Sure: %v | Toplam: %d bulgu</div></div></div><div class="stats"><div class="sc c"><div class="n">%d</div><div class="l">Critical</div></div><div class="sc h"><div class="n">%d</div><div class="l">High</div></div><div class="sc m"><div class="n">%d</div><div class="l">Medium</div></div><div class="sc i"><div class="n">%d</div><div class="l">Info</div></div><div class="sc t"><div class="n">%d</div><div class="l">Toplam</div></div></div><div class="mods">%s</div><div class="fb"><input id="q" placeholder="Bulgu ara..." oninput="f()"><button class="a" onclick="fs('all',this)">Tumu</button><button onclick="fs('critical',this)">Critical</button><button onclick="fs('high',this)">High</button><button onclick="fs('medium',this)">Medium</button><button onclick="fs('info',this)">Info</button></div><table id="tbl"><thead><tr><th>Modul</th><th>Adim</th><th>Bulgu</th><th>Severity</th></tr></thead><tbody>%s</tbody></table><div class="ftr"><span>Sahin v0.1.0</span><span>Rapor: %s</span></div><script>var sv='all';function fs(s,b){sv=s;document.querySelectorAll('.fb button').forEach(x=>x.classList.remove('a'));b.classList.add('a');f();}function f(){var q=document.getElementById('q').value.toLowerCase();document.querySelectorAll('#tbl tbody tr').forEach(r=>{var t=r.textContent.toLowerCase();var s=r.querySelector('td:last-child').textContent.toLowerCase();r.style.display=(sv==='all'||s.includes(sv))&&(!q||t.includes(q))?'':'none';});}</script></body></html>`
