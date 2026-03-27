<div align="center">

```
 ██████╗  █████╗ ██╗  ██╗██╗███╗   ██╗
██╔════╝ ██╔══██╗██║  ██║██║████╗  ██║
╚█████╗  ███████║███████║██║██╔██╗ ██║
 ╚═══██╗ ██╔══██║██╔══██║██║██║╚██╗██║
██████╔╝ ██║  ██║██║  ██║██║██║ ╚████║
╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
```

**Go-based automated penetration testing framework**

[![Go](https://img.shields.io/badge/Go-1.22-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)](https://kali.org)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()

*YAML-driven workflow engine · Real-time Web UI · Multi-format reporting · Turkey-specific recon*

</div>

---

## Overview

Şahin is an automated penetration testing framework written in Go, inspired by [Sn1per](https://github.com/1N3/Sn1per) and [Osmedeus](https://github.com/j3ssie/osmedeus). It is designed with a focus on the Turkish internet infrastructure and provides features unavailable in existing tools — including BTK domain queries, `.gov.tr` subdomain enumeration, TR-CERT/USOM feed integration, and BGP hijacking risk analysis based on historical Turkish incidents.

### Why Şahin over Sn1per?

| Feature | Sn1per | **Şahin** |
|---|---|---|
| Language | Bash | **Go (high performance, concurrent)** |
| Workflow definition | Hardcoded | **Declarative YAML with `depends_on` & parallel execution** |
| Turkey-specific modules | ❌ | **✅ BTK, .gov.tr, TR-CERT, USOM, BGP hijack** |
| Web UI | Paid (Pro) | **✅ Open-source React dashboard** |
| Reporting | Basic text | **✅ HTML + PDF + DOCX** |
| Network attack detection | ❌ | **✅ ARP spoofing, UDP amplification, OS fingerprint** |
| Notifications | Slack only | **✅ Slack + generic webhook (Discord, Teams)** |

---

## Modules

| Module | Description |
|---|---|
| `tr` | BTK domain queries, `.gov.tr`/`.edu.tr` subdomain enumeration, crt.sh, subdomain takeover detection, USOM malicious list check (47K+ entries), TR-CERT feed |
| `portscan` | nmap wrapper with XML parsing, service fingerprinting, OS detection, port diff (detects newly opened ports), NSE script execution |
| `web` | HTTP header security analysis, WAF/CDN detection, technology fingerprinting (whatweb), Nikto, JavaScript secret scanning, directory brute-force (ffuf), screenshot (gowitness) |
| `osint` | theHarvester, email format detection, GitHub dork via API, Google dork URL generation, Shodan, Wayback Machine (CDX API), HIBP breach check |
| `recon` | Subdomain enumeration (subfinder, amass), DNS records (A/MX/NS/TXT/DMARC), zone transfer attempt, certificate transparency (crt.sh JSON API), subdomain takeover check, httpx probing |
| `netattack` | UDP amplification service detection (DNS/NTP/SNMP/Memcached/SSDP), SYN cookie status, OS fingerprinting via TTL, ARP spoofing risk, BGP hijacking risk analysis (TR-specific), ICMP vulnerability assessment, IP fragmentation behavior |

---

## Architecture

```
sahin/
├── cmd/sahin/              # CLI entry point (cobra)
├── core/
│   ├── engine/             # YAML workflow parser, ScanContext
│   ├── runner/             # Goroutine pool, depends_on resolution, parallel execution
│   └── db/                 # SQLite models (GORM) — Workspace, Asset, Finding, ScanJob
├── internal/
│   ├── cli/                # Cobra commands: scan, run, serve, list, version
│   ├── config/             # Typed config system (177 fields → Go structs + YAML profiles)
│   ├── workspace/          # Structured scan output directory management
│   ├── report/             # HTML/PDF/DOCX report generation
│   ├── notify/             # Slack + webhook notification system
│   └── tools/              # External binary dependency checker
├── modules/
│   ├── tr/                 # Turkey-specific recon
│   ├── portscan/           # nmap wrapper
│   ├── web/                # Web application scanning
│   ├── osint/              # Open-source intelligence
│   ├── recon/              # Subdomain & DNS recon
│   └── netattack/          # Network attack surface analysis
├── api/                    # Go stdlib HTTP server + SSE for real-time UI
├── scripts/
│   ├── generate_pdf.py     # reportlab PDF generator (Turkish font support)
│   └── generate_docx.js    # docx-js Word document generator
└── workflows/              # Pre-built YAML workflow definitions
    ├── full-pentest.yaml
    ├── tr-gov.yaml
    └── quick-recon.yaml
```

---

## Installation

**Requirements:** Go 1.22+, Python 3, Node.js 18+, nmap

```bash
git clone https://github.com/memo-13-byte/sahin.git
cd sahin

# Build
go build -o sahin cmd/sahin/main.go

# Install report dependencies
pip install reportlab --break-system-packages
npm install -g docx

# Optional: install to PATH
sudo mv sahin /usr/local/bin/sahin
```

---

## Usage

```bash
# Single module
sahin scan -t tcdd.gov.tr -m tr
sahin scan -t tcdd.gov.tr -m portscan
sahin scan -t tcdd.gov.tr -m netattack

# Workflow (modules run in dependency order, parallel where safe)
sahin scan -t tcdd.gov.tr -w workflows/full-pentest.yaml

# Turkey government targets
sahin scan -t kurum.gov.tr -w workflows/tr-gov.yaml --stealth

# Quick recon (~10 min)
sahin scan -t target.com -w workflows/quick-recon.yaml -c 10

# Start Web UI + REST API
sahin serve --port 3000
# Open: http://localhost:3000

# List available modules and workflows
sahin list modules
sahin list workflows
```

---

## Workflows

Workflows are declarative YAML files that chain modules with dependency resolution and parallel execution:

```yaml
kind: workflow
name: full-pentest
description: Full pentest — recon → portscan → web → osint (parallel)

modules:
  - name: tr
  - name: portscan
    depends_on: [tr]
  - name: web
    depends_on: [portscan]
    parallel: true
  - name: osint
    parallel: true        # runs concurrently with web
  - name: netattack
    depends_on: [portscan]
    condition: "stealth == false"
```

Write your own methodology once, run it at scale.

---

## Reporting

After each scan, Şahin generates three report formats automatically:

```bash
~/.sahin/workspaces/<target>/reports/
├── sahin-<target>-<timestamp>.html   # Dark-themed, filterable, searchable
├── sahin-<target>-<timestamp>.pdf    # Professional pentest report (reportlab)
└── sahin-<target>-<timestamp>.docx   # Word document (docx-js)
```

Reports include: cover page, executive summary, findings table (sorted by severity), critical/high detail section with evidence, and auto-generated remediation recommendations.

---

## Web UI

```bash
sahin serve
```

| Page | Features |
|---|---|
| Dashboard | Severity counters, active scan indicators, recent scan history |
| New Scan | Target input, module/workflow selector, stealth toggle, thread control |
| Live Scan | Real-time terminal output via Server-Sent Events (SSE), per-severity counters |
| All Scans | Job history with critical/high badge counts, click to open live view |
| Modules | Module descriptions and categories |

---

## Turkey-Specific Features

Şahin includes recon capabilities specifically designed for Turkish targets that no existing framework provides:

- **BTK Domain Queries** — Bilgi Teknolojileri ve İletişim Kurumu registry lookup
- **`.gov.tr` / `.edu.tr` Subdomain Enumeration** — 25 government-specific subdomain patterns (portal, sso, vpn, otomasyon, ihale, sgk, vergi...)
- **USOM Malicious List** — Real-time check against USOM's 47,000+ entry threat feed
- **TR-CERT Feed** — RSS-based vulnerability advisory ingestion
- **BGP Hijacking Risk Analysis** — Historical incident awareness (Türk Telekom 2014: hijacked 8.8.8.8, OpenDNS; Pakistan 2008: hijacked YouTube) with RPKI/BGPMon monitoring links
- **Turkish ASN Coverage** — Türk Telekom (AS9121), Turkcell (AS15897), Vodafone TR (AS47331), Türksat (AS8517), Superonline (AS34984)
- **Subdomain Takeover Patterns** — Extended with Turkish CDN/hosting providers

---

## Notification System

Configure `~/.sahin/config.yaml` to receive alerts on scan events:

```yaml
notify:
  slack:
    enabled: true
    token: "your-webhook-token"
  webhook:
    enabled: true
    url: "https://discord.com/api/webhooks/..."
  events:
    new_domain: true
    port_change: true
    takeover: true       # always notified regardless of filter
    critical_only: false
```

---

## Configuration

Copy and edit the example config:

```bash
cp config.example.yaml ~/.sahin/config.yaml
```

Key settings: API keys (Shodan, Censys, GitHub, Hunter.io), nmap options per scan mode, port profiles (quick/default/web/full), out-of-scope list, OpenVAS/Nessus/Burp integration.

---

## Legal

This tool is intended for use only against systems you own or have explicit written authorization to test. Unauthorized use against systems without permission is illegal.

The authors assume no liability for misuse of this software.

---

## Acknowledgements

- [Sn1per](https://github.com/1N3/Sn1per) — architecture inspiration, port profiles, loot directory structure
- [Osmedeus](https://github.com/j3ssie/osmedeus) — YAML workflow engine concept
- [BBM456 Network Security](https://cs.hacettepe.edu.tr) — Hacettepe University course content (netattack module)
- ProjectDiscovery — subfinder, httpx, dnsx, nuclei

---

<div align="center">
Made at <a href="https://cs.hacettepe.edu.tr">Hacettepe University</a> · Spring 2026
</div>