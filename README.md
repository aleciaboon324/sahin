# 🦅 Şahin — Pentest Otomasyon Motoru

> Sn1per + Osmedeus'tan ilham alan, Türkiye odaklı, YAML tabanlı pentest framework.

## Sn1per'dan Farkı

| Özellik | Sn1per | **Şahin** |
|---|---|---|
| Workflow tanımlama | Sabit | **YAML ile özelleştirilebilir** |
| TR-özel modüller | ❌ | **✅ BTK, .gov.tr, TR-CERT, USOM** |
| Web UI | Premium (ücretli) | **✅ Open-source React dashboard** |
| Paralel çalışma | Temel | **Goroutine pool + depends_on** |
| Dil | Bash | **Go (yüksek performans)** |

## Kurulum

```bash
git clone https://github.com/sahin-security/sahin
cd sahin
go build -o sahin ./cmd/sahin
./sahin version
```

## Kullanım

```bash
# Tam pentest
./sahin scan -t hedef.com -w workflows/full-pentest.yaml

# Türk kamu kurumu taraması
./sahin scan -t kurum.gov.tr -w workflows/tr-gov.yaml --stealth

# Sadece TR modülü
./sahin scan -t tcdd.gov.tr -m tr

# Hızlı keşif
./sahin scan -t hedef.com -w workflows/quick-recon.yaml -c 10

# Modülleri listele
./sahin list modules

# Workflow'ları listele
./sahin list workflows
```

## Modüller

| Modül | Araçlar | TR'ye özel |
|---|---|---|
| `recon` | whois, subfinder, amass, dnsx | - |
| `portscan` | nmap, masscan | - |
| `web` | nikto, whatweb, wafw00f, gowitness | - |
| `osint` | theHarvester, emailfinder | - |
| `tr` | BTK API, gov.tr enum, Shodan TR | **✅** |

## YAML Workflow Yazma

```yaml
kind: workflow
name: benim-metodolojim
description: Kişisel bug bounty workflow'um

modules:
  - name: recon
    params:
      cert_transparency: "true"

  - name: portscan
    depends_on: [recon]
    params:
      ports: "80,443,8080"

  - name: tr
    depends_on: [recon]
    condition: "target.endsWith('.tr')"
```

## Proje Yapısı

```
sahin/
├── cmd/sahin/          → CLI entry point
├── core/
│   ├── engine/         → YAML parser + scan context
│   ├── runner/         → goroutine pool
│   └── db/             → SQLite models (GORM)
├── modules/
│   ├── recon/          → DNS, subdomain, whois
│   ├── portscan/       → nmap wrapper
│   ├── web/            → web uygulama taraması
│   ├── osint/          → e-posta, metadata
│   └── tr/             → 🇹🇷 Türkiye'ye özel
├── workflows/          → Hazır YAML workflow'lar
├── api/                → Gin REST API
└── web/                → React dashboard
```

## Lisans

MIT — Yalnızca izinli hedeflerde kullanın.
