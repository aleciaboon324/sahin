#!/usr/bin/env python3
"""
Şahin Pentest Framework — PDF Rapor Üretici
Kullanım: python3 generate_pdf.py <results.json> <output.pdf>
"""

import json
import sys
import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.colors import (
    HexColor, white, black
)
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib import colors

# ── Renk Paleti ───────────────────────────────────────────────────────────────
BG_DARK     = HexColor("#0d1117")
BG_CARD     = HexColor("#161b22")
BORDER      = HexColor("#30363d")
TEXT        = HexColor("#e6edf3")
TEXT2       = HexColor("#8b949e")
BLUE        = HexColor("#58a6ff")
GREEN       = HexColor("#3fb950")
RED         = HexColor("#f85149")
ORANGE      = HexColor("#d29922")
YELLOW      = HexColor("#e3b341")
PURPLE      = HexColor("#bc8cff")

SEV_COLORS = {
    "critical": (HexColor("#f85149"), HexColor("#3d0f0e")),
    "high":     (HexColor("#d29922"), HexColor("#3d2b0a")),
    "medium":   (HexColor("#e3b341"), HexColor("#3d320b")),
    "info":     (HexColor("#58a6ff"), HexColor("#0d1f38")),
}

# ── Sayfa Düzeni ──────────────────────────────────────────────────────────────
PAGE_W, PAGE_H = A4
MARGIN = 2 * cm


def load_data(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def sev_color(sev):
    return SEV_COLORS.get(sev, SEV_COLORS["info"])


def make_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "CoverTitle",
        fontName="Helvetica-Bold",
        fontSize=32,
        textColor=BLUE,
        spaceAfter=6,
        alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        "CoverSub",
        fontName="Helvetica",
        fontSize=14,
        textColor=TEXT2,
        spaceAfter=4,
        alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        "SectionTitle",
        fontName="Helvetica-Bold",
        fontSize=14,
        textColor=BLUE,
        spaceBefore=18,
        spaceAfter=8,
        borderPad=4,
    ))
    styles.add(ParagraphStyle(
        "Body",
        fontName="Helvetica",
        fontSize=9,
        textColor=black,
        spaceAfter=4,
        leading=14,
    ))
    styles.add(ParagraphStyle(
        "CodePentest",
        fontName="Courier",
        fontSize=8,
        textColor=HexColor("#333333"),
        backColor=HexColor("#f6f8fa"),
        spaceAfter=2,
        leading=12,
        leftIndent=8,
        rightIndent=8,
        spaceBefore=2,
    ))
    styles.add(ParagraphStyle(
        "Meta",
        fontName="Helvetica",
        fontSize=9,
        textColor=HexColor("#555555"),
        spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        "TableCell",
        fontName="Helvetica",
        fontSize=8,
        textColor=black,
        leading=11,
    ))
    styles.add(ParagraphStyle(
        "TableHeader",
        fontName="Helvetica-Bold",
        fontSize=8,
        textColor=white,
        leading=11,
    ))
    return styles


# ── Header/Footer ─────────────────────────────────────────────────────────────

def make_header_footer(canvas, doc, target, report_date):
    canvas.saveState()
    w, h = A4

    # Header
    canvas.setFillColor(HexColor("#161b22"))
    canvas.rect(0, h - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)
    canvas.setFillColor(BLUE)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(MARGIN, h - 0.8*cm, "SAHIN Pentest Raporu")
    canvas.setFillColor(TEXT2)
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - MARGIN, h - 0.8*cm, f"Hedef: {target}")

    # Footer
    canvas.setFillColor(HexColor("#161b22"))
    canvas.rect(0, 0, w, 1*cm, fill=1, stroke=0)
    canvas.setFillColor(TEXT2)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(MARGIN, 0.35*cm, f"Gizli — {report_date}")
    canvas.drawRightString(w - MARGIN, 0.35*cm, f"Sayfa {doc.page}")

    canvas.restoreState()


# ── Kapak Sayfası ─────────────────────────────────────────────────────────────

def build_cover(data, styles):
    story = []
    target   = data.get("target", "")
    scan_at  = data.get("scan_date", datetime.now().strftime("%d.%m.%Y %H:%M"))
    findings = data.get("findings", [])

    counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    story.append(Spacer(1, 3*cm))

    # Logo / başlık
    story.append(Paragraph("SAHIN", styles["CoverTitle"]))
    story.append(Paragraph("Pentest Otomasyon Motoru — Gizli Güvenlik Raporu", styles["CoverSub"]))
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=BLUE, spaceAfter=20))

    # Meta bilgi
    meta = [
        ["Hedef",          target],
        ["Tarama Tarihi",  scan_at],
        ["Rapor Tarihi",   datetime.now().strftime("%d.%m.%Y %H:%M")],
        ["Toplam Bulgu",   str(len(findings))],
    ]
    meta_table = Table(meta, colWidths=[4*cm, 12*cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",    (1,0), (1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0), (-1,-1), 10),
        ("TEXTCOLOR",   (0,0), (0,-1), HexColor("#555555")),
        ("TEXTCOLOR",   (1,0), (1,-1), black),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("LINEBELOW",   (0,0), (-1,-2), 0.3, HexColor("#eeeeee")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 1*cm))

    # Özet istatistik kartları
    stat_data = [
        [
            _stat_cell("CRITICAL", counts["critical"], "#f85149"),
            _stat_cell("HIGH",     counts["high"],     "#d29922"),
            _stat_cell("MEDIUM",   counts["medium"],   "#e3b341"),
            _stat_cell("INFO",     counts["info"],     "#58a6ff"),
        ]
    ]
    stat_table = Table(stat_data, colWidths=[4*cm]*4)
    stat_table.setStyle(TableStyle([
        ("ALIGN",       (0,0), (-1,-1), "CENTER"),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [HexColor("#f6f8fa")]),
        ("BOX",         (0,0), (0,0), 0.5, HexColor("#f85149")),
        ("BOX",         (1,0), (1,0), 0.5, HexColor("#d29922")),
        ("BOX",         (2,0), (2,0), 0.5, HexColor("#e3b341")),
        ("BOX",         (3,0), (3,0), 0.5, HexColor("#58a6ff")),
        ("TOPPADDING",  (0,0), (-1,-1), 14),
        ("BOTTOMPADDING",(0,0), (-1,-1), 14),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("RIGHTPADDING",(0,0), (-1,-1), 8),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 1.5*cm))

    # Uyarı kutusu
    warning = Table(
        [["BU RAPOR GİZLİDİR. Yalnızca yetkili güvenlik personeli tarafından görüntülenebilir."]],
        colWidths=[PAGE_W - 2*MARGIN]
    )
    warning.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), HexColor("#fff3cd")),
        ("TEXTCOLOR",   (0,0), (-1,-1), HexColor("#856404")),
        ("FONTNAME",    (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("BOX",         (0,0), (-1,-1), 0.5, HexColor("#ffc107")),
        ("TOPPADDING",  (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0), (-1,-1), 10),
        ("LEFTPADDING", (0,0), (-1,-1), 12),
    ]))
    story.append(warning)
    story.append(PageBreak())
    return story


def _stat_cell(label, count, color_hex):
    return Paragraph(
        f'<font color="{color_hex}" size="28"><b>{count}</b></font><br/>'
        f'<font color="#555555" size="8">{label}</font>',
        ParagraphStyle("sc", alignment=TA_CENTER, leading=20)
    )


# ── Yönetici Özeti ────────────────────────────────────────────────────────────

def build_executive_summary(data, styles):
    story = []
    findings = data.get("findings", [])
    target = data.get("target", "")
    counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    for f in findings:
        counts[f.get("severity","info")] = counts.get(f.get("severity","info"),0) + 1

    story.append(Paragraph("1. Yönetici Özeti", styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=10))

    summary = (
        f"Bu rapor, <b>{target}</b> hedefine yönelik gerçekleştirilen otomatik pentest taramasının "
        f"bulgularını özetlemektedir. Tarama sonucunda toplam <b>{len(findings)}</b> bulgu tespit edilmiştir. "
        f"Bu bulgular arasında <b>{counts['critical']} kritik</b>, "
        f"<b>{counts['high']} yüksek</b>, "
        f"<b>{counts['medium']} orta</b> ve "
        f"<b>{counts['info']} bilgi</b> seviyesinde bulgu yer almaktadır."
    )
    story.append(Paragraph(summary, styles["Body"]))
    story.append(Spacer(1, 0.5*cm))

    if counts["critical"] > 0 or counts["high"] > 0:
        risk_text = (
            "Tespit edilen kritik ve yüksek seviye bulgular, sistemin güvenlik durumunun "
            "acilen gözden geçirilmesini gerektirmektedir. Bu bulgular yetkisiz erişim, "
            "veri sızıntısı ve sistem ele geçirme gibi risklere yol açabilir."
        )
        risk_box = Table(
            [[Paragraph(risk_text, ParagraphStyle("rb", fontName="Helvetica", fontSize=9, textColor=HexColor("#721c24"), leading=14))]],
            colWidths=[PAGE_W - 2*MARGIN]
        )
        risk_box.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), HexColor("#f8d7da")),
            ("BOX",          (0,0), (-1,-1), 0.5, HexColor("#f5c6cb")),
            ("TOPPADDING",   (0,0), (-1,-1), 10),
            ("BOTTOMPADDING",(0,0), (-1,-1), 10),
            ("LEFTPADDING",  (0,0), (-1,-1), 12),
        ]))
        story.append(risk_box)

    story.append(PageBreak())
    return story


# ── Bulgular Tablosu ──────────────────────────────────────────────────────────

def build_findings_table(data, styles):
    story = []
    findings = data.get("findings", [])

    story.append(Paragraph("2. Bulgular", styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=10))

    if not findings:
        story.append(Paragraph("Hiçbir bulgu tespit edilmedi.", styles["Body"]))
        return story

    # Severity sırasıyla sırala
    sev_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    findings_sorted = sorted(findings, key=lambda f: sev_order.get(f.get("severity","info"), 3))

    # Tablo başlığı
    header = [
        Paragraph("#",        styles["TableHeader"]),
        Paragraph("Modül",    styles["TableHeader"]),
        Paragraph("Adım",     styles["TableHeader"]),
        Paragraph("Bulgu",    styles["TableHeader"]),
        Paragraph("Severity", styles["TableHeader"]),
    ]
    rows = [header]

    for i, f in enumerate(findings_sorted, 1):
        sev = f.get("severity", "info")
        fg, bg = sev_color(sev)
        sev_para = Paragraph(
            f'<font color="{fg.hexval()}" size="8"><b>{sev.upper()}</b></font>',
            ParagraphStyle("sc", alignment=TA_CENTER, leading=11)
        )
        output = f.get("output", "")
        if len(output) > 120:
            output = output[:117] + "..."
        rows.append([
            Paragraph(str(i), styles["TableCell"]),
            Paragraph(f.get("module", ""), styles["TableCell"]),
            Paragraph(f.get("step", ""), styles["TableCell"]),
            Paragraph(output, styles["TableCell"]),
            sev_para,
        ])

    col_w = [1*cm, 2.5*cm, 4*cm, 8.5*cm, 2*cm]
    table = Table(rows, colWidths=col_w, repeatRows=1)
    table.setStyle(TableStyle([
        # Header
        ("BACKGROUND",   (0,0), (-1,0), HexColor("#21262d")),
        ("TEXTCOLOR",    (0,0), (-1,0), white),
        ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 8),
        ("TOPPADDING",   (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ("LEFTPADDING",  (0,0), (-1,-1), 5),
        ("RIGHTPADDING", (0,0), (-1,-1), 5),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[white, HexColor("#f6f8fa")]),
        ("GRID",         (0,0), (-1,-1), 0.3, HexColor("#dddddd")),
        ("VALIGN",       (0,0), (-1,-1), "TOP"),
        ("ALIGN",        (0,0), (0,-1), "CENTER"),
        ("ALIGN",        (4,0), (4,-1), "CENTER"),
    ]))
    story.append(table)
    story.append(PageBreak())
    return story


# ── Detaylı Bulgular ──────────────────────────────────────────────────────────

def build_findings_detail(data, styles):
    story = []
    findings = data.get("findings", [])
    sev_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    findings_sorted = sorted(
        [f for f in findings if f.get("severity") in ("critical","high","medium")],
        key=lambda f: sev_order.get(f.get("severity","info"), 3)
    )

    if not findings_sorted:
        return story

    story.append(Paragraph("3. Kritik ve Yüksek Riskli Bulgular (Detay)", styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=10))

    for i, f in enumerate(findings_sorted, 1):
        sev  = f.get("severity", "info")
        fg, bg_hex = sev_color(sev)

        # Başlık kutusu
        title_text = f'{i}. [{sev.upper()}] {f.get("module","")}/{f.get("step","")}'
        title_box = Table(
            [[Paragraph(title_text, ParagraphStyle(
                "fh", fontName="Helvetica-Bold", fontSize=10,
                textColor=fg, leading=14
            ))]],
            colWidths=[PAGE_W - 2*MARGIN]
        )
        title_box.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), bg_hex),
            ("BOX",          (0,0), (-1,-1), 0.5, fg),
            ("TOPPADDING",   (0,0), (-1,-1), 8),
            ("BOTTOMPADDING",(0,0), (-1,-1), 8),
            ("LEFTPADDING",  (0,0), (-1,-1), 12),
        ]))
        story.append(title_box)

        # Bulgu içeriği
        story.append(Paragraph(f.get("output",""), styles["CodePentest"]))
        story.append(Spacer(1, 0.4*cm))

    return story


# ── Öneriler ──────────────────────────────────────────────────────────────────

def build_recommendations(data, styles):
    story = []
    findings = data.get("findings", [])
    story.append(Paragraph("4. Öneriler", styles["SectionTitle"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=10))

    # Otomatik öneri üret
    recs = []
    modules_found = set(f.get("module","") for f in findings)
    sevs = set(f.get("severity","") for f in findings)

    if any("telnet" in f.get("output","").lower() for f in findings):
        recs.append(("Kritik", "Telnet servisini (port 23) derhal devre dışı bırakın. SSH ile değiştirin."))
    if any("mongodb" in f.get("output","").lower() for f in findings):
        recs.append(("Kritik", "MongoDB'ye (port 27017) dışarıdan erişimi güvenlik duvarı ile engelleyin ve authentication'ı etkinleştirin."))
    if any("redis" in f.get("output","").lower() for f in findings):
        recs.append(("Kritik", "Redis'e (port 6379) harici erişimi engelleyin, requirepass ile şifre belirleyin."))
    if any("smb" in f.get("output","").lower() or "445" in f.get("output","") for f in findings):
        recs.append(("Yüksek", "SMB (port 445) internete açık olmamalı. Güvenlik duvarı kuralı ekleyin ve MS17-010 yamasını uygulayın."))
    if any("dmarc" in f.get("output","").lower() for f in findings):
        recs.append(("Orta", "DMARC politikasını 'reject' olarak güncelleyin: v=DMARC1; p=reject"))
    if any("hsts" in f.get("output","").lower() for f in findings):
        recs.append(("Orta", "Strict-Transport-Security (HSTS) header'ını tüm HTTP yanıtlarına ekleyin."))
    if any("csp" in f.get("output","").lower() for f in findings):
        recs.append(("Orta", "Content-Security-Policy header'ı ile XSS saldırılarına karşı koruma sağlayın."))
    if any("ftp" in f.get("output","").lower() for f in findings):
        recs.append(("Yüksek", "FTP (port 21) yerine SFTP kullanın. Anonim girişi devre dışı bırakın."))

    if not recs:
        recs.append(("Genel", "Düzenli güvenlik taramaları yapın ve açık portları minimize edin."))
        recs.append(("Genel", "Tüm güvenlik güncellemelerini zamanında uygulayın."))
        recs.append(("Genel", "Güvenlik duvarı kurallarını gözden geçirin."))

    for sev_label, rec_text in recs:
        color_map = {"Kritik": "#f85149", "Yüksek": "#d29922", "Orta": "#e3b341", "Genel": "#58a6ff"}
        c = color_map.get(sev_label, "#58a6ff")
        row = Table(
            [[
                Paragraph(f'<font color="{c}" size="8"><b>{sev_label}</b></font>',
                          ParagraphStyle("rl", fontName="Helvetica-Bold", fontSize=8, alignment=TA_CENTER, leading=11)),
                Paragraph(rec_text, styles["Body"])
            ]],
            colWidths=[2*cm, PAGE_W - 2*MARGIN - 2*cm]
        )
        row.setStyle(TableStyle([
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("LINEBELOW",    (0,0), (-1,-1), 0.3, HexColor("#eeeeee")),
            ("TOPPADDING",   (0,0), (-1,-1), 6),
            ("BOTTOMPADDING",(0,0), (-1,-1), 6),
            ("LEFTPADDING",  (0,0), (-1,-1), 4),
        ]))
        story.append(row)

    return story


# ── Ana Fonksiyon ─────────────────────────────────────────────────────────────

def generate(input_json, output_pdf):
    pdfmetrics.registerFont(TTFont('DejaVu', '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'))
    pdfmetrics.registerFont(TTFont('DejaVu-Bold', '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'))
    data = load_data(input_json)
    styles = make_styles()

    target      = data.get("target", "hedef")
    report_date = datetime.now().strftime("%d.%m.%Y")

    doc = SimpleDocTemplate(
        output_pdf,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
        title=f"Sahin Pentest Raporu — {target}",
        author="Sahin Security",
        subject="Gizli Pentest Raporu",
    )

    story = []
    story += build_cover(data, styles)
    story += build_executive_summary(data, styles)
    story += build_findings_table(data, styles)
    story += build_findings_detail(data, styles)
    story += build_recommendations(data, styles)

    def header_footer(canvas, doc):
        make_header_footer(canvas, doc, target, report_date)

    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    print(f"[OK] PDF rapor oluşturuldu: {output_pdf}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Kullanim: generate_pdf.py <results.json> <output.pdf>")
        sys.exit(1)
    generate(sys.argv[1], sys.argv[2])