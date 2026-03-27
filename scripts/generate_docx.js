#!/usr/bin/env node
/**
 * Şahin Pentest Framework — DOCX Rapor Üretici
 * Kullanım: node generate_docx.js <results.json> <output.docx>
 */

const fs   = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle,
  WidthType, ShadingType, VerticalAlign, PageNumber, PageBreak,
  LevelFormat, HorizontalPositionRelativeFrom, VerticalPositionRelativeFrom,
} = require("docx");

// ── Sabitler ──────────────────────────────────────────────────────────────────
const PAGE_W    = 11906; // A4 DXA
const CONTENT_W = 9026;  // 1" margins
const COL1 = 1200;
const COL2 = 3000;
const COL3 = 3626;
const COL4 = 1200;
const COL_SUM = COL1 + COL2 + COL3 + COL4; // = CONTENT_W

const SEV_COLORS = {
  critical: { fg: "F85149", bg: "3D0F0E" },
  high:     { fg: "D29922", bg: "3D2B0A" },
  medium:   { fg: "E3B341", bg: "3D320B" },
  info:     { fg: "58A6FF", bg: "0D1F38" },
};

// ── Yardımcı ──────────────────────────────────────────────────────────────────
function data_load(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function sev_counts(findings) {
  const c = { critical:0, high:0, medium:0, info:0 };
  findings.forEach(f => { const s = f.severity||"info"; c[s] = (c[s]||0)+1; });
  return c;
}

const BORDER_CELL = {
  top:    { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
  bottom: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
  left:   { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
  right:  { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
};
const BORDER_NONE = {
  top:    { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
  bottom: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
  left:   { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
  right:  { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
};
function statItems(counts) {
  var data = [
    ["CRITICAL", counts.critical, "F85149"],
    ["HIGH",     counts.high,     "D29922"],
    ["MEDIUM",   counts.medium,   "E3B341"],
    ["INFO",     counts.info,     "58A6FF"],
  ];
  return data.map(function(item) {
    var lbl=item[0], val=item[1], col=item[2];
    return new TableCell({
      borders: BORDER_CELL,
      width:   { size:2256, type: WidthType.DXA },
      shading: { fill:"F6F8FA", type: ShadingType.CLEAR },
      margins: { top:120, bottom:120, left:80, right:80 },
      verticalAlign: VerticalAlign.CENTER,
      children: [
        new Paragraph({ alignment: AlignmentType.CENTER, children:[
          new TextRun({ text: String(val), bold:true, size:48, color:col, font:"Arial" }),
        ]}),
        new Paragraph({ alignment: AlignmentType.CENTER, children:[
          new TextRun({ text: lbl, size:14, color:"555555", font:"Arial" }),
        ]}),
      ],
    });
  });
}



function cell(children, opts={}) {
  return new TableCell({
    borders: opts.borders || BORDER_CELL,
    width:   { size: opts.width || CONTENT_W, type: WidthType.DXA },
    shading: opts.shading || { fill: "FFFFFF", type: ShadingType.CLEAR },
    margins: { top:80, bottom:80, left:120, right:120 },
    verticalAlign: VerticalAlign.CENTER,
    children,
  });
}

function para(text, opts={}) {
  return new Paragraph({
    alignment: opts.align || AlignmentType.LEFT,
    spacing:   opts.spacing || { before: 40, after: 40 },
    children: [
      new TextRun({
        text:  String(text),
        bold:  opts.bold  || false,
        size:  opts.size  || 18,
        color: opts.color || "000000",
        font:  "Arial",
      }),
    ],
  });
}

function sev_badge_para(sev) {
  const c = SEV_COLORS[sev] || SEV_COLORS.info;
  return new Paragraph({
    alignment: AlignmentType.CENTER,
    children: [
      new TextRun({ text: sev.toUpperCase(), bold:true, size:14, color: c.fg, font:"Arial" }),
    ],
  });
}

// ── Header / Footer ───────────────────────────────────────────────────────────
function make_header(target) {
  return new Header({
    children: [
      new Paragraph({
        border: { bottom: { style: BorderStyle.SINGLE, size:6, color:"58A6FF", space:1 } },
        spacing: { before:0, after:100 },
        children: [
          new TextRun({ text:"SAHIN Pentest Raporu", bold:true, size:18, color:"58A6FF", font:"Arial" }),
          new TextRun({ text:"   |   Hedef: " + target, size:16, color:"8B949E", font:"Arial" }),
        ],
      }),
    ],
  });
}

function make_footer() {
  return new Footer({
    children: [
      new Paragraph({
        border: { top: { style: BorderStyle.SINGLE, size:3, color:"30363D", space:1 } },
        spacing: { before:60, after:0 },
        alignment: AlignmentType.RIGHT,
        children: [
          new TextRun({ text:"Sayfa ", size:14, color:"8B949E", font:"Arial" }),
          new TextRun({ children:[PageNumber.CURRENT], size:14, color:"8B949E", font:"Arial" }),
          new TextRun({ text:" / ", size:14, color:"8B949E", font:"Arial" }),
          new TextRun({ children:[PageNumber.TOTAL_PAGES], size:14, color:"8B949E", font:"Arial" }),
        ],
      }),
    ],
  });
}

// ── Kapak ─────────────────────────────────────────────────────────────────────
function build_cover(data) {
  const target   = data.target || "";
  const findings = data.findings || [];
  const counts   = sev_counts(findings);
  const now      = new Date().toLocaleDateString("tr-TR");

  const children = [
    new Paragraph({ spacing:{before:1200, after:60}, children:[
      new TextRun({ text:"SAHIN", bold:true, size:72, color:"58A6FF", font:"Arial" }),
    ]}),
    new Paragraph({ spacing:{before:0, after:600}, children:[
      new TextRun({ text:"Pentest Otomasyon Motoru — Gizli Güvenlik Raporu", size:24, color:"8B949E", font:"Arial" }),
    ]}),
    new Paragraph({
      border: { bottom:{style:BorderStyle.SINGLE, size:6, color:"58A6FF", space:1} },
      spacing:{before:0, after:400},
      children:[new TextRun({text:"", size:4})],
    }),
    // Meta
    new Table({
      width: { size: CONTENT_W, type: WidthType.DXA },
      columnWidths: [3000, 6026],
      rows: [
        ["Hedef",          target],
        ["Tarama Tarihi",  data.scan_date || now],
        ["Rapor Tarihi",   now],
        ["Toplam Bulgu",   String(findings.length)],
      ].map(([k,v]) => new TableRow({ children:[
        cell([para(k, {bold:true, color:"555555"})], {borders:BORDER_NONE, width:3000}),
        cell([para(v)], {borders:BORDER_NONE, width:6026}),
      ]})),
    }),
    new Paragraph({ spacing:{before:400, after:200}, children:[new TextRun({text:"",size:4})] }),
    // Stat table
    new Table({
      width: { size: CONTENT_W, type: WidthType.DXA },
      columnWidths: [2256, 2256, 2257, 2257],
      rows: [
        new TableRow({ children: statItems(counts) }),
      ],
    }),
    new Paragraph({ spacing:{before:400, after:0}, children:[
      new TextRun({text:"BU RAPOR GİZLİDİR. Yalnızca yetkili güvenlik personeli görüntüleyebilir.", bold:true, size:16, color:"856404", font:"Arial"}),
    ]}),
    new Paragraph({ children:[new PageBreak()] }),
  ];
  return children;
}

// ── Özet Tablo ────────────────────────────────────────────────────────────────
function build_findings_table(data) {
  const findings = data.findings || [];
  const sevOrder = { critical:0, high:1, medium:2, info:3 };
  const sorted   = [...findings].sort((a,b) => (sevOrder[a.severity]||3)-(sevOrder[b.severity]||3));

  const header = new TableRow({
    tableHeader: true,
    children: ["#","Modül","Adım / Bulgu","Severity"].map((h,i) => new TableCell({
      borders: BORDER_CELL,
      width:   { size: [COL1,COL2,COL3,COL4][i], type: WidthType.DXA },
      shading: { fill:"21262D", type: ShadingType.CLEAR },
      margins: { top:80, bottom:80, left:120, right:120 },
      children:[
        new Paragraph({ children:[new TextRun({text:h, bold:true, size:16, color:"FFFFFF", font:"Arial"})] }),
      ],
    })),
  });

  const rows = sorted.map((f, i) => {
    const sev = f.severity || "info";
    const c   = SEV_COLORS[sev] || SEV_COLORS.info;
    const out = (f.output||"").length > 100 ? (f.output||"").slice(0,97)+"..." : (f.output||"");
    const bg  = i%2===0 ? "FFFFFF" : "F6F8FA";
    return new TableRow({ children:[
      cell([para(String(i+1), {size:16})],          {width:COL1, shading:{fill:bg, type:ShadingType.CLEAR}}),
      cell([para(f.module||"", {size:16})],         {width:COL2, shading:{fill:bg, type:ShadingType.CLEAR}}),
      cell([para(out, {size:15})],                  {width:COL3, shading:{fill:bg, type:ShadingType.CLEAR}}),
      cell([new Paragraph({alignment:AlignmentType.CENTER, children:[
        new TextRun({text:sev.toUpperCase(), bold:true, size:14, color:c.fg, font:"Arial"})
      ]})], {width:COL4, shading:{fill:bg, type:ShadingType.CLEAR}}),
    ]});
  });

  return [
    new Paragraph({ heading: HeadingLevel.HEADING_1, children:[
      new TextRun({text:"Bulgular", font:"Arial", size:28, bold:true, color:"58A6FF"})
    ]}),
    new Table({
      width: { size: CONTENT_W, type: WidthType.DXA },
      columnWidths: [COL1, COL2, COL3, COL4],
      rows: [header, ...rows],
    }),
    new Paragraph({ children:[new PageBreak()] }),
  ];
}

// ── Detaylar ──────────────────────────────────────────────────────────────────
function build_details(data) {
  const findings = data.findings || [];
  const sevOrder = { critical:0, high:1, medium:2, info:3 };
  const important = findings
    .filter(f => ["critical","high","medium"].includes(f.severity))
    .sort((a,b) => (sevOrder[a.severity]||3)-(sevOrder[b.severity]||3));

  if (!important.length) return [];

  const children = [
    new Paragraph({ heading: HeadingLevel.HEADING_1, children:[
      new TextRun({text:"Kritik ve Yüksek Riskli Bulgular (Detay)", font:"Arial", size:28, bold:true, color:"58A6FF"})
    ]}),
  ];

  important.forEach((f, i) => {
    const sev = f.severity || "info";
    const c   = SEV_COLORS[sev] || SEV_COLORS.info;
    children.push(
      new Table({
        width: { size: CONTENT_W, type: WidthType.DXA },
        columnWidths: [CONTENT_W],
        rows:[
          new TableRow({ children:[
            new TableCell({
              borders: BORDER_CELL,
              width: { size: CONTENT_W, type: WidthType.DXA },
              shading:{ fill: c.bg, type: ShadingType.CLEAR },
              margins:{ top:100, bottom:100, left:140, right:140 },
              children:[new Paragraph({ children:[
                new TextRun({text:`${i+1}. [${sev.toUpperCase()}] ${f.module||""}/${f.step||""}`, bold:true, size:18, color:c.fg, font:"Arial"}),
              ]})],
            }),
          ]}),
          new TableRow({ children:[
            new TableCell({
              borders: BORDER_CELL,
              width: { size: CONTENT_W, type: WidthType.DXA },
              shading:{ fill:"F6F8FA", type: ShadingType.CLEAR },
              margins:{ top:80, bottom:80, left:140, right:140 },
              children:[new Paragraph({ children:[
                new TextRun({text: f.output||"", size:15, font:"Courier New", color:"333333"}),
              ]})],
            }),
          ]}),
        ],
      }),
      new Paragraph({ spacing:{before:120, after:0}, children:[new TextRun({text:"", size:4})] })
    );
  });

  children.push(new Paragraph({ children:[new PageBreak()] }));
  return children;
}

// ── Öneriler ──────────────────────────────────────────────────────────────────
function build_recs(data) {
  const findings = data.findings || [];
  const recs = [];
  const all_out = findings.map(f => (f.output||"").toLowerCase()).join(" ");

  if (all_out.includes("telnet"))   recs.push(["Kritik","Telnet servisini (port 23) derhal devre dışı bırakın ve SSH ile değiştirin."]);
  if (all_out.includes("mongodb"))  recs.push(["Kritik","MongoDB'ye dışarıdan erişimi engelleyin, authentication'ı etkinleştirin."]);
  if (all_out.includes("redis"))    recs.push(["Kritik","Redis'e harici erişimi engelleyin, requirepass ile şifre belirleyin."]);
  if (all_out.includes("smb") || all_out.includes("445"))
    recs.push(["Yüksek","SMB (445) internete açık olmamalı. MS17-010 yamasını uygulayın."]);
  if (all_out.includes("dmarc"))    recs.push(["Orta","DMARC politikasını 'reject' olarak güncelleyin."]);
  if (all_out.includes("hsts"))     recs.push(["Orta","Strict-Transport-Security (HSTS) header ekleyin."]);
  if (all_out.includes("ftp"))      recs.push(["Yüksek","FTP yerine SFTP kullanın, anonim girişi devre dışı bırakın."]);
  if (!recs.length) {
    recs.push(["Genel","Düzenli güvenlik taramaları yapın."]);
    recs.push(["Genel","Tüm güvenlik güncellemelerini zamanında uygulayın."]);
  }

  const SEV_C = { Kritik:"F85149", Yüksek:"D29922", Orta:"E3B341", Genel:"58A6FF" };

  return [
    new Paragraph({ heading: HeadingLevel.HEADING_1, children:[
      new TextRun({text:"Öneriler", font:"Arial", size:28, bold:true, color:"58A6FF"})
    ]}),
    new Table({
      width: { size: CONTENT_W, type: WidthType.DXA },
      columnWidths: [1800, 7226],
      rows: recs.map(([sev, text], i) => new TableRow({ children:[
        new TableCell({
          borders: BORDER_CELL,
          width:  { size:1800, type: WidthType.DXA },
          shading:{ fill: i%2===0?"FFFFFF":"F6F8FA", type: ShadingType.CLEAR },
          margins:{ top:80, bottom:80, left:120, right:120 },
          verticalAlign: VerticalAlign.CENTER,
          children:[new Paragraph({alignment:AlignmentType.CENTER, children:[
            new TextRun({text:sev, bold:true, size:15, color:SEV_C[sev]||"58A6FF", font:"Arial"}),
          ]})],
        }),
        new TableCell({
          borders: BORDER_CELL,
          width:  { size:7226, type: WidthType.DXA },
          shading:{ fill: i%2===0?"FFFFFF":"F6F8FA", type: ShadingType.CLEAR },
          margins:{ top:80, bottom:80, left:120, right:120 },
          children:[new Paragraph({ children:[
            new TextRun({text, size:16, font:"Arial"}),
          ]})],
        }),
      ]})),
    }),
  ];
}

// ── Ana Fonksiyon ─────────────────────────────────────────────────────────────
async function generate(input_json, output_docx) {
  const data = data_load(input_json);
  const target = data.target || "hedef";

  const sections = [{
    properties: {
      page: {
        size: { width: PAGE_W, height: 16838 },
        margin: { top:1134, right:1134, bottom:1134, left:1134 },
      },
    },
    headers: { default: make_header(target) },
    footers: { default: make_footer() },
    children: [
      ...build_cover(data),
      ...build_findings_table(data),
      ...build_details(data),
      ...build_recs(data),
    ],
  }];

  const doc = new Document({
    styles: {
      default: {
        document: { run: { font:"Arial", size:18 } },
      },
      paragraphStyles: [
        {
          id:"Heading1", name:"Heading 1", basedOn:"Normal", next:"Normal", quickFormat:true,
          run:  { size:28, bold:true, font:"Arial", color:"58A6FF" },
          paragraph: { spacing:{ before:280, after:120 }, outlineLevel:0 },
        },
      ],
    },
    sections,
  });

  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(output_docx, buffer);
  console.log("[OK] DOCX rapor olusturuldu:", output_docx);
}

const [,, inp, out] = process.argv;
if (!inp || !out) { console.error("Kullanim: generate_docx.js <results.json> <output.docx>"); process.exit(1); }
generate(inp, out).catch(e => { console.error(e); process.exit(1); });