package api

// uiHTML is the single-file React dashboard.
const uiHTML = `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sahin Pentest Dashboard</title>
<script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#e6edf3;--text2:#8b949e;--green:#3fb950;--red:#f85149;--orange:#d29922;--yellow:#e3b341;--blue:#58a6ff;--purple:#bc8cff;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:var(--bg2)}::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.layout{display:flex;height:100vh;}
.sidebar{width:220px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;}
.main{flex:1;overflow:hidden;display:flex;flex-direction:column;}
.sidebar-logo{padding:20px 16px;border-bottom:1px solid var(--border);}
.logo{font-size:20px;font-weight:700;color:var(--blue);}
.ver{font-size:11px;color:var(--text2);margin-top:2px;}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 16px;cursor:pointer;color:var(--text2);transition:all 0.15s;border-left:3px solid transparent;font-size:13px;}
.nav-item:hover{background:var(--bg3);color:var(--text);}
.nav-item.active{background:var(--bg3);color:var(--blue);border-left-color:var(--blue);}
.sidebar-bottom{margin-top:auto;padding:16px;border-top:1px solid var(--border);font-size:11px;color:var(--text2);}
.topbar{padding:16px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;background:var(--bg2);}
.topbar-title{font-size:16px;font-weight:600;}
.content{flex:1;overflow-y:auto;padding:24px;}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px;}
.card-title{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:var(--text2);margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:24px;}
.stat{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px;}
.stat .val{font-size:28px;font-weight:700;}
.stat .lbl{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:0.5px;margin-top:4px;}
.stat.critical .val{color:var(--red)}.stat.high .val{color:var(--orange)}.stat.medium .val{color:var(--yellow)}.stat.info .val{color:var(--blue)}.stat.total .val{color:var(--green)}
.form-group{margin-bottom:14px;}
.form-group label{display:block;font-size:12px;color:var(--text2);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px;}
.form-group input,.form-group select{width:100%;background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:14px;outline:none;transition:border 0.15s;}
.form-group input:focus,.form-group select:focus{border-color:var(--blue);}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.form-check{display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px;color:var(--text2);}
.btn{padding:9px 18px;border-radius:6px;border:none;cursor:pointer;font-size:14px;font-weight:500;transition:all 0.15s;display:inline-flex;align-items:center;gap:6px;}
.btn-primary{background:var(--blue);color:#fff;}.btn-primary:hover{background:#4d9fe0;}.btn-primary:disabled{background:var(--border);color:var(--text2);cursor:not-allowed;}
.btn-ghost{background:var(--bg3);color:var(--text2);border:1px solid var(--border);}.btn-ghost:hover{border-color:var(--blue);color:var(--blue);}
.btn-sm{padding:5px 12px;font-size:12px;}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;text-transform:uppercase;}
.b-crit{background:rgba(248,81,73,0.15);color:#f85149;border:1px solid rgba(248,81,73,0.3);}
.b-high{background:rgba(210,153,34,0.15);color:#d29922;border:1px solid rgba(210,153,34,0.3);}
.b-med{background:rgba(227,179,65,0.15);color:#e3b341;border:1px solid rgba(227,179,65,0.3);}
.b-info{background:rgba(88,166,255,0.15);color:#58a6ff;border:1px solid rgba(88,166,255,0.3);}
.b-run{background:rgba(63,185,80,0.15);color:#3fb950;border:1px solid rgba(63,185,80,0.3);}
.b-done{background:rgba(139,148,158,0.1);color:var(--text2);border:1px solid var(--border);}
.b-fail{background:rgba(248,81,73,0.1);color:var(--red);border:1px solid rgba(248,81,73,0.2);}
.terminal{background:#0a0c10;border:1px solid var(--border);border-radius:8px;padding:16px;font-family:'SFMono-Regular',Consolas,monospace;font-size:12px;height:440px;overflow-y:auto;}
.tl{line-height:1.8;white-space:pre-wrap;word-break:break-all;}
.tl.critical{color:var(--red)}.tl.high{color:var(--orange)}.tl.medium{color:var(--yellow)}.tl.info{color:var(--text2)}.tl.system{color:var(--green)}
.cursor{display:inline-block;width:8px;height:14px;background:var(--green);animation:blink 1s step-end infinite;vertical-align:middle;}
@keyframes blink{50%{opacity:0}}
table{width:100%;border-collapse:collapse;}
th{text-align:left;padding:8px 12px;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--text2);border-bottom:1px solid var(--border);white-space:nowrap;}
td{padding:10px 12px;border-bottom:1px solid rgba(48,54,61,0.5);vertical-align:middle;}
tr:hover td{background:rgba(88,166,255,0.03);}
td code{background:var(--bg3);padding:2px 6px;border-radius:4px;font-size:11px;font-family:monospace;color:var(--purple);}
.pulse{width:8px;height:8px;background:var(--green);border-radius:50%;display:inline-block;animation:pulse 1.5s ease-in-out infinite;}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.5;transform:scale(0.8)}}
.empty{text-align:center;padding:48px;color:var(--text2);}
.empty .icon{font-size:48px;margin-bottom:12px;}
.alert{padding:12px 16px;border-radius:6px;margin-bottom:16px;font-size:13px;}
.alert-success{background:rgba(63,185,80,0.1);border:1px solid rgba(63,185,80,0.3);color:var(--green);}
.alert-error{background:rgba(248,81,73,0.1);border:1px solid rgba(248,81,73,0.3);color:var(--red);}
.fade-in{animation:fi 0.2s ease-in;}
@keyframes fi{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
</style>
</head>
<body>
<div id="root"></div>
<script type="text/babel">
const {useState, useEffect, useRef} = React;

function timeSince(d) {
  var s = Math.floor((Date.now() - new Date(d)) / 1000);
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s/60) + "dk";
  return Math.floor(s/3600) + "sa";
}

function StatusBadge({s}) {
  var cls = {running:"b-run",done:"b-done",failed:"b-fail",pending:"b-done"}[s] || "b-info";
  var lbl = {running:"Caliyor",done:"Tamam",failed:"Hata",pending:"Bekliyor"}[s] || s;
  return React.createElement("span", {className:"badge " + cls}, lbl);
}

function SevBadge({s}) {
  var cls = {critical:"b-crit",high:"b-high",medium:"b-med"}[s] || "b-info";
  return React.createElement("span", {className:"badge " + cls}, s);
}

function Sidebar({page, setPage}) {
  var items = [
    {id:"dashboard", icon:"PANO", label:"Dashboard"},
    {id:"scan",      icon:"TARA", label:"Yeni Tarama"},
    {id:"jobs",      icon:"LISTE", label:"Taramalar"},
    {id:"modules",   icon:"MODUL", label:"Moduller"},
  ];
  return React.createElement("div", {className:"sidebar"},
    React.createElement("div", {className:"sidebar-logo"},
      React.createElement("div", {className:"logo"}, "Sahin"),
      React.createElement("div", {className:"ver"}, "v0.1.0 Pentest Engine")
    ),
    items.map(function(i) {
      return React.createElement("div", {
        key: i.id,
        className: "nav-item" + (page === i.id ? " active" : ""),
        onClick: function() { setPage(i.id); }
      }, i.label);
    }),
    React.createElement("div", {className:"sidebar-bottom"}, "Turkiye odakli pentest motoru")
  );
}

function Dashboard({jobs, setPage}) {
  var all = jobs.reduce(function(acc, j) { return acc.concat(j.results || []); }, []);
  var counts = {critical:0, high:0, medium:0, info:0};
  all.forEach(function(r) { counts[r.severity] = (counts[r.severity]||0)+1; });
  var running = jobs.filter(function(j) { return j.status==="running"; });
  var recent = jobs.slice().sort(function(a,b){ return new Date(b.started_at)-new Date(a.started_at); }).slice(0,5);

  return React.createElement("div", {className:"fade-in"},
    React.createElement("div", {className:"stats-grid"},
      React.createElement("div", {className:"stat critical"}, React.createElement("div",{className:"val"},counts.critical), React.createElement("div",{className:"lbl"},"Critical")),
      React.createElement("div", {className:"stat high"}, React.createElement("div",{className:"val"},counts.high), React.createElement("div",{className:"lbl"},"High")),
      React.createElement("div", {className:"stat medium"}, React.createElement("div",{className:"val"},counts.medium), React.createElement("div",{className:"lbl"},"Medium")),
      React.createElement("div", {className:"stat info"}, React.createElement("div",{className:"val"},counts.info), React.createElement("div",{className:"lbl"},"Info")),
      React.createElement("div", {className:"stat total"}, React.createElement("div",{className:"val"},all.length), React.createElement("div",{className:"lbl"},"Toplam"))
    ),
    running.length > 0 && React.createElement("div", {className:"card"},
      React.createElement("div", {className:"card-title"}, "Aktif Taramalar"),
      running.map(function(j) {
        return React.createElement("div", {key:j.id, style:{display:"flex",alignItems:"center",gap:12,marginBottom:8}},
          React.createElement("span", {className:"pulse"}),
          React.createElement("span", null, j.target),
          React.createElement("span", {style:{color:"var(--text2)",fontSize:12}}, j.module || j.workflow),
          React.createElement("span", {style:{marginLeft:"auto",fontSize:12,color:"var(--text2)"}}, timeSince(j.started_at))
        );
      })
    ),
    React.createElement("div", {className:"card"},
      React.createElement("div", {className:"card-title"},
        "Son Taramalar",
        React.createElement("button", {className:"btn btn-ghost btn-sm", onClick:function(){setPage("scan");}}, "+ Yeni Tarama")
      ),
      recent.length === 0
        ? React.createElement("div", {className:"empty"}, React.createElement("div",{className:"icon"},""), React.createElement("div",null,"Henuz tarama yok"))
        : React.createElement("table", null,
            React.createElement("thead", null,
              React.createElement("tr", null,
                React.createElement("th",null,"Hedef"),
                React.createElement("th",null,"Modul"),
                React.createElement("th",null,"Durum"),
                React.createElement("th",null,"Bulgu"),
                React.createElement("th",null,"Sure")
              )
            ),
            React.createElement("tbody", null,
              recent.map(function(j) {
                return React.createElement("tr", {key:j.id},
                  React.createElement("td", null, React.createElement("strong",null,j.target)),
                  React.createElement("td", null, React.createElement("code",null, j.module || j.workflow)),
                  React.createElement("td", null, React.createElement(StatusBadge,{s:j.status})),
                  React.createElement("td", {style:{color:"var(--text2)"}}, (j.results||[]).length),
                  React.createElement("td", {style:{color:"var(--text2)",fontSize:12}}, timeSince(j.started_at))
                );
              })
            )
          )
    )
  );
}

function ScanForm({onScanStarted}) {
  var _s = useState(""); var target = _s[0]; var setTarget = _s[1];
  var _m = useState("module"); var mtype = _m[0]; var setMtype = _m[1];
  var _mod = useState("tr"); var mod = _mod[0]; var setMod = _mod[1];
  var _wf = useState("workflows/full-pentest.yaml"); var wf = _wf[0]; var setWf = _wf[1];
  var _st = useState(false); var stealth = _st[0]; var setStealth = _st[1];
  var _th = useState(5); var threads = _th[0]; var setThreads = _th[1];
  var _ld = useState(false); var loading = _ld[0]; var setLoading = _ld[1];
  var _al = useState(null); var alert = _al[0]; var setAlert = _al[1];

  var mods = ["tr","portscan","web","osint","recon"];
  var wfs  = ["workflows/full-pentest.yaml","workflows/tr-gov.yaml","workflows/quick-recon.yaml"];

  function start() {
    if (!target) { setAlert({type:"error",msg:"Hedef bos olamaz"}); return; }
    setLoading(true); setAlert(null);
    var body = {target:target, stealth:stealth, threads:parseInt(threads)};
    if (mtype === "module") { body.module = mod; } else { body.workflow = wf; }
    fetch("/api/scan/start", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify(body)
    }).then(function(r){ return r.json(); }).then(function(d){
      setAlert({type:"success", msg:"Tarama baslatildi: " + d.job_id});
      onScanStarted(d.job_id);
    }).catch(function(e){
      setAlert({type:"error", msg:e.message});
    }).finally(function(){ setLoading(false); });
  }

  return React.createElement("div", {className:"fade-in"},
    alert && React.createElement("div", {className:"alert alert-"+alert.type}, alert.msg),
    React.createElement("div", {className:"card"},
      React.createElement("div", {className:"card-title"}, "Hedef Bilgileri"),
      React.createElement("div", {className:"form-group"},
        React.createElement("label", null, "Hedef (domain / IP)"),
        React.createElement("input", {
          value:target,
          onChange:function(e){setTarget(e.target.value);},
          placeholder:"tcdd.gov.tr veya 192.168.1.1",
          onKeyDown:function(e){if(e.key==="Enter")start();}
        })
      ),
      React.createElement("div", {className:"form-row"},
        React.createElement("div", {className:"form-group"},
          React.createElement("label", null, "Tarama Tipi"),
          React.createElement("select", {value:mtype, onChange:function(e){setMtype(e.target.value);}},
            React.createElement("option",{value:"module"},"Tekil Modul"),
            React.createElement("option",{value:"workflow"},"Workflow")
          )
        ),
        React.createElement("div", {className:"form-group"},
          React.createElement("label", null, mtype==="module"?"Modul":"Workflow"),
          mtype==="module"
            ? React.createElement("select", {value:mod, onChange:function(e){setMod(e.target.value);}},
                mods.map(function(m){ return React.createElement("option",{key:m,value:m},m); })
              )
            : React.createElement("select", {value:wf, onChange:function(e){setWf(e.target.value);}},
                wfs.map(function(w){ return React.createElement("option",{key:w,value:w},w); })
              )
        )
      ),
      React.createElement("div", {className:"form-row"},
        React.createElement("div", {className:"form-group"},
          React.createElement("label", null, "Thread Sayisi"),
          React.createElement("input", {type:"number",value:threads,onChange:function(e){setThreads(e.target.value);},min:"1",max:"50"})
        ),
        React.createElement("div", {className:"form-group", style:{display:"flex",alignItems:"flex-end",paddingBottom:2}},
          React.createElement("label", {className:"form-check"},
            React.createElement("input", {type:"checkbox",checked:stealth,onChange:function(e){setStealth(e.target.checked);}}),
            "Stealth Mod"
          )
        )
      )
    ),
    React.createElement("button", {
      className:"btn btn-primary",
      onClick:start,
      disabled:loading,
      style:{width:"100%",justifyContent:"center",padding:12}
    }, loading ? "Baslatiliyor..." : "Taramayi Baslatma")
  );
}

function LiveScan({jobId, jobs}) {
  var _r = useState([]); var results = _r[0]; var setResults = _r[1];
  var _s = useState("running"); var status = _s[0]; var setStatus = _s[1];
  var termRef = useRef(null);

  useEffect(function() {
    if (!jobId) return;
    var job = jobs.find(function(j){ return j.id===jobId; });
    if (job) { setResults(job.results||[]); setStatus(job.status); }

    var es = new EventSource("/api/events/" + jobId);
    es.onmessage = function(e) {
      try {
        var r = JSON.parse(e.data);
        setResults(function(prev){ return prev.concat([r]); });
        if (r.step === "scan-complete") { setStatus("done"); es.close(); }
      } catch(err){}
    };
    es.onerror = function(){ es.close(); };
    return function(){ es.close(); };
  }, [jobId]);

  useEffect(function() {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [results]);

  var counts = {critical:0,high:0,medium:0,info:0};
  results.forEach(function(r){ counts[r.severity]=(counts[r.severity]||0)+1; });

  function lineClass(r) {
    if (r.module==="system") return "system";
    return r.severity || "info";
  }
  function prefix(r) {
    if (r.module==="system") return "[OK] ";
    var m = {critical:"[!!!]",high:"[!!] ",medium:"[!]  "};
    return m[r.severity] || "[+]  ";
  }

  var job = jobs.find(function(j){ return j.id===jobId; });

  return React.createElement("div", {className:"fade-in"},
    React.createElement("div", {style:{display:"flex",alignItems:"center",gap:12,marginBottom:16}},
      status==="running" && React.createElement("span",{className:"pulse"}),
      React.createElement("span", {style:{fontWeight:600,fontSize:16}}, job ? job.target : jobId),
      React.createElement(StatusBadge, {s:status}),
      React.createElement("span", {style:{color:"var(--text2)",fontSize:12,marginLeft:"auto"}}, results.length + " bulgu")
    ),
    React.createElement("div", {className:"stats-grid", style:{gridTemplateColumns:"repeat(4,1fr)",marginBottom:16}},
      React.createElement("div",{className:"stat critical"},React.createElement("div",{className:"val",style:{fontSize:20}},counts.critical),React.createElement("div",{className:"lbl"},"Critical")),
      React.createElement("div",{className:"stat high"},React.createElement("div",{className:"val",style:{fontSize:20}},counts.high),React.createElement("div",{className:"lbl"},"High")),
      React.createElement("div",{className:"stat medium"},React.createElement("div",{className:"val",style:{fontSize:20}},counts.medium),React.createElement("div",{className:"lbl"},"Medium")),
      React.createElement("div",{className:"stat info"},React.createElement("div",{className:"val",style:{fontSize:20}},counts.info),React.createElement("div",{className:"lbl"},"Info"))
    ),
    React.createElement("div", {className:"terminal", ref:termRef},
      results.map(function(r,i){
        return React.createElement("div", {key:i, className:"tl "+lineClass(r)},
          prefix(r) + " [" + r.module + "/" + r.step + "] " + r.output
        );
      }),
      status==="running" && React.createElement("span",{className:"cursor"}),
      status==="done" && React.createElement("div",{className:"tl system"}, "[OK] Tarama tamamlandi " + results.length + " bulgu")
    )
  );
}

function JobList({jobs, onSelect}) {
  if (!jobs || jobs.length===0) return React.createElement("div",{className:"empty"},
    React.createElement("div",{className:"icon"},""),
    React.createElement("div",null,"Henuz tarama yok")
  );
  var sorted = jobs.slice().sort(function(a,b){ return new Date(b.started_at)-new Date(a.started_at); });
  return React.createElement("div", {className:"fade-in"},
    React.createElement("table", null,
      React.createElement("thead",null,
        React.createElement("tr",null,
          React.createElement("th",null,"Hedef"),
          React.createElement("th",null,"Modul"),
          React.createElement("th",null,"Durum"),
          React.createElement("th",null,"Critical"),
          React.createElement("th",null,"High"),
          React.createElement("th",null,"Toplam"),
          React.createElement("th",null,"Sure"),
          React.createElement("th",null,"")
        )
      ),
      React.createElement("tbody",null,
        sorted.map(function(j){
          var res = j.results||[];
          var c = res.filter(function(r){return r.severity==="critical";}).length;
          var h = res.filter(function(r){return r.severity==="high";}).length;
          return React.createElement("tr",{key:j.id,style:{cursor:"pointer"},onClick:function(){onSelect(j.id);}},
            React.createElement("td",null,React.createElement("strong",null,j.target)),
            React.createElement("td",null,React.createElement("code",null,j.module||j.workflow)),
            React.createElement("td",null,React.createElement(StatusBadge,{s:j.status})),
            React.createElement("td",null, c>0 ? React.createElement("span",{className:"badge b-crit"},c) : React.createElement("span",{style:{color:"var(--text2)"}},"-")),
            React.createElement("td",null, h>0 ? React.createElement("span",{className:"badge b-high"},h) : React.createElement("span",{style:{color:"var(--text2)"}},"-")),
            React.createElement("td",{style:{color:"var(--text2)"}},res.length),
            React.createElement("td",{style:{color:"var(--text2)",fontSize:12}},timeSince(j.started_at)),
            React.createElement("td",null,React.createElement("button",{className:"btn btn-ghost btn-sm"},"Goster"))
          );
        })
      )
    )
  );
}

function ModuleList() {
  var mods = [
    {name:"tr",      desc:"BTK sorgulama, gov.tr enum, TR-CERT, USOM"},
    {name:"portscan",desc:"Nmap port taramasi, servis fingerprint, OS tespiti"},
    {name:"web",     desc:"Header analizi, WAF, nikto, JS secret, ffuf, screenshot"},
    {name:"osint",   desc:"theHarvester, GitHub dork, Wayback Machine, HIBP breach"},
    {name:"netattack",desc:"BBM456: UDP amp, BGP hijack, ARP spoof, ICMP, OS fingerprint"},
    {name:"recon",   desc:"Subdomain enum, crt.sh, zone transfer, takeover tespiti"},
  ];
  return React.createElement("div", {className:"fade-in", style:{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(280px,1fr))",gap:16}},
    mods.map(function(m){
      return React.createElement("div",{key:m.name,className:"card",style:{marginBottom:0}},
        React.createElement("div",{style:{fontWeight:600,fontSize:15,marginBottom:8,color:"var(--blue)"}},m.name),
        React.createElement("div",{style:{fontSize:13,color:"var(--text2)",lineHeight:1.6}},m.desc)
      );
    })
  );
}

function App() {
  var _p = useState("dashboard"); var page = _p[0]; var setPage = _p[1];
  var _j = useState([]); var jobs = _j[0]; var setJobs = _j[1];
  var _a = useState(null); var activeId = _a[0]; var setActiveId = _a[1];

  useEffect(function(){
    function fetchJobs(){
      fetch("/api/scan/list").then(function(r){return r.json();}).then(function(d){setJobs(d||[]);}).catch(function(){});
    }
    fetchJobs();
    var t = setInterval(fetchJobs, 2000);
    return function(){ clearInterval(t); };
  }, []);

  function onScanStarted(id){ setActiveId(id); setPage("live"); }
  function onSelect(id){ setActiveId(id); setPage("live"); }

  var running = jobs.filter(function(j){return j.status==="running";}).length;
  var titles = {dashboard:"Dashboard",scan:"Yeni Tarama",jobs:"Taramalar",modules:"Moduller",live:"Canli Tarama"};

  return React.createElement("div",{className:"layout"},
    React.createElement(Sidebar,{page:page==="live"?"jobs":page, setPage:function(p){setPage(p);if(p!=="live")setActiveId(null);}}),
    React.createElement("div",{className:"main"},
      React.createElement("div",{className:"topbar"},
        React.createElement("div",{className:"topbar-title"},titles[page]||page),
        React.createElement("div",{style:{fontSize:12,color:"var(--text2)"}},
          running > 0
            ? React.createElement("span",{style:{color:"var(--green)"}}, running + " aktif tarama")
            : "Hazir"
        )
      ),
      React.createElement("div",{className:"content"},
        page==="dashboard" && React.createElement(Dashboard,{jobs:jobs,setPage:setPage}),
        page==="scan"      && React.createElement(ScanForm,{onScanStarted:onScanStarted}),
        page==="jobs"      && React.createElement(JobList,{jobs:jobs,onSelect:onSelect}),
        page==="modules"   && React.createElement(ModuleList,null),
        page==="live" && activeId && React.createElement(LiveScan,{jobId:activeId,jobs:jobs})
      )
    )
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(React.createElement(App,null));
</script>
</body>
</html>`
