"""
MX Sentinel - standalone interactive HTML report generator.

`render()` returns a single self-contained HTML file (no server needed): summary
tiles, a sortable/filterable table with click-to-expand per-domain detail, and a
Print / Save-as-PDF button. The colour palette is supplied by the caller
(`theme_vars`) so the report inherits whatever theme is active in the app.

Kept as a plain string (not an f-string) so the embedded CSS/JS braces need no
escaping; placeholders (__DATA__ etc.) are substituted in render().
"""

from __future__ import annotations

import json
from datetime import datetime

_TEMPLATE = r"""<!doctype html>
<html lang="en" data-theme="__THEME__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Email Security Report __TS__</title>
<style>
  :root{__THEME_VARS__ --ok:#22c55e;--bad:#ef4444;--warn:#f59e0b;--crit:#dc2626}
  *{box-sizing:border-box}
  body{margin:0;font-family:Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text)}
  header{padding:18px 26px;border-bottom:1px solid var(--line)}
  header h1{font-size:20px;margin:0}
  header .sub{color:var(--muted);font-size:13px;margin-top:4px}
  .wrap{padding:20px 26px}
  .stats{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 14px;font-size:13px;min-width:92px}
  .stat span{color:var(--muted)} .stat b{display:block;font-size:18px}
  .stat small{display:block;color:var(--muted);font-size:11px;margin-top:3px;line-height:1.6}
  .stat small .passok,.stat small .passwarn,.stat small .passbad{font-weight:600}
  .stat.big{min-width:120px;border-width:2px} .stat.big b{font-size:28px;line-height:1.1}
  .stat.ok2{border-color:#14532d} .stat.warn2{border-color:#854d0e} .stat.bad2{border-color:#7f1d1d}
  .toolbar{display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
  input[type=text]{background:var(--panel);border:1px solid var(--line);color:var(--text);
    border-radius:8px;padding:9px 12px;font-size:13px;min-width:240px}
  button{background:transparent;border:1px solid var(--line);color:var(--text);border-radius:8px;
    padding:8px 13px;font-size:13px;cursor:pointer}
  button:hover{border-color:var(--accent);color:var(--accent)}
  button:disabled{opacity:.45;cursor:not-allowed;color:var(--muted);border-color:var(--line)}
  button:disabled:hover{color:var(--muted);border-color:var(--line)}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:center;white-space:nowrap}
  th{background:var(--panel2);cursor:pointer;user-select:none;position:sticky;top:0}
  th:hover{color:var(--accent)}
  td:first-child,th:first-child{text-align:left}
  tr.dom{cursor:pointer} tr.dom:hover{background:var(--panel)}
  .passok{color:var(--ok)} .passbad{color:var(--bad)} .passwarn{color:var(--warn)}
  .pill{padding:2px 8px;border-radius:20px;font-size:12px;font-weight:600}
  .g-Excellent{background:#14532d;color:#bbf7d0} .g-Good{background:#365314;color:#d9f99d}
  .g-Fair{background:#78350f;color:#fed7aa} .g-Poor{background:#7f1d1d;color:#fecaca}
  .r-Low{color:var(--ok)} .r-Medium{color:var(--warn)} .r-High{color:#fb923c}
  .r-Critical{color:var(--crit);font-weight:700}
  /* Light theme: bold the status colours so they stay legible on a pale background. */
  [data-theme="corporate"] .passok,[data-theme="corporate"] .passbad,
  [data-theme="corporate"] .passwarn,[data-theme="corporate"] .r-Low,
  [data-theme="corporate"] .r-Medium,[data-theme="corporate"] .r-High{font-weight:700}
  .detail{background:var(--panel);text-align:left;white-space:normal}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px;padding:6px 0}
  .card{border:1px solid var(--line);border-radius:8px;padding:10px;font-size:12.5px;min-width:0}
  .card h4{margin:0 0 4px;font-size:13px}
  .card code{white-space:pre-wrap;word-break:break-word;display:block}
  .muted{color:var(--muted)} code{font-family:Consolas,monospace}
  .fixes{margin-top:12px;border-top:1px solid var(--line);padding-top:10px}
  .fixes h3{font-size:13px;margin:0 0 8px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
  .fix{display:grid;grid-template-columns:74px 78px 1fr;gap:10px;align-items:start;
    padding:8px 0;border-bottom:1px dashed var(--line)}
  .fix:last-child{border-bottom:0}
  .sev{font-size:11px;font-weight:700;text-align:center;padding:2px 0;border-radius:5px}
  .sev-CRITICAL{background:#7f1d1d;color:#fecaca} .sev-HIGH{background:#9a3412;color:#fed7aa}
  .sev-MEDIUM{background:#854d0e;color:#fde68a} .sev-LOW{background:#1e3a5f;color:#bae6fd}
  .sev-INFO{background:#334155;color:#cbd5e1}
  .fix .ctrl{font-weight:600} .fix .act{font-size:12.5px}
  .fix .rec{display:block;margin-top:5px;font-family:Consolas,monospace;font-size:12px;
    background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px 8px;
    color:var(--accent);white-space:pre-wrap;word-break:break-word}
  .fix.ok2{color:var(--muted)}
  #scoringPanel{background:var(--panel);border:1px solid var(--line);border-radius:8px;
    padding:12px 14px;font-size:13px;margin-bottom:12px;max-width:940px;line-height:1.6}
  #scoringPanel b{font-size:14px}
  #scoringPanel .w{display:flex;flex-wrap:wrap;gap:6px 14px;margin:6px 0}
  @media print{
    /* No forced size -> follows the orientation chosen in the print dialog
       (landscape or portrait). Real per-page margins so no page is clipped. */
    @page{margin:12mm 10mm}
    body{background:#fff;color:#000;padding:0}
    header{padding:0 0 8px}
    .toolbar{display:none}
    .stats{gap:6px}
    /* By default <thead> repeats on every printed page; make it a normal row group
       so the "Domain SPF DKIM ..." header prints only once. */
    thead{display:table-row-group}
    th{position:static;background:#0f172a!important;color:#fff!important;
       -webkit-print-color-adjust:exact;print-color-adjust:exact}
    /* Let wide cells wrap instead of overflowing in portrait. */
    th,td{white-space:normal;word-break:break-word}
    .pill,.sev{-webkit-print-color-adjust:exact;print-color-adjust:exact}
    .card,.stat{border-color:#ccc}
    table{font-size:10.5px}
    tr.det{display:table-row!important}
    /* Keep a domain's row, its detail and cards from splitting awkwardly. */
    tr.dom,tr.det,.card,.fix{break-inside:avoid}}
</style></head>
<body>
<header>
  <h1>🛡️ Email Security Audit Report</h1>
  <div class="sub">Generated __GENERATED__ &middot; __COUNT__ domain(s)</div>
</header>
<div class="wrap">
  <div class="stats" id="stats"></div>
  <div class="toolbar">
    <input type="text" id="filter" placeholder="Filter domains…">
    <button id="expandAll">Expand all</button>
    <button id="collapseAll">Collapse all</button>
    <button id="scoringBtn">ⓘ Scoring rationale</button>
    <button id="printBtn" disabled title="PDF export is temporarily disabled">🖨 Print / Save PDF</button>
  </div>
  <div id="scoringPanel" style="display:none"></div>
  <div id="tableWrap"></div>
</div>
<script>
const DATA = __DATA__;
const COLS = __COLS__;
const SCORING = __SCORING__;
let sortKey="score", sortDir=-1;

const $=s=>document.querySelector(s);
const esc=s=>String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

function cellClass(ch){
  if(!ch.ok) return 'passbad';
  if(ch.severity || /Enf-SPF|Enf-DKIM|Soft|testing|unverified|Partial|inherited/i.test(ch.status))
    return 'passwarn';
  return 'passok';
}

function stats(){
  const v=DATA.filter(r=>r.valid), n=v.length;
  const s={risk:{Critical:0,High:0,Medium:0,Low:0},
    dmarc:{enforced:0,partial:0,monitor:0,none:0,inherited:0},
    spf:{ok:0,weak:0,missing:0}, dkim:{ok:0,issues:0,missing:0},
    mta:{enforce:0,any:0}, dnssec:0, dane:0, tlsrpt:0,
    avg:n?Math.round(v.reduce((a,r)=>a+r.score,0)/n):0};
  v.forEach(r=>{
    s.risk[r.risk]=(s.risk[r.risk]||0)+1;
    const b=r.dmarc_base;
    if(b==="Enforced"||b==="Enf-NoAuth")s.dmarc.enforced++;
    else if(b==="Enf-SPF"||b==="Enf-DKIM")s.dmarc.partial++;
    else if(b==="Monitor")s.dmarc.monitor++; else s.dmarc.none++;
    if(r.dmarc_inherited)s.dmarc.inherited++;
    const spf=r.checks.SPF;
    if(spf.status==="Missing"||spf.status.indexOf("Invalid")===0)s.spf.missing++;
    else if(spf.ok && !/Soft|PERMERROR/i.test(spf.status))s.spf.ok++; else s.spf.weak++;
    const dk=r.checks.DKIM;
    if(dk.ok && !dk.severity)s.dkim.ok++; else if(dk.ok)s.dkim.issues++; else s.dkim.missing++;
    if(/enforce/i.test(r.checks["MTA-STS"].status||""))s.mta.enforce++;
    if(r.checks["MTA-STS"].ok)s.mta.any++;
    if(r.checks.DNSSEC.ok)s.dnssec++;
    if(r.checks["TLS-RPT"].ok)s.tlsrpt++;
    if(r.transport&&r.transport.dane)s.dane++;
  });
  const seg=(num,cls,label)=>`<span class="${num?cls:'muted'}">${num} ${label}</span>`;
  const prot=s.risk.Low, part=s.risk.Medium, risk=s.risk.High+s.risk.Critical;
  const avgCls=s.avg>=75?"passok":s.avg>=50?"passwarn":"passbad";
  const big=(cls,box,label,val,sub)=>`<div class="stat big ${box}"><span>${label}</span><b class="${cls}">${val}</b><small>${sub}</small></div>`;
  const card=(l,segs)=>`<div class="stat"><span>${l}</span><small>${segs.join(" · ")}</small></div>`;
  $("#stats").innerHTML=
    big("passok","ok2","✓ Protected", prot, "DMARC enforced + SPF/DKIM")+
    big("passwarn","warn2","⚠ Partial", part, "monitor / single-auth")+
    big("passbad","bad2","✗ At risk", risk, "no effective DMARC")+
    big(avgCls,"","Avg score", s.avg+"%", `${n} domain${n===1?"":"s"}`+((DATA.length-n)?`, ${DATA.length-n} invalid`:""))+
    card("DMARC", [seg(s.dmarc.enforced,"passok","enforced"), seg(s.dmarc.partial,"passwarn","partial"),
                   seg(s.dmarc.monitor,"passwarn","monitor"), seg(s.dmarc.none,"passbad","none/ineff")])+
    card("SPF", [seg(s.spf.ok,"passok","ok"), seg(s.spf.weak,"passwarn","weak"), seg(s.spf.missing,"passbad","missing")])+
    card("DKIM", [seg(s.dkim.ok,"passok","ok"), seg(s.dkim.issues,"passwarn","issues"), seg(s.dkim.missing,"passbad","not found")])+
    card("Transport", [seg(s.mta.enforce,"passok","MTA-STS"), seg(s.dnssec,"passok","DNSSEC"),
                       seg(s.dane,"passok","DANE"), seg(s.tlsrpt,"passok","TLS-RPT")]);
}

function sorted(rows){
  const o={Low:0,Medium:1,High:2,Critical:3,Unknown:-1};
  return rows.slice().sort((a,b)=>{
    if(sortKey==="domain") return a.domain.localeCompare(b.domain)*sortDir;
    if(sortKey==="risk") return ((o[a.risk]??-1)-(o[b.risk]??-1))*sortDir;
    if(sortKey==="grade"||COLS.includes(sortKey)){
      const av=sortKey==="grade"?a.grade:(a.checks[sortKey]||{}).status||"";
      const bv=sortKey==="grade"?b.grade:(b.checks[sortKey]||{}).status||"";
      return String(av).localeCompare(String(bv))*sortDir;
    }
    return ((a[sortKey]||0)-(b[sortKey]||0))*sortDir;
  });
}

function detail(r,i){
  const cards=COLS.map(c=>{
    const ch=r.checks[c];
    const sev=ch.severity?` <span class="muted">[${ch.severity}]</span>`:"";
    const recs=(ch.records&&ch.records.length)
      ? `<div class="muted"><code>${esc(ch.records.join("\n")).replace(/\n/g,"<br>")}</code></div>`:"";
    return `<div class="card"><h4 class="${cellClass(ch)}">${c}: ${esc(ch.status)}${sev}</h4>
      <div>${esc(ch.detail||"").replace(/\n/g,"<br>")}</div>${recs}</div>`;
  }).join("");
  return `<tr class="det" id="d${i}" style="display:none"><td class="detail" colspan="${COLS.length+4}">
    <div class="grid">${cards}</div>${transportHtml(r.transport)}${fixesHtml(r.recommendations)}</td></tr>`;
}

function transportHtml(t){
  if(!t || !t.checked || !t.hosts || !t.hosts.length) return "";
  const rows=t.hosts.map(h=>{
    const c=h.cert||{};
    const tls=h.starttls?`<span class="passok">${esc(h.tls_version||"TLS")}</span>`:`<span class="passbad">no STARTTLS</span>`;
    const cert=c.not_after?`${esc(c.subject||"")} · exp ${esc((c.not_after||"").slice(0,10))} (${c.days_left}d)${c.expired?' <span class="passbad">EXPIRED</span>':''}${c.host_match===false?' <span class="passbad">host mismatch</span>':''}`:(h.error?esc(h.error):"");
    const dane=(h.tlsa&&h.tlsa.length)?'<span class="passok">DANE</span>':'<span class="muted">no DANE</span>';
    return `<div class="card"><h4>${esc(h.host)}</h4><div>STARTTLS: ${tls} &nbsp; ${dane}</div><div class="muted">${cert}</div></div>`;
  }).join("");
  return `<div class="fixes"><h3>Transport (MX TLS / DANE)</h3><div class="grid">${rows}</div></div>`;
}

function fixesHtml(recs){
  if(!recs || !recs.length)
    return `<div class="fixes"><div class="fix ok2">✓ No remediation needed — core controls look healthy.</div></div>`;
  const items=recs.map(f=>`
    <div class="fix">
      <span class="sev sev-${f.severity}">${f.severity}</span>
      <span class="ctrl">${esc(f.control)}</span>
      <span class="act">${esc(f.action)}${f.record?`<code class="rec">${esc(f.record)}</code>`:""}</span>
    </div>`).join("");
  return `<div class="fixes"><h3>Recommended fixes (${recs.length})</h3>${items}</div>`;
}

function render(){
  const q=($("#filter").value||"").toLowerCase();
  const rows=sorted(DATA).filter(r=>r.domain.toLowerCase().includes(q));
  const head=`<tr><th data-k="domain">Domain</th>${COLS.map(c=>`<th data-k="${c}">${c}</th>`).join("")}
    <th data-k="score">Score</th><th data-k="grade">Grade</th><th data-k="risk">Risk</th></tr>`;
  const body=rows.map(r=>{
    const i=DATA.indexOf(r);
    if(!r.valid) return `<tr class="dom"><td><b>${esc(r.domain)}</b></td>
      <td colspan="${COLS.length+3}" class="passbad" style="text-align:left">⚠️ ${esc(r.error)}</td></tr>`;
    const cells=COLS.map(c=>`<td class="${cellClass(r.checks[c])}">${esc(r.checks[c].status)}</td>`).join("");
    return `<tr class="dom" data-i="${i}"><td><b>${esc(r.domain)}</b> <span class="muted">${r.elapsed}s</span></td>
      ${cells}<td><b>${r.score}</b></td><td><span class="pill g-${r.grade}">${r.grade}</span></td>
      <td class="r-${r.risk}">${r.risk}</td></tr>`+detail(r,i);
  }).join("");
  $("#tableWrap").innerHTML=`<table><thead>${head}</thead><tbody>${body}</tbody></table>`;
  document.querySelectorAll("th[data-k]").forEach(th=>th.onclick=()=>{
    const k=th.dataset.k;
    if(sortKey===k) sortDir*=-1; else {sortKey=k; sortDir=(k==="domain")?1:-1;}
    render();
  });
  document.querySelectorAll("tr.dom[data-i]").forEach(tr=>tr.onclick=()=>{
    const d=document.getElementById("d"+tr.dataset.i);
    if(d) d.style.display=d.style.display==="table-row"?"none":"table-row";
  });
}

function toggleScoring(){
  const p=$("#scoringPanel");
  if(p.style.display!=="none"){ p.style.display="none"; return; }
  const w=Object.entries(SCORING.weights||{}).map(([k,v])=>`<span>${esc(k)} <b>${v}</b></span>`).join("");
  const g=(SCORING.grades||[]).map(x=>`${esc(x.grade)} ≥${x.min}`).join(" · ");
  p.innerHTML=`<b>Scoring rationale</b> <span class="muted">(max ${SCORING.max_score||100})</span>
    <div class="w">${w}</div>
    <div class="muted">Grades: ${g}</div>
    <div style="margin-top:6px">${esc(SCORING.risk||"")}</div>
    <div class="muted" style="margin-top:6px">${esc(SCORING.notes||"")}</div>`;
  p.style.display="block";
}

$("#filter").oninput=render;
$("#expandAll").onclick=()=>document.querySelectorAll("tr.det").forEach(d=>d.style.display="table-row");
$("#collapseAll").onclick=()=>document.querySelectorAll("tr.det").forEach(d=>d.style.display="none");
$("#scoringBtn").onclick=toggleScoring;
$("#printBtn").onclick=()=>window.print();
stats(); render();
</script>
</body></html>"""


def render(results, ts, columns, theme_vars, theme="default", scoring=None):
    """Build the self-contained interactive HTML report.

    theme_vars is a CSS-variable string (e.g. "--bg:#0e1621;--accent:#c8a24a;…")
    so the report inherits the app's active theme; it is baked into :root and is
    not switchable from within the report. `theme` is the theme name, set as the
    root data-theme so theme-specific tweaks (e.g. bold text on the light theme)
    apply in the exported report too. `scoring` is the audit.scoring_model() dict,
    embedded so the report's "Scoring rationale" panel works offline.
    """
    # Guard against any '</script>' sequences inside record data breaking the page.
    data_json = json.dumps(results).replace("</", "<\\/")
    scoring_json = json.dumps(scoring or {}).replace("</", "<\\/")
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return (_TEMPLATE
            .replace("__THEME_VARS__", theme_vars)
            .replace("__THEME__", theme)
            .replace("__SCORING__", scoring_json)
            .replace("__DATA__", data_json)
            .replace("__COLS__", json.dumps(columns))
            .replace("__GENERATED__", generated)
            .replace("__COUNT__", str(len(results)))
            .replace("__TS__", ts))
