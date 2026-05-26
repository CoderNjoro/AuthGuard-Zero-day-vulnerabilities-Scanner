"""
AuthGuard Pro v4.0 — Professional Dashboard GUI (Fixed)
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading, time, json, html, re, base64
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse

from authguard_core import C, SEV_ORDER, Finding, ExploitResult, StealthSession
from enhanced_engine import EnhancedScanEngine as ScanEngine
from scanner_utils import compute_risk_score, dedup_findings
from pentest_framework import enrich_finding

# ============================================================================
# CUSTOM WIDGETS
# ============================================================================

class ThinBar(tk.Canvas):
    def __init__(self, parent, **kw):
        kw.setdefault("height",3); kw.setdefault("highlightthickness",0)
        kw.setdefault("bg",C["bg1"])
        super().__init__(parent, **kw)
        self._v = 0
    def set(self, v):
        self._v = max(0,min(100,v)); self.after(0,self._draw)
    def _draw(self):
        self.delete("all")
        w = self.winfo_width() or 500
        n = int(w*self._v/100)
        self.create_rectangle(0,0,w,3,fill=C["bg3"],outline="")
        if n>0:
            self.create_rectangle(0,0,n,3,fill=C["cyan"],outline="")
            if n>8: self.create_rectangle(n-8,0,n,3,fill=C["cyan2"],outline="")

class NavBtn(tk.Frame):
    def __init__(self, parent, icon, label, cmd):
        super().__init__(parent, bg=C["bg1"], cursor="hand2")
        self._active=False; self._cmd=cmd
        self._strip=tk.Frame(self,bg=C["bg1"],width=3); self._strip.pack(side="left",fill="y")
        self._ico=tk.Label(self,text=icon,font=("Courier",13),bg=C["bg1"],fg=C["t3"],width=3)
        self._ico.pack(side="left",pady=10)
        self._lbl=tk.Label(self,text=label,font=("Helvetica",10,"bold"),bg=C["bg1"],fg=C["t2"],anchor="w")
        self._lbl.pack(side="left",fill="x",expand=True)
        for w in [self,self._ico,self._lbl,self._strip]:
            w.bind("<Button-1>",lambda e:cmd())
            w.bind("<Enter>",self._on); w.bind("<Leave>",self._off)
    def _on(self,e=None):
        if not self._active:
            for w in [self,self._ico,self._lbl]: w.configure(bg=C["bg_hover"])
    def _off(self,e=None):
        if not self._active:
            for w in [self,self._ico,self._lbl]: w.configure(bg=C["bg1"])
    def activate(self,v):
        self._active=v
        bg=C["bg_hover"] if v else C["bg1"]
        for w in [self,self._ico,self._lbl]: w.configure(bg=bg)
        self._ico.configure(fg=C["cyan"] if v else C["t3"])
        self._lbl.configure(fg=C["t1"] if v else C["t2"])
        self._strip.configure(bg=C["cyan"] if v else C["bg1"])

# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGen:
    def __init__(self, findings, target, elapsed, modules):
        self.findings=findings; self.target=target
        self.elapsed=elapsed; self.modules=modules

    def stats(self):
        d=defaultdict(int)
        for f in self.findings: d[f.severity]+=1
        return d

    def score(self):
        return compute_risk_score(self.findings, min_confidence=0.7)

    def risk(self):
        sc=self.score()
        return (
            "CRITICAL" if sc >= 70 else "HIGH" if sc >= 40 else "MEDIUM" if sc >= 15
            else "LOW" if sc > 0 else "CLEAN"
        )

    def html_report(self):
        st=self.stats(); sc=self.score(); rl=self.risk()
        rc={"CRITICAL":C["red"],"HIGH":C["orange"],"MEDIUM":C["yellow"],"LOW":C["cyan"],"CLEAN":C["green"]}.get(rl,C["cyan"])
        sc_col={"CRITICAL":C["red"],"HIGH":C["orange"],"MEDIUM":C["yellow"],"LOW":C["cyan"],"INFO":C["t2"]}
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        rows=""
        for i,f in enumerate(sorted(self.findings,key=lambda x:SEV_ORDER.index(x.severity) if x.severity in SEV_ORDER else 99)):
            col=sc_col.get(f.severity,"#aaa")
            cve_b=f'<span class="tag cve">{html.escape(f.cve)}</span>' if f.cve else ""
            cvss_b=f'<span class="tag cvss">CVSS {html.escape(f.cvss)}</span>' if f.cvss else ""
            verified=bool(getattr(f.exploit,"confirmed",False))
            proof_cls="confirmed" if verified else "unconfirmed"
            proof_lbl="✓ VERIFIED EVIDENCE" if verified else "⚠ SIGNAL (NEEDS VALIDATION)"
            cscore=getattr(f.exploit,"confidence",0.0) or 0.0
            try: cscore=float(cscore)
            except: cscore=0.0
            aff=getattr(f.exploit,"location_url","") or getattr(f.exploit,"affected","") or ""
            access=getattr(f.exploit,"access_level","Unknown")
            succ="SUCCESSFUL" if getattr(f.exploit,"success",False) else "UNSUCCESSFUL/BLIND"
            loc_sum=html.escape(getattr(f.exploit,"location_summary","") or aff or "—")
            comp=html.escape(getattr(f.exploit,"component","") or "")
            comp_html=f'<br><span style="color:{C["purple"]};font-size:10px">&gt; {comp}</span>' if comp else ""
            exploit_analysis=html.escape(getattr(f.exploit,"exploitation_analysis","") or "")
            remed=html.escape(getattr(f.exploit,"remediation","") or "")
            repro=html.escape(getattr(f.exploit,"reproduction","") or "")
            grade=html.escape(getattr(f.exploit,"evidence_grade","") or proof_lbl)
            rows+=f"""
<tr class="fr" onclick="t({i})">
  <td><span class="sb" style="border-color:{col};color:{col}">{html.escape(f.severity)}</span></td>
  <td><b>{html.escape(f.title)}</b> {cve_b}{cvss_b}<br><span style="color:{C['cyan2']};font-family:monospace;font-size:11px">{loc_sum}</span>{comp_html}</td>
  <td style="color:{C['t2']};font-size:11px">{html.escape(f.module)}</td>
  <td><span class="{proof_cls}">{grade[:48]}</span></td>
  <td><span class="conf" style="--p:{int(cscore*100)}">{int(cscore*100)}%</span></td>
  <td style="color:{C['t3']};font-size:10px;font-family:monospace">{f.timestamp}</td>
</tr>
<tr id="r{i}" class="detail">
<td colspan="6"><div class="dbox">
  <div class="full"><span class="dl">Weakpoint Location</span><pre class="req">{loc_sum}{(' — '+comp) if comp else ''}</pre></div>
  <div class="dcol"><span class="dl">Description</span><p class="dbody">{html.escape(f.description)}</p></div>
  <div class="dcol"><span class="dl">Controlled Exploitation Analysis</span>
    <pre class="proof" style="max-height:240px">{exploit_analysis or 'N/A'}</pre>
    <p style="color:{C['t3']};font-family:monospace;font-size:11px;margin-top:8px">Confidence: {cscore:.0%} · {html.escape(access)} · {html.escape(succ)}</p>
  </div>
  <div class="full"><span class="dl">Remediation — Fix Before Attackers</span><pre class="proof">{remed or 'Apply defense-in-depth for this vulnerability class.'}</pre></div>
  <div class="full"><span class="dl">Reproduction (Controlled)</span><pre class="proof">{repro or html.escape((f.exploit.proof or '')[:800]) or 'N/A'}</pre></div>
  <div class="dcol"><span class="dl">Request Sent</span><pre class="req">{html.escape(f.exploit.request[:600] if f.exploit.request else 'N/A')}</pre></div>
  <div class="dcol"><span class="dl">Server Response</span><pre class="resp">{html.escape(f.exploit.response[:600] if f.exploit.response else 'N/A')}</pre></div>
  <div class="full"><span class="dl">Evidence Chain</span><pre class="proof">{html.escape(f.exploit.proof[:1200] if f.exploit.proof else 'N/A')}</pre></div>
</div></td>
</tr>"""
        return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>AuthGuard Pro v5.0 — Security Report</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Outfit:wght@300;400;600;700;800&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:{C["bg0"]};color:{C["t1"]};font-family:'Outfit',sans-serif;padding:48px 0}}
.wrap{{max-width:1280px;margin:0 auto;padding:0 28px}}
header{{border-bottom:1px solid {C["border"]};padding-bottom:36px;margin-bottom:40px}}
.logo{{font:700 10px/1 'JetBrains Mono',mono;letter-spacing:4px;color:{C["t4"]};margin-bottom:12px}}
h1{{font-size:38px;font-weight:800;letter-spacing:-1px}} h1 em{{color:{C["cyan"]};font-style:normal}}
.meta{{display:flex;gap:48px;margin-top:18px;flex-wrap:wrap}}
.m{{display:flex;flex-direction:column;gap:4px}}
.ml{{font:700 8px/1 'JetBrains Mono',mono;letter-spacing:3px;color:{C["t4"]};text-transform:uppercase}}
.mv{{font:400 13px/1 'JetBrains Mono',mono;color:{C["cyan"]};margin-top:5px}}
.risk{{background:{C["bg3"]};border-left:5px solid {rc};border-radius:10px;padding:24px 32px;margin-bottom:36px;display:flex;align-items:center;gap:28px}}
.rn{{font:700 60px/1 'JetBrains Mono',mono;color:{rc}}}
.ri h3{{font-size:26px;font-weight:800;color:#fff}} .ri p{{color:{C["t2"]};font-size:13px;margin-top:6px}}
.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:36px}}
.sc{{background:{C["bg3"]};border-top:3px solid var(--c);border-radius:8px;padding:18px;text-align:center}}
.sn{{font:700 32px/1 'JetBrains Mono',mono;color:var(--c)}} .sl{{font:700 8px/1 'JetBrains Mono',mono;letter-spacing:2px;color:{C["t4"]};text-transform:uppercase;margin-top:5px}}
h2{{font:700 11px/1 'JetBrains Mono',mono;letter-spacing:3px;text-transform:uppercase;color:{C["t2"]};margin-bottom:14px}}
table{{width:100%;border-collapse:collapse;margin-bottom:40px}}
thead th{{background:{C["bg4"]};font:700 8px/1 'JetBrains Mono',mono;letter-spacing:2px;color:{C["t4"]};text-transform:uppercase;padding:11px 14px;text-align:left;border-bottom:1px solid {C["border"]}}}
.fr{{cursor:pointer;border-bottom:1px solid {C["border"]}}} .fr:hover td{{background:{C["bg3"]}}}
.fr td{{padding:12px 14px}}
.sb{{font:700 9px/1 'JetBrains Mono',mono;padding:3px 9px;border-radius:4px;border:1px solid;letter-spacing:1px}}
.tag{{font:700 8px/1 'JetBrains Mono',mono;padding:2px 7px;border-radius:3px;margin-left:6px}}
.cve{{background:rgba(255,255,255,.05);color:{C["t3"]}}} .cvss{{background:rgba(255,209,48,.1);color:{C["yellow"]}}}
.confirmed{{background:rgba(255,45,107,.15);color:{C["red"]};font:700 9px/1 'JetBrains Mono',mono;padding:3px 8px;border-radius:4px}}
.unconfirmed{{background:rgba(255,209,48,.1);color:{C["yellow"]};font:700 9px/1 'JetBrains Mono',mono;padding:3px 8px;border-radius:4px}}
.conf{{font:700 9px/1 'JetBrains Mono',mono;padding:3px 8px;border-radius:4px;background:rgba(79,216,255,.1);color:{C['cyan']}}}
.detail td{{padding:0}}
.dbox{{display:grid;grid-template-columns:1fr 1fr;gap:0;background:{C["bg0"]};border-bottom:2px solid {C["border"]}}}
.dcol{{padding:16px 20px;border-bottom:1px solid {C["border"]};border-right:1px solid {C["border"]}}}
.full{{grid-column:span 2;padding:16px 20px;border-bottom:1px solid {C["border"]}}}
.dl{{display:block;font:700 8px/1 'JetBrains Mono',mono;letter-spacing:2px;text-transform:uppercase;color:{C["t3"]};margin-bottom:8px}}
.dbody{{font-size:13px;color:{C["t2"]};line-height:1.6}}
.req{{font:400 11px/1.5 'JetBrains Mono',mono;color:{C["cyan"]};background:rgba(0,191,255,.05);padding:12px;border-radius:6px;white-space:pre-wrap;word-break:break-all;border-left:2px solid {C["cyan"]}}}
.resp{{font:400 11px/1.5 'JetBrains Mono',mono;color:{C["orange"]};background:rgba(255,122,47,.05);padding:12px;border-radius:6px;white-space:pre-wrap;word-break:break-all;border-left:2px solid {C["orange"]}}}
.proof{{font:400 11px/1.5 'JetBrains Mono',mono;color:{C["green"]};background:rgba(0,255,157,.05);padding:14px;border-radius:6px;white-space:pre-wrap;word-break:break-all;border-left:3px solid {C["green"]};max-height:320px;overflow-y:auto}}
footer{{text-align:center;color:{C["t4"]};font-size:11px;border-top:1px solid {C["border"]};padding-top:24px;margin-top:20px}}
</style></head><body><div class="wrap">
<header>
<div class="logo">AUTHGUARD PRO v4.0 // VERIFIED EVIDENCE REPORT</div>
<h1>Security <em>Assessment</em></h1>
<div class="meta">
  <div class="m"><span class="ml">Target</span><span class="mv">{html.escape(self.target)}</span></div>
  <div class="m"><span class="ml">Generated</span><span class="mv">{now}</span></div>
  <div class="m"><span class="ml">Duration</span><span class="mv">{self.elapsed:.1f}s</span></div>
  <div class="m"><span class="ml">Modules</span><span class="mv">{len(self.modules)}</span></div>
  <div class="m"><span class="ml">Total</span><span class="mv">{len(self.findings)}</span></div>
  <div class="m"><span class="ml">Verified</span><span class="mv" style="color:{C['red']}">{sum(1 for f in self.findings if f.exploit.confirmed)}</span></div>
</div></header>
<div class="risk">
  <span class="rn">{sc}</span>
  <div class="ri"><h3>Risk: {rl}</h3><p>{sum(1 for f in self.findings if f.exploit.confirmed)} verified evidence items · Full requests/responses &amp; secrets captured for detailed review</p></div>
</div>
<div class="stats">
  <div class="sc" style="--c:{C['red']}"><div class="sn">{st['CRITICAL']}</div><div class="sl">Critical</div></div>
  <div class="sc" style="--c:{C['orange']}"><div class="sn">{st['HIGH']}</div><div class="sl">High</div></div>
  <div class="sc" style="--c:{C['yellow']}"><div class="sn">{st['MEDIUM']}</div><div class="sl">Medium</div></div>
  <div class="sc" style="--c:{C['cyan']}"><div class="sn">{st['LOW']}</div><div class="sl">Low</div></div>
  <div class="sc" style="--c:{C['t2']}"><div class="sn">{st['INFO']}</div><div class="sl">Info</div></div>
  <div class="sc" style="--c:{C['green']}"><div class="sn">{sum(1 for f in self.findings if f.exploit.confirmed)}</div><div class="sl">Confirmed</div></div>
</div>
<h2>All Findings — Click to expand evidence</h2>
<table>
<thead><tr><th>Severity</th><th>Finding</th><th>Module</th><th>Status</th><th>Confidence</th><th>Time</th></tr></thead>
<tbody>{rows or '<tr><td colspan="6" style="padding:40px;text-align:center;color:'+C["green"]+'">✓ No verified issues</td></tr>'}</tbody>
</table>
<footer>AuthGuard Pro v5.0 · Verified Evidence · {now}<br>Full requests, responses, and secrets are captured for detailed presentation and verification. For authorized testing only.</footer>
</div>
<script>function t(i){{const r=document.getElementById('r'+i);r.style.display=r.style.display==='table-row'?'none':'table-row';}}</script>
</body></html>"""

    def json_report(self):
        return json.dumps({
            "meta":{"target":self.target,"generated":datetime.now().isoformat(),
                    "duration_s":round(self.elapsed,2),"modules":self.modules,
                    "risk_score":self.score(),"risk_level":self.risk(),
                    "total":len(self.findings),
                    "confirmed":sum(1 for f in self.findings if f.exploit.confirmed)},
            "summary":dict(self.stats()),
            "findings":[{
                "title":f.title,"severity":f.severity,"module":f.module,
                "cvss":f.cvss,"cve":f.cve,"timestamp":f.timestamp,
                "description":f.description,
                "exploit":{
                    "confirmed":f.exploit.confirmed,
                    "confidence":getattr(f.exploit,"confidence",0.0),
                    "evidence_grade":getattr(f.exploit,"evidence_grade",""),
                    "affected":getattr(f.exploit,"affected",""),
                    "location":{
                        "summary":getattr(f.exploit,"location_summary",""),
                        "url":getattr(f.exploit,"location_url",""),
                        "method":getattr(f.exploit,"location_method",""),
                        "path":getattr(f.exploit,"location_path",""),
                        "parameter":getattr(f.exploit,"location_parameter",""),
                        "header":getattr(f.exploit,"location_header",""),
                        "component":getattr(f.exploit,"component",""),
                    },
                    "controlled_exploitation":{
                        "analysis":getattr(f.exploit,"exploitation_analysis",""),
                        "access_level":getattr(f.exploit,"access_level",""),
                        "blast_radius":getattr(f.exploit,"blast_radius",""),
                        "attacker_scenario":getattr(f.exploit,"attacker_scenario",""),
                        "reproduction":getattr(f.exploit,"reproduction",""),
                    },
                    "remediation":getattr(f.exploit,"remediation",""),
                    "technique":f.exploit.technique,
                    "request":f.exploit.request,
                    "response":f.exploit.response,
                    "proof":f.exploit.proof,
                }
            } for f in sorted(self.findings,key=lambda x:SEV_ORDER.index(x.severity) if x.severity in SEV_ORDER else 99)]
        },indent=2)

# ============================================================================
# MAIN APPLICATION
# ============================================================================

class AuthGuardApp(tk.Tk):
    PAGES=["Dashboard","New Scan","Findings","Live Log","Reports","Settings"]
    ICONS={"Dashboard":"⬡","New Scan":"▷","Findings":"◈","Live Log":"≡","Reports":"⊞","Settings":"⚙"}

    def __init__(self):
        super().__init__()
        self.title("AuthGuard Pro v5.0 — Pen-Test Weakpoint Scanner")
        self.geometry("1440x920"); self.minsize(1100,720)
        self.configure(bg=C["bg0"])
        self.findings=[]; self.engine=None; self.thread=None
        self.scan_start=None; self.running=False
        self._page="Dashboard"; self._nav={}; self._pages={}
        self._history=[]; self._tick=0
        self._build()
        self._show("Dashboard")
        self._clock()

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build(self):
        # Topbar
        top=tk.Frame(self,bg=C["bg1"],height=56); top.pack(fill="x"); top.pack_propagate(False)
        lg=tk.Frame(top,bg=C["bg1"]); lg.pack(side="left",padx=20,fill="y")
        tk.Label(lg,text="⬡",font=("Courier",18),fg=C["cyan"],bg=C["bg1"]).pack(side="left",pady=14)
        tk.Label(lg,text=" AuthGuard",font=("Helvetica",14,"bold"),fg=C["t1"],bg=C["bg1"]).pack(side="left")
        tk.Label(lg,text="Pro",font=("Helvetica",14,"bold"),fg=C["cyan"],bg=C["bg1"]).pack(side="left")
        tk.Label(lg,text="  v4.0",font=("Courier",9),fg=C["t4"],bg=C["bg1"]).pack(side="left")
        tk.Frame(top,bg=C["border"],width=1).pack(side="left",fill="y",pady=14,padx=16)
        self._bread=tk.Label(top,text="",font=("Helvetica",10),fg=C["t2"],bg=C["bg1"]); self._bread.pack(side="left")
        rt=tk.Frame(top,bg=C["bg1"]); rt.pack(side="right",padx=20,fill="y")
        self._stat=tk.Label(rt,text="● IDLE",font=("Courier",9,"bold"),fg=C["t3"],bg=C["bg1"]); self._stat.pack(side="right",pady=18)
        tk.Button(rt,text="+ New Scan",font=("Helvetica",9,"bold"),bg=C["cyan"],fg=C["bg0"],
                  relief="flat",padx=14,pady=5,cursor="hand2",
                  command=lambda:self._show("New Scan")).pack(side="right",pady=14,padx=(0,16))
        self._clk=tk.Label(rt,text="",font=("Courier",9),fg=C["t4"],bg=C["bg1"]); self._clk.pack(side="right",padx=(0,16),pady=18)

        # Body
        body=tk.Frame(self,bg=C["bg0"]); body.pack(fill="both",expand=True)

        # Sidebar
        sb=tk.Frame(body,bg=C["bg1"],width=210); sb.pack(side="left",fill="y"); sb.pack_propagate(False)
        tk.Label(sb,text="NAVIGATION",font=("Courier",7,"bold"),fg=C["t4"],bg=C["bg1"]).pack(anchor="w",padx=18,pady=(18,6))
        for pg in self.PAGES:
            btn=NavBtn(sb,self.ICONS[pg],pg,cmd=lambda p=pg:self._show(p))
            btn.pack(fill="x",padx=8,pady=1); self._nav[pg]=btn
        tk.Frame(sb,bg=C["border"],height=1).pack(fill="x",padx=16,pady=14)
        tk.Label(sb,text="LIVE STATS",font=("Courier",7,"bold"),fg=C["t4"],bg=C["bg1"]).pack(anchor="w",padx=18,pady=(0,8))
        self._sbv={}
        for key,col,lbl in [("total",C["t1"],"Findings"),("conf",C["red"],"Confirmed"),
                              ("crit",C["orange"],"Critical"),("high",C["yellow"],"High")]:
            r=tk.Frame(sb,bg=C["bg1"]); r.pack(fill="x",padx=18,pady=2)
            v=tk.Label(r,text="0",font=("Courier",10,"bold"),fg=col,bg=C["bg1"],width=4,anchor="e"); v.pack(side="left")
            tk.Label(r,text=lbl,font=("Helvetica",9),fg=C["t2"],bg=C["bg1"]).pack(side="left",padx=6)
            self._sbv[key]=v
        tk.Frame(sb,bg=C["border"],height=1).pack(fill="x",padx=16,pady=14)
        tk.Label(sb,text="v4.0 · Exploit Verified",font=("Courier",7),fg=C["t4"],bg=C["bg1"]).pack(side="bottom",pady=4)
        tk.Label(sb,text="Authorized use only",font=("Courier",7),fg=C["t4"],bg=C["bg1"]).pack(side="bottom")

        # Container
        self._c=tk.Frame(body,bg=C["bg2"]); self._c.pack(side="left",fill="both",expand=True)

        # Build pages
        self._mk_dashboard()
        self._mk_newscan()
        self._mk_findings()
        self._mk_log()
        self._mk_reports()
        self._mk_settings()

        # Progress strip
        pf=tk.Frame(self,bg=C["bg1"],height=28); pf.pack(fill="x",side="bottom"); pf.pack_propagate(False)
        pi=tk.Frame(pf,bg=C["bg1"]); pi.pack(fill="both",expand=True,padx=12,pady=4)
        self._plbl=tk.Label(pi,text="Ready",font=("Courier",8),fg=C["t3"],bg=C["bg1"]); self._plbl.pack(side="left")
        self._ppct=tk.Label(pi,text="",font=("Courier",8,"bold"),fg=C["cyan"],bg=C["bg1"]); self._ppct.pack(side="right")
        self._pbar=ThinBar(pf,bg=C["bg1"]); self._pbar.pack(fill="x",side="bottom")

    # ── Dashboard ─────────────────────────────────────────────────────────────
    def _mk_dashboard(self):
        pg=tk.Frame(self._c,bg=C["bg2"]); self._pages["Dashboard"]=pg
        self._hdr(pg,"Dashboard","Exploit verification overview")
        self._dash_cf=tk.Frame(pg,bg=C["bg2"]); self._dash_cf.pack(fill="x",padx=24,pady=(0,12))
        row2=tk.Frame(pg,bg=C["bg2"]); row2.pack(fill="x",padx=24,pady=(0,12))
        # Sev panel
        sp=tk.Frame(row2,bg=C["bg3"]); sp.pack(side="left",fill="both",expand=True,padx=(0,8))
        self._sub_hdr(sp,"SEVERITY BREAKDOWN")
        self._sev_f=tk.Frame(sp,bg=C["bg3"]); self._sev_f.pack(fill="x",padx=14,pady=(0,14))
        self._sev_lbls=[]
        for sev,col in zip(SEV_ORDER,[C["red"],C["orange"],C["yellow"],C["cyan"],C["t2"]]):
            f=tk.Frame(self._sev_f,bg=C["bg3"]); f.pack(side="left",expand=True)
            n=tk.Label(f,text="0",font=("Courier",22,"bold"),fg=col,bg=C["bg3"]); n.pack()
            tk.Label(f,text=sev[:4],font=("Courier",7,"bold"),fg=C["t4"],bg=C["bg3"]).pack()
            self._sev_lbls.append(n)
        # Confirmed panel
        cp=tk.Frame(row2,bg=C["bg3"],width=300); cp.pack(side="left",fill="y"); cp.pack_propagate(False)
        self._sub_hdr(cp,"EXPLOIT STATUS")
        self._conf_f=tk.Frame(cp,bg=C["bg3"]); self._conf_f.pack(fill="both",expand=True,padx=14,pady=(0,14))
        # Recent table
        rt=tk.Frame(pg,bg=C["bg3"]); rt.pack(fill="both",expand=True,padx=24,pady=(0,20))
        self._sub_hdr(rt,"RECENT CONFIRMED EXPLOITS")
        th=tk.Frame(rt,bg=C["bg4"]); th.pack(fill="x",padx=14)
        for t,w in [("SEV",7),("FINDING",40),("MODULE",16),("STATUS",12),("TIME",7)]:
            tk.Label(th,text=t,font=("Courier",7,"bold"),fg=C["t4"],bg=C["bg4"],
                     anchor="w",pady=6,padx=6,width=w).pack(side="left")
        self._dash_tbl=tk.Frame(rt,bg=C["bg3"]); self._dash_tbl.pack(fill="both",expand=True,padx=14,pady=(0,12))

    def _refresh_dash(self):
        for w in self._dash_cf.winfo_children(): w.destroy()
        st=defaultdict(int)
        for f in self.findings: st[f.severity]+=1
        confirmed=sum(1 for f in self.findings if f.exploit.confirmed)
        sc=st["CRITICAL"]*10+st["HIGH"]*6+st["MEDIUM"]*3+st["LOW"]
        rl="CRITICAL" if sc>30 else "HIGH" if sc>15 else "MEDIUM" if sc>5 else "LOW" if sc>0 else "CLEAN"
        rc={"CRITICAL":C["red"],"HIGH":C["orange"],"MEDIUM":C["yellow"],"LOW":C["cyan"],"CLEAN":C["green"]}.get(rl,C["cyan"])
        for lbl,val,col in [("Risk Score",sc,rc),("Total Findings",len(self.findings),C["t1"]),
                              ("Confirmed",confirmed,C["red"]),("Critical",st["CRITICAL"],C["red"]),
                              ("High",st["HIGH"],C["orange"]),("Scans",len(self._history),C["blue"])]:
            card=tk.Frame(self._dash_cf,bg=C["bg3"]); card.pack(side="left",fill="x",expand=True,padx=(0,5),pady=3)
            tk.Frame(card,bg=col,height=2).pack(fill="x")
            tk.Label(card,text=str(val),font=("Courier",22,"bold"),fg=col,bg=C["bg3"],pady=8).pack()
            tk.Label(card,text=lbl.upper(),font=("Courier",7,"bold"),fg=C["t4"],bg=C["bg3"]).pack(pady=(0,10))
        for i,n in enumerate(self._sev_lbls):
            n.configure(text=str(st[SEV_ORDER[i]]))
        # Exploit status
        for w in self._conf_f.winfo_children(): w.destroy()
        by_module=defaultdict(lambda:{"confirmed":0,"total":0})
        for f in self.findings:
            by_module[f.module]["total"]+=1
            if f.exploit.confirmed: by_module[f.module]["confirmed"]+=1
        for mod,(data) in list(by_module.items())[:12]:
            row=tk.Frame(self._conf_f,bg=C["bg3"]); row.pack(fill="x",pady=2)
            col=C["red"] if data["confirmed"]>0 else C["t4"]
            tk.Label(row,text="●",font=("Courier",8),fg=col,bg=C["bg3"]).pack(side="left")
            tk.Label(row,text=mod[:24],font=("Helvetica",8),fg=C["t1"] if data["confirmed"] else C["t3"],bg=C["bg3"]).pack(side="left",padx=4)
            tk.Label(row,text=f"{data['confirmed']}/{data['total']}",font=("Courier",8,"bold"),fg=col,bg=C["bg3"]).pack(side="right")
        # Table
        for w in self._dash_tbl.winfo_children(): w.destroy()
        if not self.findings:
            tk.Label(self._dash_tbl,text="Run a scan to see confirmed exploits.",font=("Helvetica",10),fg=C["t3"],bg=C["bg3"]).pack(pady=30); return
        sorted_f=sorted(self.findings,key=lambda x:(0 if x.exploit.confirmed else 1,SEV_ORDER.index(x.severity) if x.severity in SEV_ORDER else 99))
        for f in sorted_f[:15]:
            col=C.get(f.severity,C["t2"])
            row=tk.Frame(self._dash_tbl,bg=C["bg3"]); row.pack(fill="x")
            tk.Frame(self._dash_tbl,bg=C["border"],height=1).pack(fill="x")
            tk.Label(row,text=f.severity[:4],font=("Courier",8,"bold"),fg=col,bg=C["bg3"],width=7,anchor="w").pack(side="left",padx=6,pady=5)
            tk.Label(row,text=f.title[:48],font=("Helvetica",10),fg=C["t1"],bg=C["bg3"],anchor="w").pack(side="left",fill="x",expand=True)
            tk.Label(row,text=f.module[:16],font=("Helvetica",8),fg=C["t3"],bg=C["bg3"],width=16).pack(side="left")
            conf_col=C["red"] if f.exploit.confirmed else C["yellow"]
            conf_txt="CONFIRMED" if f.exploit.confirmed else "RISK"
            tk.Label(row,text=conf_txt,font=("Courier",7,"bold"),fg=conf_col,bg=C["bg3"],width=10).pack(side="left")
            tk.Label(row,text=f.timestamp,font=("Courier",8),fg=C["t4"],bg=C["bg3"]).pack(side="left",padx=8)
        # Sidebar
        self._sbv["total"].configure(text=str(len(self.findings)))
        self._sbv["conf"].configure(text=str(confirmed))
        self._sbv["crit"].configure(text=str(st["CRITICAL"]))
        self._sbv["high"].configure(text=str(st["HIGH"]))

    # ── New Scan ──────────────────────────────────────────────────────────────
    def _mk_newscan(self):
        pg=tk.Frame(self._c,bg=C["bg2"]); self._pages["New Scan"]=pg
        self._hdr(pg,"New Scan","Configure and launch exploit-verification assessment")
        body=tk.Frame(pg,bg=C["bg2"]); body.pack(fill="both",expand=True,padx=24,pady=(0,20))
        left=tk.Frame(body,bg=C["bg2"]); left.pack(side="left",fill="both",expand=True,padx=(0,12))
        # Target
        tc=tk.Frame(left,bg=C["bg3"]); tc.pack(fill="x",pady=(0,10))
        self._sub_hdr(tc,"TARGET URL")
        ti=tk.Frame(tc,bg=C["bg4"],highlightbackground=C["border2"],highlightthickness=1)
        ti.pack(fill="x",padx=14,pady=(0,14))
        tk.Label(ti,text="URL",font=("Courier",9,"bold"),fg=C["cyan"],bg=C["bg4"],padx=10).pack(side="left",pady=10)
        tk.Frame(ti,bg=C["border"],width=1).pack(side="left",fill="y",pady=8)
        self.target_var=tk.StringVar()
        e=tk.Entry(ti,textvariable=self.target_var,font=("Courier",12),bg=C["bg4"],fg=C["t1"],
                   insertbackground=C["cyan"],relief="flat",bd=0)
        e.pack(side="left",fill="x",expand=True,ipady=9,padx=10)
        e.insert(0,"https://")
        # Warning
        warn=tk.Frame(left,bg=C["bg3"]); warn.pack(fill="x",pady=(0,10))
        tk.Label(warn,text="⚠  AUTHORIZED USE ONLY — Only scan systems you own or have written permission to test.",
                 font=("Helvetica",9,"bold"),fg=C["yellow"],bg=C["bg3"],padx=14,pady=10).pack(anchor="w")
        # Options
        oc=tk.Frame(left,bg=C["bg2"]); oc.pack(fill="x",pady=(0,10))
        sc_c=tk.Frame(oc,bg=C["bg3"]); sc_c.pack(side="left",fill="x",expand=True,padx=(0,6))
        self._sub_hdr(sc_c,"STEALTH LEVEL")
        self.stealth_var=tk.IntVar(value=2)
        sf=tk.Frame(sc_c,bg=C["bg3"]); sf.pack(padx=14,pady=(0,14),fill="x")
        for v,l,d in [(1,"Low","Fast"),(2,"Medium","Balanced"),(3,"High","Stealthy")]:
            f=tk.Frame(sf,bg=C["bg3"]); f.pack(side="left",expand=True)
            tk.Radiobutton(f,text=l,variable=self.stealth_var,value=v,font=("Helvetica",10,"bold"),
                           fg=C["t1"],bg=C["bg3"],activeforeground=C["cyan"],activebackground=C["bg3"],
                           selectcolor=C["bg4"],relief="flat",cursor="hand2").pack()
            tk.Label(f,text=d,font=("Helvetica",8),fg=C["t3"],bg=C["bg3"]).pack()
        to_c=tk.Frame(oc,bg=C["bg3"]); to_c.pack(side="left",fill="x",expand=True)
        self._sub_hdr(to_c,"TIMEOUT")
        tof=tk.Frame(to_c,bg=C["bg3"]); tof.pack(padx=14,pady=(0,14))
        self.timeout_var=tk.IntVar(value=12)
        tk.Spinbox(tof,textvariable=self.timeout_var,from_=3,to=60,width=5,
                   font=("Courier",16,"bold"),bg=C["bg4"],fg=C["cyan"],
                   buttonbackground=C["bg3"],relief="flat",insertbackground=C["cyan"]).pack(side="left")
        tk.Label(tof,text=" sec/req",font=("Helvetica",9),fg=C["t3"],bg=C["bg3"]).pack(side="left")
        # Buttons
        self._scan_btn=tk.Button(left,text="▶   LAUNCH EXPLOIT VERIFICATION",font=("Helvetica",12,"bold"),
                                  bg=C["cyan"],fg=C["bg0"],activebackground=C["green"],relief="flat",
                                  pady=14,cursor="hand2",command=self.start_scan)
        self._scan_btn.pack(fill="x",pady=(0,8))
        self._stop_btn=tk.Button(left,text="■   ABORT",font=("Helvetica",11,"bold"),
                                  bg=C["bg4"],fg=C["red"],relief="flat",pady=10,cursor="hand2",
                                  command=self.stop_scan,state="disabled")
        self._stop_btn.pack(fill="x")
        # Module list
        right=tk.Frame(body,bg=C["bg3"],width=300); right.pack(side="left",fill="y"); right.pack_propagate(False)
        self._sub_hdr(right,"EXPLOIT MODULES")
        ctrl=tk.Frame(right,bg=C["bg3"]); ctrl.pack(fill="x",padx=14,pady=(0,6))
        tk.Button(ctrl,text="All",font=("Courier",8,"bold"),bg=C["bg4"],fg=C["cyan"],
                  relief="flat",padx=8,pady=3,cursor="hand2",
                  command=lambda:[v.set(True) for v in self.mod_vars.values()]).pack(side="left")
        tk.Button(ctrl,text="None",font=("Courier",8,"bold"),bg=C["bg4"],fg=C["t2"],
                  relief="flat",padx=8,pady=3,cursor="hand2",
                  command=lambda:[v.set(False) for v in self.mod_vars.values()]).pack(side="left",padx=4)
        tk.Button(ctrl,text="Auth Only",font=("Courier",8,"bold"),bg=C["bg4"],fg=C["yellow"],
                  relief="flat",padx=8,pady=3,cursor="hand2",command=self._preset_auth).pack(side="right")
        self.mod_vars={}
        mf=tk.Frame(right,bg=C["bg3"]); mf.pack(fill="both",expand=True,padx=14,pady=(0,14))
        cv=tk.Canvas(mf,bg=C["bg3"],highlightthickness=0)
        vsb=tk.Scrollbar(mf,orient="vertical",command=cv.yview,bg=C["bg3"])
        cv.configure(yscrollcommand=vsb.set); vsb.pack(side="right",fill="y"); cv.pack(side="left",fill="both",expand=True)
        inner=tk.Frame(cv,bg=C["bg3"]); cw=cv.create_window((0,0),window=inner,anchor="nw")
        inner.bind("<Configure>",lambda e:cv.configure(scrollregion=cv.bbox("all")))
        icons={"SSL/TLS":"🔒","Security Headers":"🛡","Cookie Security":"🍪","JWT Analysis":"🔑",
               "Admin Panel Discovery":"🚪","Auth Bypass":"💥","Account Enumeration":"👤",
               "Default Credentials":"🔓","Rate Limit Bypass":"⏱","SQL Injection":"💉",
               "XSS Reflection":"⚡","Open Redirect":"↪","Directory Traversal":"📂",
               "Sensitive File Exposure":"📁","API Auth Testing":"🔌","CORS Misconfiguration":"🌐",
               "CSRF Detection":"🎯","Clickjacking":"🖱","Error & Stack Trace":"🔍",
               "Subdomain Discovery":"🌐","cPanel / WHM Testing":"⚙","WAF Fingerprint":"🧱"}
        for mod in ScanEngine.MODULES:
            var=tk.BooleanVar(value=True); self.mod_vars[mod]=var
            tk.Checkbutton(inner,text=f"{icons.get(mod,'◆')} {mod}",variable=var,
                           font=("Helvetica",10),fg=C["t1"],bg=C["bg3"],
                           activeforeground=C["cyan"],activebackground=C["bg3"],
                           selectcolor=C["bg4"],relief="flat",anchor="w",cursor="hand2").pack(fill="x",pady=2)

    def _preset_auth(self):
        auth={"SSL/TLS","Cookie Security","JWT Analysis","Admin Panel Discovery","Auth Bypass",
              "Account Enumeration","Default Credentials","Rate Limit Bypass","CSRF Detection","cPanel / WHM Testing"}
        for m,v in self.mod_vars.items(): v.set(m in auth)

    # ── Findings ──────────────────────────────────────────────────────────────
    def _mk_findings(self):
        pg=tk.Frame(self._c,bg=C["bg2"]); self._pages["Findings"]=pg
        self._hdr(pg,"Findings","Pen-test weakpoints — location, controlled exploitation & remediation")
        # Filter bar
        fb=tk.Frame(pg,bg=C["bg3"]); fb.pack(fill="x",padx=24,pady=(0,10))
        fi=tk.Frame(fb,bg=C["bg3"]); fi.pack(fill="x",padx=14,pady=8)
        tk.Label(fi,text="SEVERITY:",font=("Courier",7,"bold"),fg=C["t3"],bg=C["bg3"]).pack(side="left",padx=(0,8))
        self.filt_sev=tk.StringVar(value="ALL")
        for l,col in [("ALL",C["t1"]),("CRITICAL",C["red"]),("HIGH",C["orange"]),
                       ("MEDIUM",C["yellow"]),("LOW",C["cyan"]),("INFO",C["t2"])]:
            tk.Radiobutton(fi,text=l,variable=self.filt_sev,value=l,font=("Courier",9,"bold"),fg=col,bg=C["bg3"],
                           activeforeground=col,activebackground=C["bg3"],selectcolor=C["bg4"],
                           relief="flat",cursor="hand2",command=self._refresh_findings).pack(side="left",padx=4)
        tk.Label(fi,text="   EXPLOIT:",font=("Courier",7,"bold"),fg=C["t3"],bg=C["bg3"]).pack(side="left",padx=(8,6))
        self.filt_conf=tk.StringVar(value="ALL")
        for l,col in [("ALL",C["t1"]),("CONFIRMED",C["red"]),("RISK",C["yellow"])]:
            tk.Radiobutton(fi,text=l,variable=self.filt_conf,value=l,font=("Courier",9,"bold"),fg=col,bg=C["bg3"],
                           activeforeground=col,activebackground=C["bg3"],selectcolor=C["bg4"],
                           relief="flat",cursor="hand2",command=self._refresh_findings).pack(side="left",padx=4)
        self._fcount=tk.Label(fi,text="0",font=("Courier",9),fg=C["t3"],bg=C["bg3"]); self._fcount.pack(side="right")
        # Split view
        sp=tk.Frame(pg,bg=C["bg2"]); sp.pack(fill="both",expand=True,padx=24,pady=(0,20))
        lf=tk.Frame(sp,bg=C["bg3"]); lf.pack(side="left",fill="both",expand=True,padx=(0,8))
        th=tk.Frame(lf,bg=C["bg4"]); th.pack(fill="x")
        for t,w in [("SEV",7),("FINDING",32),("MODULE",15),("EXPLOIT",11),("TIME",7)]:
            tk.Label(th,text=t,font=("Courier",7,"bold"),fg=C["t4"],bg=C["bg4"],anchor="w",pady=7,padx=8,width=w).pack(side="left")
        lw=tk.Frame(lf,bg=C["bg3"]); lw.pack(fill="both",expand=True)
        self._fcanv=tk.Canvas(lw,bg=C["bg3"],highlightthickness=0)
        fsb=tk.Scrollbar(lw,orient="vertical",command=self._fcanv.yview,bg=C["bg3"])
        self._fcanv.configure(yscrollcommand=fsb.set); fsb.pack(side="right",fill="y"); self._fcanv.pack(side="left",fill="both",expand=True)
        self._flist=tk.Frame(self._fcanv,bg=C["bg3"])
        fw=self._fcanv.create_window((0,0),window=self._flist,anchor="nw")
        self._flist.bind("<Configure>",lambda e:self._fcanv.configure(scrollregion=self._fcanv.bbox("all")))
        self._fcanv.bind("<Configure>",lambda e:self._fcanv.itemconfig(fw,width=e.width))
        self._fcanv.bind_all("<MouseWheel>",lambda e:self._fcanv.yview_scroll(-1*(e.delta//120),"units"))
        # Detail panel — shows real request/response/proof
        det=tk.Frame(sp,bg=C["bg3"],width=440); det.pack(side="left",fill="y"); det.pack_propagate(False)
        self._sub_hdr(det,"WEAKPOINT & EXPLOITATION ANALYSIS")
        self._det=scrolledtext.ScrolledText(det,font=("Courier",9),bg=C["bg4"],fg=C["t1"],
                                             insertbackground=C["cyan"],relief="flat",padx=12,pady=10,
                                             state="disabled",wrap="word")
        self._det.pack(fill="both",expand=True,padx=8,pady=(0,8))
        for tag,kw in [
            ("title",{"foreground":C["cyan"],"font":("Courier",11,"bold")}),
            ("sc_C",{"foreground":C["red"],"font":("Courier",10,"bold")}),
            ("sc_H",{"foreground":C["orange"],"font":("Courier",10,"bold")}),
            ("sc_M",{"foreground":C["yellow"],"font":("Courier",10,"bold")}),
            ("sc_L",{"foreground":C["cyan"],"font":("Courier",10,"bold")}),
            ("sc_I",{"foreground":C["t2"],"font":("Courier",10,"bold")}),
            ("lbl",{"foreground":C["t3"],"font":("Courier",8,"bold")}),
            ("technique",{"foreground":C["purple"],"font":("Courier",9,"bold")}),
            ("req",{"foreground":C["cyan"],"font":("Courier",9)}),
            ("resp",{"foreground":C["orange"],"font":("Courier",9)}),
            ("proof",{"foreground":C["green"],"font":("Courier",9,"bold")}),
            ("location",{"foreground":C["cyan2"],"font":("Courier",9,"bold")}),
            ("remediation",{"foreground":C["green"],"font":("Courier",9)}),
            ("analysis",{"foreground":C["t1"],"font":("Courier",9)}),
            ("body",{"foreground":C["t1"]}),
            ("sep",{"foreground":C["t4"]}),
            ("confirmed",{"foreground":C["red"],"font":("Courier",9,"bold")}),
            ("risk",{"foreground":C["yellow"],"font":("Courier",9,"bold")}),
        ]:
            self._det.tag_configure(tag,**kw)

    def _refresh_findings(self):
        for w in self._flist.winfo_children(): w.destroy()
        fsev=self.filt_sev.get(); fcon=self.filt_conf.get()
        shown=[]
        for f in self.findings:
            if fsev!="ALL" and f.severity!=fsev: continue
            if fcon=="CONFIRMED" and not f.exploit.confirmed: continue
            if fcon=="RISK" and f.exploit.confirmed: continue
            shown.append(f)
        shown.sort(key=lambda x:(0 if x.exploit.confirmed else 1,
                                  SEV_ORDER.index(x.severity) if x.severity in SEV_ORDER else 99))
        self._fcount.configure(text=f"{len(shown)} findings")
        if not shown:
            tk.Label(self._flist,text="No findings match filter.",font=("Helvetica",11),fg=C["t3"],bg=C["bg3"]).pack(pady=40); return
        for f in shown:
            col=C.get(f.severity,C["t2"])
            conf_col=C["red"] if f.exploit.confirmed else C["yellow"]
            conf_txt="✓ CONFIRMED" if f.exploit.confirmed else "⚠ SIGNAL"
            aff=getattr(f.exploit,"location_url","") or getattr(f.exploit,"affected","") or ""
            weak=getattr(f.exploit,"location_summary","") or aff
            row=tk.Frame(self._flist,bg=C["bg3"],cursor="hand2"); row.pack(fill="x")
            tk.Frame(self._flist,bg=C["border"],height=1).pack(fill="x")
            bar=tk.Frame(row,bg=col,width=3); bar.pack(side="left",fill="y")
            inner=tk.Frame(row,bg=C["bg3"]); inner.pack(side="left",fill="x",expand=True,padx=8,pady=6)
            top_r=tk.Frame(inner,bg=C["bg3"]); top_r.pack(fill="x")
            tk.Label(top_r,text=f.severity,font=("Courier",8,"bold"),fg=col,bg=C["bg3"]).pack(side="left")
            if f.cvss: tk.Label(top_r,text=f" CVSS {f.cvss}",font=("Courier",7),fg=C["yellow"],bg=C["bg3"]).pack(side="left")
            tk.Label(top_r,text=f.timestamp,font=("Courier",7),fg=C["t4"],bg=C["bg3"]).pack(side="right")
            tk.Label(top_r,text=conf_txt,font=("Courier",7,"bold"),fg=conf_col,bg=C["bg3"]).pack(side="right",padx=8)
            tk.Label(inner,text=f.title,font=("Helvetica",10,"bold"),fg=C["t1"],bg=C["bg3"],anchor="w").pack(fill="x")
            url_row=tk.Frame(inner,bg=C["bg3"]); url_row.pack(fill="x",pady=(1,0))
            if weak:
                url_lbl=tk.Label(url_row,text=weak,font=("Courier",8),fg=C["cyan2"],bg=C["bg3"],anchor="w",cursor="hand2")
                url_lbl.pack(side="left",fill="x",expand=True)
                def _copy_url(u=aff or weak):
                    self.clipboard_clear(); self.clipboard_append(u)
                    self._plbl.configure(text=f"Copied: {u[:60]}")
                copy_btn=tk.Button(url_row,text="⎘",font=("Courier",8),bg=C["bg4"],fg=C["cyan"],
                                   relief="flat",padx=4,pady=0,cursor="hand2",command=_copy_url)
                copy_btn.pack(side="right",padx=(4,0))
            else:
                tk.Label(url_row,text="—",font=("Courier",8),fg=C["t4"],bg=C["bg3"],anchor="w").pack(side="left")
            comp=getattr(f.exploit,"component","")
            if comp:
                tk.Label(inner,text=f"> {comp}",font=("Helvetica",8),fg=C["purple"],bg=C["bg3"],anchor="w").pack(fill="x")
            tk.Label(inner,text=f.module,font=("Helvetica",8),fg=C["t3"],bg=C["bg3"],anchor="w").pack(fill="x")
            for w in [row,inner,top_r,bar,url_row]:
                w.bind("<Button-1>",lambda e,finding=f:self._show_detail(finding))
                w.bind("<Enter>",lambda e,r=row,i=inner,t2=top_r,ur=url_row:[x.configure(bg=C["bg_hover"]) for x in [r,i,t2,ur]])
                w.bind("<Leave>",lambda e,r=row,i=inner,t2=top_r,ur=url_row:[x.configure(bg=C["bg3"]) for x in [r,i,t2,ur]])

    def _show_detail(self, f):
        self._det.configure(state="normal"); self._det.delete("1.0","end")
        ex = f.exploit
        sc_tag={"CRITICAL":"sc_C","HIGH":"sc_H","MEDIUM":"sc_M","LOW":"sc_L"}.get(f.severity,"sc_I")
        self._det.insert("end",f"  {f.severity}",sc_tag)
        if f.cvss: self._det.insert("end",f"  CVSS {f.cvss}  ","lbl")
        if f.cve:  self._det.insert("end",f"{f.cve}","lbl")
        self._det.insert("end","\n")
        self._det.insert("end",f"{f.title}\n","title")
        grade = getattr(ex, "evidence_grade", "") or (
            "✓ EXPLOIT CONFIRMED" if ex.confirmed else "⚠ SIGNAL — needs manual validation"
        )
        tag = "confirmed" if ex.confirmed else "risk"
        self._det.insert("end",f"  {grade}\n", tag)
        self._det.insert("end","━"*44+"\n","sep")

        self._det.insert("end","WEAKPOINT LOCATION\n","lbl")
        loc = getattr(ex, "location_summary", "") or getattr(ex, "affected", "") or "—"
        self._det.insert("end",f"  {loc}\n","location")
        if getattr(ex, "location_method", ""):
            self._det.insert("end",f"  Method: {ex.location_method}","body")
        if getattr(ex, "location_path", ""):
            self._det.insert("end",f"  Path: {ex.location_path}\n","body")
        if getattr(ex, "location_parameter", ""):
            self._det.insert("end",f"  Parameter: {ex.location_parameter}\n","body")
        if getattr(ex, "location_header", ""):
            self._det.insert("end",f"  Header: {ex.location_header}\n","body")
        if getattr(ex, "component", ""):
            self._det.insert("end",f"  Component: {ex.component}\n\n","body")
        else:
            self._det.insert("end","\n")

        if getattr(ex, "exploitation_analysis", ""):
            self._det.insert("end","CONTROLLED EXPLOITATION ANALYSIS\n","lbl")
            self._det.insert("end",f"{ex.exploitation_analysis}\n\n","analysis")
        else:
            access = getattr(ex, "access_level", "Unknown")
            succ = "SUCCESSFUL" if getattr(ex, "success", False) else "UNSUCCESSFUL/BLIND"
            self._det.insert("end","CONTROLLED EXPLOITATION IMPACT\n","lbl")
            self._det.insert("end",f"  Status: {succ}\n  Access if abused: {access}\n\n","body")

        if getattr(ex, "reproduction", ""):
            self._det.insert("end","REPRODUCTION (CONTROLLED)\n","lbl")
            self._det.insert("end",f"{ex.reproduction[:1500]}\n\n","proof")

        if getattr(ex, "attacker_scenario", ""):
            self._det.insert("end","ATTACKER SCENARIO\n","lbl")
            self._det.insert("end",f"{ex.attacker_scenario}\n\n","body")

        if getattr(ex, "blast_radius", ""):
            self._det.insert("end","BLAST RADIUS\n","lbl")
            self._det.insert("end",f"{ex.blast_radius}\n\n","body")

        self._det.insert("end","DESCRIPTION\n","lbl")
        self._det.insert("end",f"{f.description}\n\n","body")

        if getattr(ex, "remediation", ""):
            self._det.insert("end","REMEDIATION (FIX BEFORE ATTACKERS)\n","lbl")
            self._det.insert("end",f"{ex.remediation}\n\n","remediation")

        if ex.technique:
            self._det.insert("end","EXPLOIT TECHNIQUE\n","lbl")
            self._det.insert("end",f"{ex.technique}\n\n","technique")
        if ex.request:
            self._det.insert("end","REQUEST SENT\n","lbl")
            self._det.insert("end",f"{ex.request[:800]}\n\n","req")
        if ex.response:
            self._det.insert("end","SERVER RESPONSE\n","lbl")
            self._det.insert("end",f"{ex.response[:800]}\n\n","resp")
        if ex.proof:
            self._det.insert("end","EVIDENCE CHAIN\n","lbl")
            self._det.insert("end",f"{ex.proof[:1200]}\n\n","proof")
        self._det.insert("end","━"*44+"\n","sep")
        conf = float(getattr(ex, "confidence", 0) or 0)
        self._det.insert("end",f"Confidence: {conf:.0%}  ·  Module: {f.module}  ·  {f.timestamp}","lbl")
        self._det.configure(state="disabled")

    # ── Live Log ──────────────────────────────────────────────────────────────
    def _mk_log(self):
        pg=tk.Frame(self._c,bg=C["bg2"]); self._pages["Live Log"]=pg
        self._hdr(pg,"Live Log","Real-time exploit verification feed")
        self._log=scrolledtext.ScrolledText(pg,font=("Courier",10),bg="#020810",fg=C["t1"],
                                             insertbackground=C["cyan"],relief="flat",padx=16,pady=12,
                                             state="disabled")
        self._log.pack(fill="both",expand=True,padx=24,pady=(0,20))
        self._log.tag_config("time",foreground=C["t4"])
        self._log.tag_config("info",foreground=C["t2"])
        self._log.tag_config("success",foreground=C["green"])
        self._log.tag_config("warn",foreground=C["yellow"])
        self._log.tag_config("error",foreground=C["red"])
        self._log.tag_config("module",foreground=C["cyan"])
        self._log.tag_config("exploit",foreground=C["purple"])
        self._logn=0
        # Clear button
        tb=tk.Frame(pg,bg=C["bg3"]); tb.pack(fill="x",padx=24,pady=(0,10))
        tk.Button(tb,text="Clear Log",font=("Courier",8,"bold"),bg=C["bg4"],fg=C["t2"],
                  relief="flat",padx=10,pady=5,cursor="hand2",command=self._clear_log).pack(side="right")

    def _clear_log(self):
        self._log.configure(state="normal"); self._log.delete("1.0","end")
        self._log.configure(state="disabled"); self._logn=0

    # ── Reports ───────────────────────────────────────────────────────────────
    def _mk_reports(self):
        pg=tk.Frame(self._c,bg=C["bg2"]); self._pages["Reports"]=pg
        self._hdr(pg,"Reports","Export full exploit-verification reports")
        body=tk.Frame(pg,bg=C["bg2"]); body.pack(fill="both",expand=True,padx=24,pady=(0,20))
        ec=tk.Frame(body,bg=C["bg3"]); ec.pack(fill="x",pady=(0,12))
        self._sub_hdr(ec,"EXPORT")
        eb=tk.Frame(ec,bg=C["bg3"]); eb.pack(fill="x",padx=14,pady=(0,14))
        for lbl,desc,col,cmd in [
            ("HTML Report","Interactive — includes real request/response/proof for each exploit",C["cyan"],self.export_html),
            ("JSON Report","Machine-readable — full exploit evidence for SIEM / CI-CD",C["blue"],self.export_json)]:
            f=tk.Frame(eb,bg=C["bg4"]); f.pack(side="left",fill="x",expand=True,padx=(0,8 if "HTML" in lbl else 0))
            tk.Label(f,text=lbl,font=("Helvetica",12,"bold"),fg=C["t1"],bg=C["bg4"],pady=10,padx=14,anchor="w").pack(fill="x")
            tk.Label(f,text=desc,font=("Helvetica",9),fg=C["t3"],bg=C["bg4"],padx=14,anchor="w").pack(fill="x")
            tk.Button(f,text=f"⬇  {lbl}",font=("Helvetica",10,"bold"),bg=col,fg=C["bg0"],
                      relief="flat",pady=8,padx=14,cursor="hand2",command=cmd).pack(fill="x",padx=14,pady=10)
        hc=tk.Frame(body,bg=C["bg3"]); hc.pack(fill="both",expand=True)
        self._sub_hdr(hc,"SCAN HISTORY")
        hth=tk.Frame(hc,bg=C["bg4"]); hth.pack(fill="x",padx=14)
        for t,w in [("TARGET",35),("TOTAL",8),("CONFIRMED",10),("RISK",10),("DURATION",10),("TIME",18)]:
            tk.Label(hth,text=t,font=("Courier",7,"bold"),fg=C["t4"],bg=C["bg4"],anchor="w",
                     padx=8,pady=6,width=w).pack(side="left")
        self._histf=tk.Frame(hc,bg=C["bg3"]); self._histf.pack(fill="both",expand=True,padx=14,pady=(0,12))

    def _refresh_history(self):
        for w in self._histf.winfo_children(): w.destroy()
        if not self._history:
            tk.Label(self._histf,text="No scan history.",font=("Helvetica",11),fg=C["t3"],bg=C["bg3"]).pack(pady=30); return
        for target,total,confirmed,st2,elapsed,ts in reversed(self._history):
            sc=st2["CRITICAL"]*10+st2["HIGH"]*6+st2["MEDIUM"]*3+st2["LOW"]
            rl="CRITICAL" if sc>30 else "HIGH" if sc>15 else "MEDIUM" if sc>5 else "LOW" if sc>0 else "CLEAN"
            rc=C.get(rl,C["green"])
            row=tk.Frame(self._histf,bg=C["bg3"]); row.pack(fill="x",pady=1)
            tk.Frame(self._histf,bg=C["border"],height=1).pack(fill="x")
            tk.Label(row,text=target[:42],font=("Courier",9),fg=C["cyan"],bg=C["bg3"],width=35,anchor="w",padx=8,pady=7).pack(side="left")
            tk.Label(row,text=str(total),font=("Courier",9,"bold"),fg=C["t1"],bg=C["bg3"],width=8).pack(side="left")
            tk.Label(row,text=str(confirmed),font=("Courier",9,"bold"),fg=C["red"],bg=C["bg3"],width=10).pack(side="left")
            tk.Label(row,text=rl,font=("Courier",9,"bold"),fg=rc,bg=C["bg3"],width=10).pack(side="left")
            tk.Label(row,text=f"{elapsed:.1f}s",font=("Courier",9),fg=C["t2"],bg=C["bg3"],width=10).pack(side="left")
            tk.Label(row,text=ts,font=("Courier",9),fg=C["t3"],bg=C["bg3"]).pack(side="left")

    # ── Settings ──────────────────────────────────────────────────────────────
    def _mk_settings(self):
        pg=tk.Frame(self._c,bg=C["bg2"]); self._pages["Settings"]=pg
        self._hdr(pg,"Settings","About & legal notice")
        body=tk.Frame(pg,bg=C["bg2"]); body.pack(fill="x",padx=24)
        ac=tk.Frame(body,bg=C["bg3"]); ac.pack(fill="x",pady=(0,12))
        self._sub_hdr(ac,"ABOUT AUTHGUARD PRO v5.0")
        for lbl,val in [("Version","5.0.0 — Zero-Day & Controlled Verification Suite"),
                         ("Architecture","Evidence-first: every finding requires confirmed server response"),
                         ("False Positives","Actively minimized — findings require real server proof"),
                         ("Modules",f"{len(ScanEngine.MODULES)} exploit verification modules"),
                         ("Reports","HTML (interactive) + JSON (machine-readable with full evidence)")]:
            row=tk.Frame(ac,bg=C["bg3"]); row.pack(fill="x",padx=14,pady=3)
            tk.Label(row,text=f"{lbl}:",font=("Courier",9,"bold"),fg=C["t3"],bg=C["bg3"],width=14,anchor="w").pack(side="left")
            tk.Label(row,text=val,font=("Helvetica",10),fg=C["t1"],bg=C["bg3"],anchor="w",wraplength=700).pack(side="left")
        tk.Frame(ac,bg=C["bg3"],height=10).pack()
        lc=tk.Frame(body,bg=C["bg3"]); lc.pack(fill="x")
        self._sub_hdr(lc,"⚠  LEGAL NOTICE")
        tk.Label(lc,text=(
            "This tool performs active security testing including controlled exploit verification.\n"
            "ONLY use on systems you own or have EXPLICIT WRITTEN AUTHORIZATION to test.\n"
            "Unauthorized use violates the Computer Fraud and Abuse Act (CFAA) and equivalent laws.\n"
            "The authors accept NO LIABILITY for misuse. You are solely responsible for compliance with applicable laws."
        ),font=("Helvetica",10),fg=C["yellow"],bg=C["bg3"],justify="left",padx=14,pady=12,anchor="w").pack(fill="x")

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _hdr(self,parent,title,sub):
        h=tk.Frame(parent,bg=C["bg2"]); h.pack(fill="x",padx=24,pady=(18,12))
        tk.Label(h,text=title,font=("Helvetica",22,"bold"),fg=C["t1"],bg=C["bg2"]).pack(anchor="w")
        tk.Label(h,text=sub,font=("Helvetica",10),fg=C["t3"],bg=C["bg2"]).pack(anchor="w")
        tk.Frame(parent,bg=C["border"],height=1).pack(fill="x",padx=24,pady=(0,12))

    def _sub_hdr(self,parent,title):
        f=tk.Frame(parent,bg=parent.cget("bg")); f.pack(fill="x",padx=14,pady=(10,6))
        tk.Label(f,text=title,font=("Courier",7,"bold"),fg=C["t3"],bg=parent.cget("bg")).pack(side="left")
        tk.Frame(f,bg=C["border"],height=1).pack(side="left",fill="x",expand=True,padx=8,pady=4)

    def _show(self,name):
        for p in self._pages.values(): p.pack_forget()
        self._pages[name].pack(fill="both",expand=True)
        for n,b in self._nav.items(): b.activate(n==name)
        self._page=name; self._bread.configure(text=name)
        if name=="Dashboard":  self._refresh_dash()
        if name=="Findings":   self._refresh_findings()
        if name=="Reports":    self._refresh_history()

    # ── Scan Control ─────────────────────────────────────────────────────────
    def start_scan(self):
        target=self.target_var.get().strip().strip("`").strip()
        if not target or target=="https://":
            messagebox.showwarning("No Target","Enter a target URL."); return
        if not target.startswith(("http://","https://")):
            target="https://"+target; self.target_var.set(target)
        mods=[m for m,v in self.mod_vars.items() if v.get()]
        if not mods: messagebox.showwarning("No Modules","Select at least one module."); return
        self.findings=[]
        self._show("Live Log")
        self.running=True; self.scan_start=time.time()
        self._scan_btn.configure(state="disabled"); self._stop_btn.configure(state="normal")
        self._stat.configure(text="● SCANNING",fg=C["green"]); self._pbar.set(0)
        opts={"modules":mods,"stealth":self.stealth_var.get(),"timeout":self.timeout_var.get()}
        self.engine=ScanEngine(target,opts,self._log_msg,self._on_finding,self._set_prog)
        self.thread=threading.Thread(target=self._run,daemon=True); self.thread.start()
        self._log_msg("═"*60,"module")
        self._log_msg(f"  AuthGuard Pro v5.0 — Pen-Test Weakpoint Detection","module")
        self._log_msg(f"  Target  : {target}","info")
        self._log_msg(f"  Modules : {len(mods)}","info")
        self._log_msg(f"  Stealth : Level {self.stealth_var.get()}","info")
        self._log_msg("═"*60,"module")

    def _run(self):
        try: self.engine.run()
        except Exception as e: self._log_msg(f"Fatal: {e}","error")
        finally: self.after(0,self._done)

    def stop_scan(self):
        if self.engine: self.engine.stop()
        self._log_msg("Scan aborted.","warn")

    def _done(self):
        elapsed=time.time()-self.scan_start if self.scan_start else 0
        self.running=False
        before=len(self.findings)
        self.findings=[enrich_finding(f) for f in dedup_findings(self.findings)]
        if len(self.findings)<before:
            self._log_msg(f"  Deduplication: {before} → {len(self.findings)} findings","info")
        self._scan_btn.configure(state="normal"); self._stop_btn.configure(state="disabled")
        confirmed=sum(1 for f in self.findings if f.exploit.confirmed)
        self._stat.configure(text=f"● DONE  {len(self.findings)} findings  {confirmed} confirmed",fg=C["cyan"])
        self._pbar.set(100); self._plbl.configure(text="Complete")
        st2=defaultdict(int)
        for f in self.findings: st2[f.severity]+=1
        self._history.append((self.engine.target,len(self.findings),confirmed,st2,elapsed,
                               datetime.now().strftime("%Y-%m-%d %H:%M")))
        self._log_msg("═"*60,"module")
        self._log_msg(f"  Complete — {len(self.findings)} findings | {confirmed} confirmed | {elapsed:.1f}s","success")
        self._log_msg("═"*60,"module")
        self.after(1500,lambda:self._show("Findings"))

    def _log_msg(self,msg,level="info"):
        def _do():
            self._log.configure(state="normal")
            ts=datetime.now().strftime("%H:%M:%S")
            self._log.insert("end",f"[{ts}]  ","time")
            self._log.insert("end",msg+"\n",level)
            self._log.see("end"); self._log.configure(state="disabled")
            self._logn+=1
        self.after(0,_do)

    def _on_finding(self,f):
        self.findings.append(f)
        col_tag="error" if f.exploit.confirmed else "warn"
        marker="!! CONFIRMED" if f.exploit.confirmed else "!! SIGNAL"
        self._log_msg(f"  {marker} [{f.severity}] {f.title}",col_tag)
        weak=getattr(f.exploit,"location_summary","") or getattr(f.exploit,"affected","")
        if weak:
            self._log_msg(f"     Weakpoint: {weak[:120]}","info")
        grade=getattr(f.exploit,"evidence_grade","")
        if grade:
            self._log_msg(f"     Evidence: {grade[:80]}","info")
        if f.exploit.confirmed and f.exploit.proof:
            short_proof=f.exploit.proof.split('\n')[0][:80]
            self._log_msg(f"     Proof: {short_proof}","exploit")

    def _set_prog(self,pct,label):
        def _do():
            self._pbar.set(pct); self._plbl.configure(text=label)
            self._ppct.configure(text=f"{pct}%" if pct<100 else "")
        self.after(0,_do)

    def export_html(self):
        path=filedialog.asksaveasfilename(defaultextension=".html",
            filetypes=[("HTML","*.html")],initialfile=f"authguard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        if not path: return
        gen=ReportGen(self.findings,self.target_var.get(),
            time.time()-self.scan_start if self.scan_start else 0,
            [m for m,v in self.mod_vars.items() if v.get()])
        with open(path,"w",encoding="utf-8") as fh: fh.write(gen.html_report())
        messagebox.showinfo("Exported",f"HTML report saved:\n{path}")

    def export_json(self):
        path=filedialog.asksaveasfilename(defaultextension=".json",
            filetypes=[("JSON","*.json")],initialfile=f"authguard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        if not path: return
        gen=ReportGen(self.findings,self.target_var.get(),
            time.time()-self.scan_start if self.scan_start else 0,
            [m for m,v in self.mod_vars.items() if v.get()])
        with open(path,"w",encoding="utf-8") as fh: fh.write(gen.json_report())
        messagebox.showinfo("Exported",f"JSON report saved:\n{path}")

    def _clock(self):
        self._clk.configure(text=datetime.now().strftime("%H:%M:%S"))
        if self.running:
            sp=["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
            self._stat.configure(text=f"{sp[self._tick%10]} SCANNING")
        self._tick+=1; self.after(200,self._clock)

if __name__ == "__main__":
    app = AuthGuardApp()
    app.mainloop()
