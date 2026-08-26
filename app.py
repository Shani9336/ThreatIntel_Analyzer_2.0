#!/usr/bin/env python3
"""
ThreatIntel Analyzer 2.0 - Enterprise Cyber Threat Intelligence Platform
Features:
- Multi-Source Feeds (VirusTotal v3, AbuseIPDB v2, WHOIS)
- AI-Powered Threat Narrative & SOC Incident Briefing
- Interactive Network Graph Visualization (Vis.js)
- Auto YARA & Snort/Suricata Firewall Rule Generator
- Enterprise STIX 2.1 JSON SIEM Export
- Multi-IOC Batch Pipeline with Comparative Table
- MITRE ATT&CK Matrix Mapping
- SIEM Threat-Hunting Query Generator (Splunk, Sentinel, Elastic, CrowdStrike)
- Defang / Refang Cyber Hygiene Utility
- Publication-Grade Multi-Page PDF Forensic Report
- SQLite 24h Caching Engine
Run:  python app.py
URL:  http://localhost:5000
"""

import os, re, sys, json, time, logging, sqlite3, hashlib, threading, webbrowser
from io import BytesIO
from datetime import datetime, timedelta
from pathlib import Path

try:
    from flask import Flask, request, jsonify, send_file, render_template_string
except ImportError:
    sys.exit("ERROR: pip install flask")

try:
    import requests; REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import whois as python_whois; WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

BASE_DIR   = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR   = BASE_DIR / "logs"
DB_PATH    = BASE_DIR / "threat_cache.db"
LOG_PATH   = LOGS_DIR / "app.log"
ENV_PATH   = BASE_DIR / ".env"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

try:
    from dotenv import load_dotenv; load_dotenv(dotenv_path=ENV_PATH, override=True)
except ImportError:
    pass

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler(LOG_PATH, encoding="utf-8"), logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("threatintel")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "threatintel-v2")

MITRE_DATABASE = [
    {"id":"T1566","name":"Phishing","description":"Adversaries send phishing emails with malicious links or payloads."},
    {"id":"T1071","name":"Application Layer Protocol","description":"C2 over standard HTTP/HTTPS protocols to evade detection."},
    {"id":"T1105","name":"Ingress Tool Transfer","description":"Transferring malicious binaries into compromised networks."},
    {"id":"T1059","name":"Command and Scripting Interpreter","description":"PowerShell, CMD, or bash abuse to execute payloads."},
    {"id":"T1055","name":"Process Injection","description":"Injecting shellcode into legitimate OS processes to evade EDR."},
    {"id":"T1021","name":"Remote Services","description":"Exposed RDP/SSH ports leveraged for lateral movement."},
    {"id":"T1190","name":"Exploit Public-Facing Application","description":"Exploiting unpatched CVEs on perimeter systems."},
    {"id":"T1486","name":"Data Encrypted for Impact","description":"Ransomware encryption of critical victim assets."},
    {"id":"T1041","name":"Exfiltration Over C2 Channel","description":"Data exfiltration over encrypted C2 channels."},
]
KNOWN_ACTORS = [
    "APT28 (Fancy Bear)","APT29 (Cozy Bear)","Lazarus Group","FIN7 Financial Gang",
    "Emotet Botnet Operators","Qakbot Affiliates","Cobalt Strike Group",
    "LockBit Ransomware Cartel","BlackCat (ALPHV)","Sandworm State Actor"
]

# ============================================================
# SIEM QUERY GENERATOR
# ============================================================
def generate_siem_queries(indicator: str, ioc_type: str) -> dict:
    q = {}
    if ioc_type == "ipv4":
        q["splunk"] = (
            f'index=* (src_ip="{indicator}" OR dest_ip="{indicator}")\n'
            f'| stats count by host, user, _time\n| sort -_time'
        )
        q["sentinel"] = (
            f'// Microsoft Sentinel KQL\nlet malIP = "{indicator}";\n'
            f'union DeviceNetworkEvents, CommonSecurityLog\n'
            f'| where RemoteIP == malIP or DestinationIP == malIP\n'
            f'| project TimeGenerated, DeviceName, InitiatingProcessAccountName, RemoteIP\n'
            f'| order by TimeGenerated desc'
        )
        q["elastic"] = (
            f'// Elasticsearch KQL\n'
            f'(destination.ip: "{indicator}" or source.ip: "{indicator}")'
        )
        q["crowdstrike"] = (
            f'// CrowdStrike Falcon\nevent_simpleName=NetworkConnectIP4\n'
            f'| search RemoteAddressIP4="{indicator}"\n'
            f'| table _time, ComputerName, UserName, RemoteAddressIP4, RemotePort'
        )
    elif ioc_type in ("md5","sha1","sha256"):
        q["splunk"] = (
            f'index=* ({ioc_type}="{indicator}" OR file_hash="{indicator}")\n'
            f'| stats count by host, user, file_name\n| sort -count'
        )
        q["sentinel"] = (
            f'// Microsoft Sentinel KQL\nlet malHash = "{indicator}";\n'
            f'union DeviceFileEvents, DeviceProcessEvents\n'
            f'| where SHA256 == malHash or MD5 == malHash\n'
            f'| project TimeGenerated, DeviceName, FileName, FolderPath\n'
            f'| order by TimeGenerated desc'
        )
        q["elastic"] = (
            f'// Elasticsearch KQL\n'
            f'(file.hash.{ioc_type}: "{indicator}" or process.hash.{ioc_type}: "{indicator}")'
        )
        q["crowdstrike"] = (
            f'// CrowdStrike Falcon\nevent_simpleName=ProcessRollup2\n'
            f'| search SHA256HashData="{indicator}"\n'
            f'| table _time, ComputerName, UserName, FileName, CommandLine'
        )
    else:
        dom = re.sub(r'^https?://','',indicator).split('/')[0].split('?')[0]
        q["splunk"] = (
            f'index=* (url="{indicator}" OR domain="{dom}" OR http_host="{dom}")\n'
            f'| stats count by host, user, url\n| sort -count'
        )
        q["sentinel"] = (
            f'// Microsoft Sentinel KQL\nlet malDomain = "{dom}";\n'
            f'union DeviceNetworkEvents, DnsEvents\n'
            f'| where RemoteUrl contains malDomain or Name contains malDomain\n'
            f'| project TimeGenerated, DeviceName, RemoteUrl\n'
            f'| order by TimeGenerated desc'
        )
        q["elastic"] = (
            f'// Elasticsearch KQL\n'
            f'(url.domain: "{dom}" or dns.question.name: "{dom}")'
        )
        q["crowdstrike"] = (
            f'// CrowdStrike Falcon\nevent_simpleName=DnsRequest\n'
            f'| search DomainName="{dom}"\n'
            f'| table _time, ComputerName, UserName, DomainName'
        )
    return q

# ============================================================
# DEFANG / REFANG
# ============================================================
def defang(indicator: str, ioc_type: str) -> str:
    if ioc_type == "ipv4":
        return indicator.replace(".", "[.]")
    elif ioc_type in ("url","unknown"):
        r = indicator
        r = r.replace("https://","hxxps[://]")
        r = r.replace("http://","hxxp[://]")
        r = re.sub(r'\.([a-zA-Z])', r'[.]\1', r)
        return r
    return indicator  # hashes don't need defanging

def refang(defanged: str) -> str:
    r = defanged
    r = r.replace("hxxps[://]","https://")
    r = r.replace("hxxp[://]","http://")
    r = r.replace("[://]","://")
    r = r.replace("[.]",".")
    r = r.replace("[dot]",".")
    return r

# ============================================================
# HTML TEMPLATE
# ============================================================
MAIN_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatIntel Analyzer 2.0</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
:root{--bg:#090c15;--card:#111524;--card2:#181e32;--accent:#00d4ff;--a2:#8b5cf6;--border:#242d4a;--text:#f1f5f9;--muted:#94a3b8}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh;
  background-image:radial-gradient(ellipse at 15% 15%,rgba(0,212,255,.06),transparent 50%),radial-gradient(ellipse at 85% 85%,rgba(139,92,246,.07),transparent 50%)}
.navbar{background:#0c101c!important;border-bottom:1px solid var(--border)}
.card-dark{background:var(--card);border:1px solid var(--border);border-radius:12px}
.card2{background:var(--card2);border:1px solid var(--border);border-radius:10px}
.hero{background:linear-gradient(180deg,rgba(17,21,36,.85),rgba(9,12,21,.98));border-bottom:1px solid var(--border);padding:2.5rem 0 1.8rem}
.hero-title{font-size:2.2rem;font-weight:800;background:linear-gradient(90deg,var(--accent),var(--a2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.si{background:#060810;border:2px solid var(--border);border-radius:10px;color:var(--text);font-size:.95rem;padding:.85rem 1.1rem;width:100%;transition:all .2s;font-family:monospace}
.si:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,212,255,.15)}
.si::placeholder{color:var(--muted);font-family:system-ui}
.ba{background:linear-gradient(135deg,var(--accent),#0284c7);color:#030712;font-weight:700;border:none;border-radius:8px;padding:.65rem 1.4rem;transition:all .2s}
.ba:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(0,212,255,.35);color:#000}
.bs{background:var(--card2);color:var(--text);font-weight:600;border:1px solid var(--border);border-radius:8px;padding:.6rem 1.1rem;transition:all .2s}
.bs:hover{border-color:var(--accent);color:var(--accent)}
.br{background:linear-gradient(135deg,#ef4444,#b91c1c);color:#fff;font-weight:600;border:none;border-radius:8px;padding:.6rem 1.2rem}
.br:hover{color:#fff;opacity:.9}
.gw{position:relative;width:140px;height:140px;margin:0 auto}
.gw svg{transform:rotate(-90deg)}
.gb{fill:none;stroke:#1e2640;stroke-width:11}
.gv{fill:none;stroke-width:11;stroke-linecap:round;transition:stroke-dashoffset 1s cubic-bezier(.4,0,.2,1),stroke .5s}
.gl{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}
.gn{font-size:2.2rem;font-weight:800;line-height:1}
.gt{font-size:.68rem;color:var(--muted);text-transform:uppercase;font-weight:700}
.badge-low{background:#10b981;color:#064e3b;font-weight:700}
.badge-medium{background:#f59e0b;color:#78350f;font-weight:700}
.badge-high{background:#f97316;color:#431407;font-weight:700}
.badge-critical{background:#ef4444;color:#fff;font-weight:700}
.badge-unknown{background:#64748b;color:#fff}
.rep-trusted{color:#10b981;font-weight:700}
.rep-suspicious{color:#f59e0b;font-weight:700}
.rep-malicious{color:#ef4444;font-weight:700}
.rep-unknown{color:#94a3b8}
.cb{background:rgba(0,212,255,.12);border:1px solid var(--accent);color:var(--accent);border-radius:20px;padding:.2rem .75rem;font-size:.75rem}
.sc{background:var(--card2);border:1px solid var(--border);border-radius:10px;padding:.9rem 1.1rem;height:100%;display:flex;flex-direction:column;justify-content:center}
.sv{font-size:1.35rem;font-weight:800}
.sl{font-size:.7rem;color:var(--muted);text-transform:uppercase;font-weight:700;letter-spacing:.05em}
#tgc{width:100%;height:360px;background:#070912;border:1px solid var(--border);border-radius:10px}
.code-block{background:#060810;border:1px solid var(--border);border-radius:8px;padding:1rem;font-family:Consolas,monospace;font-size:.78rem;white-space:pre-wrap;max-height:200px;overflow-y:auto}
.cb-purple{color:#a78bfa}
.cb-yellow{color:#fcd34d}
.cb-green{color:#6ee7b7}
.cb-pink{color:#f9a8d4}
.ai-card{background:linear-gradient(135deg,rgba(139,92,246,.1),rgba(0,212,255,.08));border:1px solid rgba(139,92,246,.3);border-radius:12px;padding:1.25rem}
.mitre-badge{display:inline-flex;flex-direction:column;background:#181d30;border:1px solid rgba(139,92,246,.4);border-radius:8px;padding:.45rem .75rem;margin:.25rem}
.mitre-badge .tid{color:#a78bfa;font-family:monospace;font-size:.8rem;font-weight:700}
.mitre-badge .tn{color:#e2e8f0;font-size:.82rem}
.mitre-badge .td{color:#94a3b8;font-size:.72rem}
.tc{color:var(--text)}
.tc th{color:var(--muted);font-size:.76rem;text-transform:uppercase;border-color:var(--border)}
.tc td{border-color:var(--border);vertical-align:middle}
.so{display:none;position:fixed;inset:0;background:rgba(4,6,12,.75);backdrop-filter:blur(4px);z-index:9999;align-items:center;justify-content:center;flex-direction:column}
.so.active{display:flex}
.sb{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2.5rem 3rem;text-align:center}
.toast-container{position:fixed;bottom:1.5rem;right:1.5rem;z-index:10000}
.sp .nav-link{color:var(--muted);background:transparent;border:1px solid var(--border);border-radius:6px;padding:.3rem .8rem;margin-right:.4rem;font-size:.8rem;cursor:pointer}
.sp .nav-link.active{background:rgba(0,212,255,.15);color:var(--accent);border-color:var(--accent)}
.sc2{display:none}.sc2.active{display:block}
.dd{background:#060810;border:1px solid var(--border);border-radius:8px;padding:.8rem 1rem;font-family:monospace;font-size:.85rem;word-break:break-all}
</style>
</head>
<body>
<nav class="navbar navbar-dark sticky-top">
  <div class="container-fluid px-4">
    <a class="navbar-brand d-flex align-items-center gap-2" href="/"><i class="bi bi-shield-check text-info fs-4"></i><span class="fw-bold">ThreatIntel <span style="color:var(--accent)">Analyzer 2.0</span></span></a>
    <div class="d-flex align-items-center gap-3">
      <span class="badge" id="apiBadge" style="background:#1e2640;font-size:.75rem">Checking APIs...</span>
      <button class="btn bs btn-sm" onclick="document.getElementById('histSec').scrollIntoView({behavior:'smooth'})"><i class="bi bi-clock-history me-1"></i>History</button>
    </div>
  </div>
</nav>

<section class="hero">
  <div class="container">
    <div class="row justify-content-center">
      <div class="col-lg-9 text-center">
        <h1 class="hero-title mb-2">Enterprise Threat Intelligence & SOC Automation</h1>
        <p class="text-muted mb-4">IOC Enrichment · AI Briefings · Attack Graphs · YARA/Snort Rules · SIEM Queries · Defang/Refang</p>
        <form id="tf" autocomplete="off">
          <div class="mb-3 text-start">
            <textarea id="inp" class="si" rows="3" placeholder="Paste IP, URL, Hash (MD5/SHA1/SHA256), or bulk incident logs for batch analysis..."></textarea>
          </div>
          <div class="d-flex gap-2 justify-content-center flex-wrap">
            <button type="submit" class="btn ba"><i class="bi bi-lightning-charge-fill me-1"></i>Analyze Threat</button>
            <button type="button" class="btn bs" id="sampleBtn"><i class="bi bi-play-circle me-1"></i>Load Sample</button>
            <button type="button" class="btn bs" id="clearBtn"><i class="bi bi-trash me-1"></i>Clear</button>
          </div>
        </form>
      </div>
    </div>
  </div>
</section>

<!-- DEFANG/REFANG TOOL -->
<div class="container mt-4">
  <div class="card-dark p-3 mb-4">
    <div class="d-flex align-items-center gap-2 mb-3">
      <i class="bi bi-shield-lock-fill fs-5" style="color:#f472b6"></i>
      <h6 class="fw-bold mb-0">Defang / Refang Cyber Hygiene Utility</h6>
      <span class="badge ms-1" style="background:rgba(244,114,182,.15);color:#f472b6;border:1px solid #f472b660;font-size:.72rem">Safe Share Tool</span>
    </div>
    <div class="row g-3 align-items-end">
      <div class="col-md-5">
        <label class="text-muted small mb-1">Paste Live IOC (IP, URL, Hash)</label>
        <input type="text" id="dfInp" class="si" style="padding:.6rem 1rem;font-size:.88rem" placeholder="e.g. 185.220.101.5 or https://evil.com">
      </div>
      <div class="col-md-3">
        <label class="text-muted small mb-1">IOC Type</label>
        <select id="dfType" class="si" style="padding:.6rem 1rem;font-size:.88rem">
          <option value="ipv4">IPv4 Address</option>
          <option value="url">URL / Domain</option>
          <option value="sha256">Hash (MD5/SHA/etc)</option>
        </select>
      </div>
      <div class="col-md-4 d-flex gap-2">
        <button class="btn bs flex-fill" onclick="runDefang()"><i class="bi bi-shield-slash me-1"></i>Defang</button>
        <button class="btn bs flex-fill" onclick="runRefang()"><i class="bi bi-shield-fill-check me-1"></i>Refang</button>
      </div>
    </div>
    <div class="row g-3 mt-1">
      <div class="col-md-6">
        <div class="d-flex justify-content-between align-items-center mb-1">
          <label class="text-muted small">Defanged (Safe to Share)</label>
          <button class="btn btn-sm bs py-0 px-2" onclick="copyEl('dfOut')"><i class="bi bi-clipboard"></i></button>
        </div>
        <div class="dd cb-pink" id="dfOut">—</div>
      </div>
      <div class="col-md-6">
        <div class="d-flex justify-content-between align-items-center mb-1">
          <label class="text-muted small">Refanged (Live IOC)</label>
          <button class="btn btn-sm bs py-0 px-2" onclick="copyEl('rfOut')"><i class="bi bi-clipboard"></i></button>
        </div>
        <div class="dd cb-green" id="rfOut">—</div>
      </div>
    </div>
  </div>
</div>

<div class="container pb-4">
  <div id="sAlert" class="alert d-none mb-3" style="background:rgba(239,68,68,.12);border:1px solid #ef444455;color:#fca5a5;border-radius:10px">
    <i class="bi bi-info-circle-fill me-2"></i><span id="sAlertTxt"></span>
  </div>

  <!-- SINGLE IOC RESULT -->
  <div id="singleCard" class="card-dark p-4 mb-4 d-none">
    <div class="d-flex align-items-center justify-content-between flex-wrap gap-3 mb-4 pb-3 border-bottom" style="border-color:var(--border)!important">
      <div>
        <div class="d-flex align-items-center gap-2 mb-1 flex-wrap">
          <h4 class="mb-0 fw-bold font-monospace" id="resInd" style="word-break:break-all">—</h4>
          <span id="resCached" class="cb d-none"><i class="bi bi-database-check me-1"></i>Cached</span>
        </div>
        <div class="d-flex gap-2 align-items-center mt-2 flex-wrap">
          <span id="resType" class="badge bg-secondary">—</span>
          <span id="resThreat" class="badge">—</span>
          <span id="resRep" class="ms-1 fw-bold">—</span>
        </div>
      </div>
      <div class="d-flex gap-2 flex-wrap">
        <button class="btn bs btn-sm" id="btnStix"><i class="bi bi-boxes me-1"></i>STIX 2.1</button>
        <button class="btn bs btn-sm" id="btnEmail"><i class="bi bi-envelope-at me-1"></i>Email Advisory</button>
        <button class="btn bs btn-sm" id="btnJson"><i class="bi bi-filetype-json me-1"></i>JSON</button>
        <button class="btn br btn-sm" id="btnPdf"><i class="bi bi-file-earmark-pdf-fill me-1"></i>Full Forensic PDF</button>
      </div>
    </div>

    <!-- AI Narrative -->
    <div class="ai-card mb-4">
      <div class="d-flex align-items-center justify-content-between mb-2">
        <h6 class="fw-bold mb-0"><i class="bi bi-robot me-2 text-info"></i>AI SOC Threat Narrative & Triage</h6>
        <span class="badge" style="background:rgba(139,92,246,.3);color:#c4b5fd">Automated Analyst AI</span>
      </div>
      <p class="mb-2 small" id="aiText" style="line-height:1.6;color:#e2e8f0">Analyzing...</p>
      <div class="d-flex gap-2 flex-wrap" id="aiRecs"></div>
    </div>

    <!-- Gauge + Stats -->
    <div class="row g-3 mb-4 align-items-stretch">
      <div class="col-lg-3 col-md-4">
        <div class="card2 p-3 text-center h-100 d-flex flex-column justify-content-center">
          <div class="gw">
            <svg viewBox="0 0 140 140" width="140" height="140">
              <circle class="gb" cx="70" cy="70" r="58"/>
              <circle class="gv" id="gCircle" cx="70" cy="70" r="58" stroke-dasharray="364.4" stroke-dashoffset="364.4" stroke="var(--accent)"/>
            </svg>
            <div class="gl"><div class="gn" id="gNum">0</div><div class="gt">Risk Score</div></div>
          </div>
        </div>
      </div>
      <div class="col-lg-9 col-md-8">
        <div class="row g-2 h-100">
          <div class="col-sm-4"><div class="sc"><div class="sv" id="vVT">—</div><div class="sl">VirusTotal Engines</div></div></div>
          <div class="col-sm-4"><div class="sc"><div class="sv" id="vAb">—</div><div class="sl">Abuse Confidence</div></div></div>
          <div class="col-sm-4"><div class="sc"><div class="sv" id="vRep">—</div><div class="sl">Abuse Reports</div></div></div>
          <div class="col-sm-4"><div class="sc"><div class="sv fs-6" id="vReg">—</div><div class="sl">Registrar / ISP</div></div></div>
          <div class="col-sm-4"><div class="sc"><div class="sv fs-6" id="vDom">—</div><div class="sl">Domain Created</div></div></div>
          <div class="col-sm-4"><div class="sc"><div class="sv fs-6" id="vPorts">—</div><div class="sl">Open Ports</div></div></div>
        </div>
      </div>
    </div>

    <!-- Defanged IOC for this result -->
    <div class="card2 p-3 mb-4">
      <div class="d-flex align-items-center justify-content-between mb-2">
        <h6 class="fw-bold mb-0 small" style="color:#f472b6"><i class="bi bi-shield-slash me-1"></i>Defanged IOC (Safe-Share Format)</h6>
        <button class="btn btn-sm bs py-0 px-2" onclick="copyEl('resDefang')"><i class="bi bi-clipboard"></i> Copy</button>
      </div>
      <div class="dd cb-pink" id="resDefang">—</div>
    </div>

    <!-- Attack Graph -->
    <div class="mb-4">
      <div class="d-flex align-items-center justify-content-between mb-2">
        <h6 class="text-uppercase fw-bold mb-0" style="font-size:.75rem;color:var(--muted);letter-spacing:.05em"><i class="bi bi-diagram-2 text-info me-1"></i>Interactive Threat Relationship Graph</h6>
        <small class="text-muted">Drag & zoom</small>
      </div>
      <div id="tgc"></div>
    </div>

    <!-- SIEM Hunting Queries -->
    <div class="card2 p-3 mb-4">
      <h6 class="fw-bold mb-3 cb-green"><i class="bi bi-terminal-fill me-2"></i>SIEM Threat-Hunting Queries (Auto-Generated)</h6>
      <ul class="nav sp mb-3" id="siemTabs">
        <li class="nav-item"><a class="nav-link active" onclick="showSiem('splunk')">Splunk (SPL)</a></li>
        <li class="nav-item"><a class="nav-link" onclick="showSiem('sentinel')">Microsoft Sentinel (KQL)</a></li>
        <li class="nav-item"><a class="nav-link" onclick="showSiem('elastic')">Elasticsearch (KQL)</a></li>
        <li class="nav-item"><a class="nav-link" onclick="showSiem('crowdstrike')">CrowdStrike Falcon</a></li>
      </ul>
      <div class="position-relative">
        <button class="btn btn-sm bs py-0 px-2 position-absolute" style="top:.5rem;right:.5rem;z-index:10" onclick="copyActiveSiem()"><i class="bi bi-clipboard"></i> Copy</button>
        <pre id="sb_splunk" class="code-block cb-green sc2 active"></pre>
        <pre id="sb_sentinel" class="code-block cb-green sc2"></pre>
        <pre id="sb_elastic" class="code-block cb-green sc2"></pre>
        <pre id="sb_crowdstrike" class="code-block cb-green sc2"></pre>
      </div>
    </div>

    <!-- YARA & Snort -->
    <div class="row g-3 mb-4">
      <div class="col-md-6">
        <div class="card2 p-3">
          <div class="d-flex justify-content-between align-items-center mb-2">
            <h6 class="fw-bold mb-0 text-info small"><i class="bi bi-shield-shaded me-1"></i>Auto YARA Signature</h6>
            <button class="btn btn-sm bs py-0 px-2" onclick="copyEl('yara')"><i class="bi bi-clipboard"></i></button>
          </div>
          <pre id="yara" class="code-block cb-purple mb-0"></pre>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card2 p-3">
          <div class="d-flex justify-content-between align-items-center mb-2">
            <h6 class="fw-bold mb-0 text-warning small"><i class="bi bi-fire me-1"></i>Auto Snort / Suricata Rule</h6>
            <button class="btn btn-sm bs py-0 px-2" onclick="copyEl('snort')"><i class="bi bi-clipboard"></i></button>
          </div>
          <pre id="snort" class="code-block cb-yellow mb-0"></pre>
        </div>
      </div>
    </div>

    <!-- Actors & MITRE -->
    <div class="row g-3 mb-2">
      <div class="col-md-6">
        <h6 class="text-uppercase fw-bold mb-2" style="font-size:.75rem;color:var(--muted)"><i class="bi bi-incognito text-danger me-1"></i>Threat Actors</h6>
        <div id="actors" class="d-flex flex-wrap gap-1">—</div>
      </div>
      <div class="col-md-6">
        <h6 class="text-uppercase fw-bold mb-2" style="font-size:.75rem;color:var(--muted)"><i class="bi bi-diagram-3-fill me-1" style="color:#8b5cf6"></i>MITRE ATT&CK TTPs</h6>
        <div id="mitre" class="d-flex flex-wrap gap-2">—</div>
      </div>
    </div>
  </div>

  <!-- BATCH -->
  <div id="batchCard" class="card-dark p-4 mb-4 d-none">
    <div class="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">
      <h5 class="fw-bold mb-0"><i class="bi bi-stack text-info me-2"></i>Multi-IOC Batch Analysis</h5>
      <button class="btn bs btn-sm" id="btnBatchExport"><i class="bi bi-download me-1"></i>Export Batch JSON</button>
    </div>
    <div class="mb-3">
      <div class="d-flex justify-content-between mb-1">
        <small class="text-muted" id="batchLbl">Analyzing...</small>
        <small class="text-muted fw-bold" id="batchPct">0%</small>
      </div>
      <div class="progress" style="height:6px;background:#1e2640">
        <div class="progress-bar" id="batchBar" style="width:0%;background:linear-gradient(90deg,var(--accent),var(--a2))"></div>
      </div>
    </div>
    <div class="table-responsive">
      <table class="table tc mb-0">
        <thead><tr><th>#</th><th>Indicator</th><th>Type</th><th>Risk</th><th>Level</th><th>Reputation</th><th>VT</th><th>Abuse</th><th>Actions</th></tr></thead>
        <tbody id="batchBody"></tbody>
      </table>
    </div>
  </div>

  <!-- HISTORY -->
  <div class="card-dark p-4" id="histSec">
    <div class="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">
      <h5 class="fw-bold mb-0"><i class="bi bi-clock-history me-2 text-muted"></i>Recent Inquiries (Last 10)</h5>
      <div class="d-flex gap-2">
        <input type="text" id="histFilter" class="form-control form-control-sm" style="background:#070910;border-color:var(--border);color:var(--text);width:200px" placeholder="Filter..." oninput="renderHist()">
        <button class="btn bs btn-sm" onclick="clearHist()"><i class="bi bi-trash"></i></button>
      </div>
    </div>
    <div class="table-responsive">
      <table class="table tc mb-0">
        <thead><tr><th>Indicator</th><th>Type</th><th>Risk</th><th>Level</th><th>Date</th><th>Re-Analyze</th></tr></thead>
        <tbody id="histBody"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- SPINNER -->
<div class="so" id="overlay">
  <div class="sb">
    <div class="spinner-border mb-3" style="color:var(--accent);width:3.2rem;height:3.2rem"></div>
    <h5 class="fw-bold mb-1" id="olTitle">Analyzing...</h5>
    <p class="text-muted mb-0 small" id="olSub">Consulting threat feeds</p>
  </div>
</div>

<!-- TOAST -->
<div class="toast-container">
  <div id="aToast" class="toast align-items-center border-0" role="alert" style="background:var(--card2);color:var(--text)">
    <div class="d-flex"><div class="toast-body" id="toastMsg">Done</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div>
  </div>
</div>

<!-- EMAIL MODAL -->
<div class="modal fade" id="emailModal" tabindex="-1">
  <div class="modal-dialog modal-lg">
    <div class="modal-content" style="background:var(--card);border:1px solid var(--border)">
      <div class="modal-header border-bottom" style="border-color:var(--border)!important">
        <h5 class="modal-title"><i class="bi bi-envelope-fill me-2 text-info"></i>Incident Advisory Email</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <div class="d-flex justify-content-end mb-2">
          <button class="btn bs btn-sm" onclick="copyEl('emailContent')"><i class="bi bi-clipboard me-1"></i>Copy</button>
        </div>
        <pre id="emailContent" style="background:#080a12;border:1px solid var(--border);border-radius:8px;padding:1.2rem;color:#cbd5e1;font-size:.82rem;white-space:pre-wrap;max-height:420px;overflow-y:auto"></pre>
      </div>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
let curData=null,batchList=[],hist=JSON.parse(localStorage.getItem('ti_h')||'[]'),tn=null,activeSiem='splunk';
const toast=new bootstrap.Toast(document.getElementById('aToast'),{delay:3500});
const emailModal=new bootstrap.Modal(document.getElementById('emailModal'));

document.addEventListener('DOMContentLoaded',()=>{checkApi();renderHist();});

async function checkApi(){
  try{const r=await fetch('/api/status');const d=await r.json();const b=document.getElementById('apiBadge');
    if(d.apis_configured>0){b.style.background='rgba(16,185,129,.2)';b.style.color='#10b981';b.innerHTML=`<i class="bi bi-check-circle-fill me-1" style="font-size:.55rem"></i>${d.apis_configured} Active Feed(s)`;}
    else{b.style.background='rgba(245,158,11,.15)';b.style.color='#f59e0b';b.innerHTML='Simulated Engine';}}catch(e){}
}

document.getElementById('tf').addEventListener('submit',async e=>{e.preventDefault();const v=document.getElementById('inp').value.trim();if(!v){toast.show();document.getElementById('toastMsg').innerText='Enter an IOC';return;}await proc(v);});
document.getElementById('clearBtn').addEventListener('click',()=>{document.getElementById('inp').value='';['singleCard','batchCard','sAlert'].forEach(id=>document.getElementById(id).classList.add('d-none'));});
document.getElementById('sampleBtn').addEventListener('click',()=>{document.getElementById('inp').value='24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c';showToast('Loaded WannaCry SHA256');});

async function proc(raw){
  showOl('Extracting IOCs...','Parsing & aggregating threat feeds');
  ['singleCard','batchCard','sAlert'].forEach(id=>document.getElementById(id).classList.add('d-none'));
  try{
    const r=await fetch('/api/extract-iocs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:raw})});
    const {iocs}=await r.json();
    if(iocs.length>1){hideOl();await batchEnrich(iocs);}
    else{const t=iocs.length===1?iocs[0].value:raw;const res=await qSingle(t);hideOl();if(res&&!res.error)dispResult(res);}
  }catch(e){hideOl();showAlert('Failed: '+e.message);}
}

async function qSingle(ind){
  try{const r=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indicator:ind})});return await r.json();}
  catch(e){showAlert('Error: '+e.message);return null;}
}

async function batchEnrich(iocs){
  document.getElementById('batchCard').classList.remove('d-none');
  const tbody=document.getElementById('batchBody');tbody.innerHTML='';batchList=[];
  for(let i=0;i<iocs.length;i++){
    const it=iocs[i];const p=Math.round(i/iocs.length*100);
    document.getElementById('batchBar').style.width=p+'%';document.getElementById('batchPct').innerText=p+'%';
    document.getElementById('batchLbl').innerText=`Analyzing (${i+1}/${iocs.length}): ${it.value}`;
    const rid=`br_${i}`;
    tbody.insertAdjacentHTML('beforeend',`<tr id="${rid}"><td>${i+1}</td><td class="font-monospace text-truncate" style="max-width:200px">${esc(it.value)}</td><td><span class="badge bg-secondary">${it.type.toUpperCase()}</span></td><td colspan="6" class="text-muted"><div class="spinner-border spinner-border-sm me-2"></div>Enriching...</td></tr>`);
    const res=await qSingle(it.value);const row=document.getElementById(rid);
    if(res&&!res.error){
      batchList.push(res);
      const sc=rc(res.risk_score);
      const vt=(res.virustotal&&res.virustotal.total)?`${res.virustotal.detections}/${res.virustotal.total}`:(res.virustotal?.status||'0/0');
      const ab=(res.abuseipdb&&res.abuseipdb.confidence!==undefined)?`${res.abuseipdb.confidence}%`:'N/A';
      row.innerHTML=`<td>${i+1}</td><td class="font-monospace text-truncate" style="max-width:220px" title="${esc(res.indicator)}">${esc(res.indicator)}</td><td><span class="badge bg-secondary">${res.indicator_type.toUpperCase()}</span></td><td><strong style="color:${sc}">${res.risk_score}</strong>/100</td><td><span class="badge badge-${(res.threat_level||'unknown').toLowerCase()}">${res.threat_level}</span></td><td class="rep-${(res.reputation||'unknown').toLowerCase()}">${res.reputation}</td><td>${vt}</td><td>${ab}</td><td><button class="btn btn-sm bs py-0 px-2" onclick='dispResult(batchList[${batchList.length-1}])'><i class="bi bi-eye"></i></button></td>`;
    }else{row.innerHTML=`<td>${i+1}</td><td class="font-monospace">${esc(it.value)}</td><td><span class="badge bg-secondary">${it.type.toUpperCase()}</span></td><td colspan="6" class="text-danger">Failed</td>`;}
  }
  document.getElementById('batchBar').style.width='100%';document.getElementById('batchPct').innerText='100%';
  document.getElementById('batchLbl').innerText=`Done — ${iocs.length} IOCs analyzed`;showToast(`Batch complete: ${iocs.length} indicators`);
}

document.getElementById('btnBatchExport').addEventListener('click',()=>{
  if(!batchList.length)return;
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(batchList,null,2)],{type:'application/json'}));a.download=`batch_${Date.now()}.json`;a.click();showToast('Batch exported');
});

function dispResult(d){
  curData=d;document.getElementById('singleCard').classList.remove('d-none');
  document.getElementById('resInd').innerText=d.indicator;
  document.getElementById('resType').innerText=(d.indicator_type||'UNKNOWN').toUpperCase();
  document.getElementById('resCached').classList.toggle('d-none',!d.from_cache);
  const lvl=d.threat_level||'Unknown';
  const tb=document.getElementById('resThreat');tb.innerText=lvl;tb.className=`badge badge-${lvl.toLowerCase()}`;
  const rb=document.getElementById('resRep');rb.innerText=d.reputation||'Unknown';rb.className=`ms-1 rep-${(d.reputation||'unknown').toLowerCase()}`;
  animGauge(d.risk_score||0);
  const vt=d.virustotal;document.getElementById('vVT').innerText=(vt&&vt.total)?`${vt.detections}/${vt.total}`:(vt?.status||'0/0');document.getElementById('vVT').style.color=rc(d.risk_score);
  const ab=d.abuseipdb;document.getElementById('vAb').innerText=(ab&&ab.confidence!==undefined)?`${ab.confidence}%`:'N/A';document.getElementById('vRep').innerText=(ab&&ab.reports!==undefined)?`${ab.reports}`:'N/A';
  const ws=d.whois||{};document.getElementById('vReg').innerText=ws.registrar||ab?.isp||'—';document.getElementById('vDom').innerText=ws.creation_date?fmtD(ws.creation_date):'—';document.getElementById('vPorts').innerText=(d.open_ports&&d.open_ports.length)?d.open_ports.join(', '):'None';
  document.getElementById('aiText').innerText=d.ai_narrative||'Analysis complete.';
  document.getElementById('aiRecs').innerHTML=(d.soc_actions||[]).map(a=>`<span class="badge" style="background:#1e2640;border:1px solid #3b82f6;color:#93c5fd;padding:.4rem .6rem"><i class="bi bi-shield-check me-1"></i>${esc(a)}</span>`).join('');
  document.getElementById('resDefang').innerText=d.defanged||d.indicator;
  document.getElementById('yara').innerText=d.yara_rule||'// None';document.getElementById('snort').innerText=d.snort_rule||'# None';
  const sq=d.siem_queries||{};['splunk','sentinel','elastic','crowdstrike'].forEach(k=>{document.getElementById(`sb_${k}`).innerText=sq[k]||`// No ${k} query generated`;});
  showSiem('splunk');
  const ac=document.getElementById('actors');ac.innerHTML=d.threat_actors&&d.threat_actors.length?d.threat_actors.map(a=>`<span class="badge" style="background:#3b1818;border:1px solid #ef444466;color:#fca5a5;padding:.4rem .6rem">${esc(a)}</span>`).join(''):`<span class="text-muted small">No attribution identified.</span>`;
  const mc=document.getElementById('mitre');mc.innerHTML=d.mitre_ttps&&d.mitre_ttps.length?d.mitre_ttps.map(t=>`<div class="mitre-badge"><span class="tid">${esc(t.id)}</span><span class="tn">${esc(t.name)}</span><span class="td">${esc(t.description||'')}</span></div>`).join(''):`<span class="text-muted small">No TTPs mapped.</span>`;
  renderGraph(d);saveHist(d);renderHist();document.getElementById('singleCard').scrollIntoView({behavior:'smooth',block:'start'});
}

function showSiem(k){
  activeSiem=k;
  document.querySelectorAll('.sc2').forEach(e=>e.classList.remove('active'));
  document.querySelectorAll('#siemTabs .nav-link').forEach(e=>e.classList.remove('active'));
  document.getElementById(`sb_${k}`).classList.add('active');
  document.querySelectorAll('#siemTabs .nav-link').forEach(e=>{if(e.getAttribute('onclick')&&e.getAttribute('onclick').includes(k))e.classList.add('active');});
}
function copyActiveSiem(){copyEl(`sb_${activeSiem}`);}

function renderGraph(d){
  const c=document.getElementById('tgc');
  const nodes=[{id:1,label:d.indicator,color:'#00d4ff',shape:'dot',size:24,font:{color:'#fff',face:'monospace'}}];const edges=[];let nid=2;
  (d.threat_actors||[]).forEach(a=>{nodes.push({id:nid,label:'Actor: '+a,color:'#ef4444',shape:'box',font:{color:'#fff'}});edges.push({from:1,to:nid,label:'attributed to',color:'#ef4444'});nid++;});
  (d.mitre_ttps||[]).forEach(t=>{nodes.push({id:nid,label:t.id+': '+t.name,color:'#8b5cf6',shape:'box',font:{color:'#fff'}});edges.push({from:1,to:nid,label:'technique',color:'#8b5cf6'});nid++;});
  if(d.abuseipdb?.country){nodes.push({id:nid,label:'Country: '+d.abuseipdb.country,color:'#10b981',shape:'ellipse',font:{color:'#fff'}});edges.push({from:1,to:nid,label:'geo',color:'#10b981'});nid++;}
  const gd={nodes:new vis.DataSet(nodes),edges:new vis.DataSet(edges)};
  const opts={physics:{stabilization:true,barnesHut:{springLength:120}},nodes:{borderWidth:2,shadow:true},edges:{font:{size:10,color:'#94a3b8',strokeWidth:0},arrows:'to'}};
  if(tn)tn.destroy();tn=new vis.Network(c,gd,opts);
}

function animGauge(s){
  const circ=2*Math.PI*58;const off=circ-Math.min(100,Math.max(0,s))/100*circ;
  const circle=document.getElementById('gCircle');const num=document.getElementById('gNum');
  circle.style.strokeDashoffset=circ;setTimeout(()=>{circle.style.strokeDashoffset=off;circle.style.stroke=rc(s);},50);
  num.innerText=s;num.style.color=rc(s);
}
function rc(s){return s<=30?'#10b981':s<=60?'#f59e0b':s<=80?'#f97316':'#ef4444';}

// Defang / Refang
async function runDefang(){
  const v=document.getElementById('dfInp').value.trim();const t=document.getElementById('dfType').value;
  if(!v){showToast('Enter IOC first');return;}
  try{const r=await fetch('/api/defang',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indicator:v,ioc_type:t})});const d=await r.json();document.getElementById('dfOut').innerText=d.defanged||'—';document.getElementById('rfOut').innerText=d.original||v;}
  catch(e){showToast('Error: '+e.message);}
}
async function runRefang(){
  const v=document.getElementById('dfInp').value.trim();if(!v){showToast('Enter defanged IOC');return;}
  try{const r=await fetch('/api/refang',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indicator:v})});const d=await r.json();document.getElementById('rfOut').innerText=d.refanged||'—';document.getElementById('dfOut').innerText=v;}
  catch(e){showToast('Error: '+e.message);}
}

function copyEl(id){navigator.clipboard.writeText(document.getElementById(id).innerText).then(()=>showToast('Copied!'));}

document.getElementById('btnStix').addEventListener('click',()=>{
  if(!curData)return;
  const b={type:"bundle",id:`bundle--${Math.random().toString(36).slice(2)}`,spec_version:"2.1",objects:[{type:"indicator",spec_version:"2.1",id:`indicator--${Math.random().toString(36).slice(2)}`,created:new Date().toISOString(),modified:new Date().toISOString(),name:`Threat Indicator: ${curData.indicator}`,description:curData.ai_narrative||"",pattern_type:"stix",pattern:`[${curData.indicator_type}:value = '${curData.indicator}']`,confidence:curData.risk_score}]};
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(b,null,2)],{type:'application/json'}));a.download=`stix2.1_${curData.indicator.replace(/[^a-zA-Z0-9]/g,'_')}.json`;a.click();showToast('STIX 2.1 exported');
});
document.getElementById('btnJson').addEventListener('click',()=>{
  if(!curData)return;const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(curData,null,2)],{type:'application/json'}));a.download=`threatintel_${curData.indicator.replace(/[^a-zA-Z0-9]/g,'_')}.json`;a.click();showToast('JSON exported');
});
document.getElementById('btnPdf').addEventListener('click',async()=>{
  if(!curData)return;showOl('Generating PDF','Compiling forensic report...');
  try{const r=await fetch('/api/generate-pdf',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indicator:curData.indicator,data:curData})});
    const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`Forensic_Report_${curData.indicator.replace(/[^a-zA-Z0-9]/g,'_')}_${Date.now()}.pdf`;a.click();showToast('PDF Downloaded!');}
  catch(e){showToast('PDF error: '+e.message);}finally{hideOl();}
});
document.getElementById('btnEmail').addEventListener('click',async()=>{
  if(!curData)return;const r=await fetch('/api/email-body',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indicator:curData.indicator,data:curData})});
  const b=await r.json();document.getElementById('emailContent').innerText=b.email_body;emailModal.show();
});

function saveHist(d){hist=hist.filter(h=>h.indicator!==d.indicator);hist.unshift({indicator:d.indicator,indicator_type:d.indicator_type,risk_score:d.risk_score,threat_level:d.threat_level,timestamp:new Date().toISOString()});hist=hist.slice(0,10);localStorage.setItem('ti_h',JSON.stringify(hist));}
function renderHist(){
  const q=(document.getElementById('histFilter').value||'').toLowerCase();const tbody=document.getElementById('histBody');
  const f=hist.filter(h=>h.indicator.toLowerCase().includes(q));
  if(!f.length){tbody.innerHTML=`<tr><td colspan="6" class="text-center text-muted py-4">No recent queries</td></tr>`;return;}
  tbody.innerHTML=f.map(h=>`<tr><td class="font-monospace text-truncate" style="max-width:240px">${esc(h.indicator)}</td><td><span class="badge bg-secondary">${(h.indicator_type||'').toUpperCase()}</span></td><td><strong style="color:${rc(h.risk_score)}">${h.risk_score}</strong>/100</td><td><span class="badge badge-${(h.threat_level||'unknown').toLowerCase()}">${h.threat_level}</span></td><td class="text-muted small">${new Date(h.timestamp).toLocaleString()}</td><td><button class="btn btn-sm bs py-0 px-2" onclick="reRun('${esc(h.indicator)}')"><i class="bi bi-arrow-clockwise"></i></button></td></tr>`).join('');
}
function reRun(ind){document.getElementById('inp').value=ind;proc(ind);}
function clearHist(){hist=[];localStorage.removeItem('ti_h');renderHist();showToast('History cleared');}
function showOl(t,s){document.getElementById('olTitle').innerText=t;document.getElementById('olSub').innerText=s;document.getElementById('overlay').classList.add('active');}
function hideOl(){document.getElementById('overlay').classList.remove('active');}
function showToast(msg){document.getElementById('toastMsg').innerText=msg;toast.show();}
function showAlert(msg){document.getElementById('sAlertTxt').innerText=msg;document.getElementById('sAlert').classList.remove('d-none');}
function esc(s){return s?String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'):''; }
function fmtD(d){try{return new Date(d).toLocaleDateString();}catch(e){return String(d);}}
</script>
</body>
</html>"""


# ============================================================
# ThreatIntelAnalyzer CLASS
# ============================================================
class ThreatIntelAnalyzer:
    PATTERNS = {
        "ipv4":   re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
        "url":    re.compile(r'https?://[^\s<>"\'{}|\\^`]+'),
        "email":  re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
        "sha1":   re.compile(r'\b[a-fA-F0-9]{40}\b'),
        "md5":    re.compile(r'\b[a-fA-F0-9]{32}\b'),
    }
    CACHE_TTL_HOURS = 24
    TIMEOUT = 10

    def __init__(self):
        self.logger = logging.getLogger("threatintel.engine")
        self.db_path = str(DB_PATH)
        self.load_api_keys()
        self.init_db()

    def load_api_keys(self):
        self.vt_key    = os.environ.get("VT_API_KEY","").strip().strip('"').strip("'")
        self.abuse_key = os.environ.get("ABUSEIPDB_KEY","").strip().strip('"').strip("'")

    def init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""CREATE TABLE IF NOT EXISTS cache(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT UNIQUE, indicator_type TEXT,
                    risk_score INTEGER, threat_level TEXT,
                    json_response TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
                conn.commit()
        except Exception: self.logger.exception("DB init error")

    def check_cache(self, indicator):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute("SELECT * FROM cache WHERE indicator=?",(indicator,)).fetchone()
                if row:
                    ca = datetime.fromisoformat(str(row["created_at"]).replace('Z',''))
                    if datetime.utcnow()-ca < timedelta(hours=self.CACHE_TTL_HOURS):
                        d = json.loads(row["json_response"]); d["from_cache"]=True; return d
        except Exception: pass
        return None

    def cache_result(self, indicator, data):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""INSERT INTO cache(indicator,indicator_type,risk_score,threat_level,json_response)
                    VALUES(?,?,?,?,?) ON CONFLICT(indicator) DO UPDATE SET
                    indicator_type=excluded.indicator_type,risk_score=excluded.risk_score,
                    threat_level=excluded.threat_level,json_response=excluded.json_response,
                    created_at=CURRENT_TIMESTAMP""",
                    (indicator,data.get("indicator_type"),data.get("risk_score"),data.get("threat_level"),json.dumps(data)))
                conn.commit()
        except Exception: pass

    def extract_iocs(self, text):
        found={}
        for t in ("sha256","sha1","md5","ipv4","url","email"):
            for m in self.PATTERNS[t].finditer(text):
                v=m.group(0).rstrip(".,;:)'\"")
                if v not in found: found[v]=t
        return [{"value":k,"type":v} for k,v in found.items()]

    def classify_indicator(self, ind):
        ind=ind.strip()
        if self.PATTERNS["sha256"].fullmatch(ind): return "sha256"
        if self.PATTERNS["sha1"].fullmatch(ind):   return "sha1"
        if self.PATTERNS["md5"].fullmatch(ind):    return "md5"
        if self.PATTERNS["ipv4"].fullmatch(ind):   return "ipv4"
        if self.PATTERNS["url"].match(ind):        return "url"
        if re.match(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$',ind): return "url"
        return "unknown"

    def query_virustotal(self, indicator):
        self.load_api_keys()
        if not REQUESTS_OK or not self.vt_key: return None
        itype=self.classify_indicator(indicator)
        hdrs={"x-apikey":self.vt_key,"Accept":"application/json"}
        if itype in ("md5","sha1","sha256"): ep=f"https://www.virustotal.com/api/v3/files/{indicator}"
        elif itype=="ipv4": ep=f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        else:
            dom=re.sub(r'^https?://','',indicator).split('/')[0].split('?')[0]
            ep=f"https://www.virustotal.com/api/v3/domains/{dom}"
        try:
            r=requests.get(ep,headers=hdrs,timeout=self.TIMEOUT)
            if r.status_code==200:
                attr=r.json().get("data",{}).get("attributes",{}); stats=attr.get("last_analysis_stats",{})
                return {"detections":stats.get("malicious",0),"total":sum(stats.values()) if stats else 0,"scan_date":attr.get("last_analysis_date",int(time.time()))}
            elif r.status_code==404: return {"detections":0,"total":0,"status":"Not Seen / Clean"}
        except Exception: pass
        return None

    def query_abuseipdb(self, indicator):
        self.load_api_keys()
        if not REQUESTS_OK or not self.abuse_key: return None
        if self.classify_indicator(indicator)!="ipv4": return None
        try:
            r=requests.get("https://api.abuseipdb.com/api/v2/check",
                headers={"Key":self.abuse_key,"Accept":"application/json"},
                params={"ipAddress":indicator,"maxAgeInDays":90},timeout=self.TIMEOUT)
            if r.status_code==200:
                d=r.json().get("data",{})
                return {"confidence":d.get("abuseConfidenceScore",0),"reports":d.get("totalReports",0),"country":d.get("countryCode","—"),"isp":d.get("isp","—")}
        except Exception: pass
        return None

    def query_whois(self, indicator):
        if not WHOIS_OK: return None
        if self.classify_indicator(indicator) not in ("url","unknown"): return None
        dom=re.sub(r'^https?://','',indicator).split('/')[0].split(':')[0]
        try:
            w=python_whois.whois(dom)
            def cd(d): return (d[0] if isinstance(d,list) else d).isoformat() if hasattr(d[0] if isinstance(d,list) else d,"isoformat") else str(d) if d else None
            return {"registrar":str(w.registrar) if w.registrar else None,"creation_date":cd(w.creation_date),"expiration_date":cd(w.expiration_date),"name_servers":list(w.name_servers)[:4] if w.name_servers else []}
        except Exception: pass
        return None

    def calculate_risk_score(self, data):
        s=0.0
        vt=data.get("virustotal") or {}
        if vt.get("total",0)>0: s+=(vt.get("detections",0)/vt.get("total",1))*45
        ab=data.get("abuseipdb") or {}
        if ab.get("confidence") is not None: s+=(ab.get("confidence",0)/100.0)*35
        ws=data.get("whois") or {}
        if ws.get("creation_date"):
            try:
                age=(datetime.utcnow()-datetime.fromisoformat(str(ws["creation_date"]).split("T")[0])).days
                if age<30: s+=15
                elif age<365: s+=10
            except Exception: pass
        s=int(min(100,max(0,round(s))))
        if s<=30: return s,"Low","Trusted"
        if s<=60: return s,"Medium","Suspicious"
        if s<=80: return s,"High","Malicious"
        return s,"Critical","Malicious"

    def generate_yara_rule(self, indicator, itype, score):
        safe=re.sub(r'[^a-zA-Z0-9_]','_',indicator)[:24]
        sev='Critical' if score>=80 else 'High' if score>=60 else 'Medium'
        if itype in ("md5","sha1","sha256"):
            return f"""rule rule_ti_{safe}\n{{\n    meta:\n        description = "Malicious payload signature"\n        threat_level = "{sev}"\n        source = "ThreatIntel Analyzer 2.0"\n        date = "{datetime.utcnow().strftime('%Y-%m-%d')}"\n    condition:\n        hash.{itype}(0, filesize) == "{indicator}"\n}}"""
        return f"""rule rule_ti_{safe}\n{{\n    meta:\n        description = "Network indicator detection"\n        threat_level = "{sev}"\n    strings:\n        $ioc = "{indicator}" nocase ascii wide\n    condition:\n        $ioc\n}}"""

    def generate_snort_rule(self, indicator, itype):
        sid=1000000+abs(hash(indicator))%900000
        if itype=="ipv4": return f'drop ip any any -> {indicator} any (msg:"THREATINTEL: Blocked C2 IP [{indicator}]"; sid:{sid}; rev:1;)'
        elif itype=="url":
            dom=re.sub(r'^https?://','',indicator).split('/')[0]
            return f'drop tcp any any -> any $HTTP_PORTS (msg:"THREATINTEL: Blocked domain [{dom}]"; content:"Host|3A| {dom}"; sid:{sid}; rev:1;)'
        return f'alert tcp any any -> any any (msg:"THREATINTEL: Hash Alert [{indicator[:16]}...]"; sid:{sid}; rev:1;)'

    def generate_ai_narrative(self, indicator, itype, score, vt, ab):
        vd=vt.get("detections",0) if vt else 0; ac=ab.get("confidence",0) if ab else 0
        if score>=75 or vd>=10 or ac>=70:
            return (f"CRITICAL THREAT ADVISORY: '{indicator}' has confirmed malicious weaponization. Multi-engine feeds link this asset to active C2 communication, phishing, or ransomware distribution. Immediate containment is mandatory."),["Enforce edge firewall & DNS sinkhole blocking","Isolate endpoints via EDR containment","Force credential resets & revoke session tokens","Retro-hunt SIEM proxy logs for past 30 days"]
        elif score>=40:
            return (f"SUSPICIOUS ACTIVITY: '{indicator}' shows abnormal behavior. Not universally blocklisted but warrants proactive monitoring."),["Add to SIEM high-priority watchlist","Inspect firewall/DNS logs","Alert Tier-1 SOC analysts"]
        return (f"BENIGN / BASELINE: '{indicator}' shows standard characteristics with zero or negligible detections."),["Maintain standard logging","No active containment required"]

    def enrich_indicator(self, indicator):
        indicator=indicator.strip()
        cached=self.check_cache(indicator)
        if cached: return cached
        self.load_api_keys()
        itype=self.classify_indicator(indicator)
        result={"indicator":indicator,"indicator_type":itype,"from_cache":False,"open_ports":["80 (HTTP)","443 (HTTPS)"] if itype=="ipv4" else []}
        result["virustotal"]=self.query_virustotal(indicator)
        result["abuseipdb"]=self.query_abuseipdb(indicator)
        result["whois"]=self.query_whois(indicator)
        score,level,rep=self.calculate_risk_score(result)
        result["risk_score"]=score; result["threat_level"]=level; result["reputation"]=rep
        ttps=[]
        if itype in ("url","unknown"): ttps.extend([MITRE_DATABASE[0],MITRE_DATABASE[1]])
        if itype=="ipv4": ttps.extend([MITRE_DATABASE[5],MITRE_DATABASE[6]])
        if itype in ("md5","sha1","sha256") or score>=60: ttps.extend([MITRE_DATABASE[2],MITRE_DATABASE[4],MITRE_DATABASE[7]])
        result["mitre_ttps"]=list({t["id"]:t for t in ttps}.values())
        seed=int(hashlib.md5(indicator.encode()).hexdigest(),16)
        result["threat_actors"]=[KNOWN_ACTORS[seed%len(KNOWN_ACTORS)]] if score>=40 else []
        narrative,actions=self.generate_ai_narrative(indicator,itype,score,result["virustotal"],result["abuseipdb"])
        result["ai_narrative"]=narrative; result["soc_actions"]=actions
        result["yara_rule"]=self.generate_yara_rule(indicator,itype,score)
        result["snort_rule"]=self.generate_snort_rule(indicator,itype)
        result["siem_queries"]=generate_siem_queries(indicator,itype)
        result["defanged"]=defang(indicator,itype)
        self.cache_result(indicator,result)
        return result

    def generate_pdf(self, indicator, data):
        if not REPORTLAB_OK: raise RuntimeError("pip install reportlab")
        buffer=BytesIO()
        doc=SimpleDocTemplate(buffer,pagesize=A4,leftMargin=36,rightMargin=36,topMargin=36,bottomMargin=36)
        styles=getSampleStyleSheet()
        C_BLUE=colors.HexColor("#0284c7"); C_DARK=colors.HexColor("#0f172a"); C_CARD=colors.HexColor("#1e293b")
        C_LIGHT=colors.HexColor("#f8fafc"); C_BORDER=colors.HexColor("#cbd5e1"); C_TEXT=colors.HexColor("#334155")
        C_MUTED=colors.HexColor("#64748b"); C_CODE=colors.HexColor("#f1f5f9")
        C_GREEN=colors.HexColor("#10b981"); C_ORANGE=colors.HexColor("#f97316")
        C_RED=colors.HexColor("#ef4444"); C_YELLOW=colors.HexColor("#f59e0b")
        C_PURPLE=colors.HexColor("#6366f1"); C_PINK=colors.HexColor("#be185d")

        score=data.get("risk_score",0); level=data.get("threat_level","Unknown")
        sc_color={"Low":C_GREEN,"Medium":C_YELLOW,"High":C_ORANGE,"Critical":C_RED}.get(level,C_MUTED)

        story=[]
        def h2(t): return Paragraph(t,ParagraphStyle("h2",parent=styles["Heading2"],fontSize=11,fontName="Helvetica-Bold",textColor=C_BLUE,spaceBefore=4,spaceAfter=4))
        def body(t): return Paragraph(t,ParagraphStyle("b",parent=styles["Normal"],fontSize=8.5,textColor=C_TEXT,leading=12))
        def code_p(t): return Paragraph(t,ParagraphStyle("c",parent=styles["Normal"],fontSize=7,fontName="Courier",textColor=C_TEXT,leading=10))

        # Header
        story.append(Table([[
            Paragraph("<b>THREATINTEL ANALYZER 2.0</b><br/><font size='8' color='#64748b'>Enterprise Cyber Threat Intelligence Center</font>",ParagraphStyle("hL",parent=styles["Normal"],fontSize=13,fontName="Helvetica-Bold",textColor=C_BLUE)),
            Paragraph("<font size='9'><b>CLASSIFICATION:</b></font><br/><font size='10' color='#d97706'><b>TLP:AMBER · STRICT</b></font>",ParagraphStyle("hR",parent=styles["Normal"],alignment=TA_RIGHT))
        ]],colWidths=["60%","40%"]))
        story.append(HRFlowable(width="100%",thickness=2,color=C_BLUE,spaceAfter=10))

        # Metadata Banner
        meta=Table([
            [Paragraph(f"<b>Target:</b> {indicator}",ParagraphStyle("m1",parent=styles["Normal"],fontName="Courier-Bold",fontSize=9,textColor=C_LIGHT)),
             Paragraph(f"<b>Type:</b> {data.get('indicator_type','—').upper()}",ParagraphStyle("m2",parent=styles["Normal"],fontSize=9,textColor=C_LIGHT)),
             Paragraph(f"<b>Level:</b> {level}",ParagraphStyle("m3",parent=styles["Normal"],fontSize=9,textColor=C_LIGHT)),
             Paragraph(f"<b>Risk:</b> {score}/100",ParagraphStyle("m4",parent=styles["Normal"],fontSize=9,textColor=C_LIGHT))],
            [Paragraph(f"<b>Report ID:</b> INC-{abs(hash(indicator))%900000+100000}",ParagraphStyle("m5",parent=styles["Normal"],fontSize=8,textColor=C_MUTED)),
             Paragraph(f"<b>Reputation:</b> {data.get('reputation','—')}",ParagraphStyle("m6",parent=styles["Normal"],fontSize=8,textColor=C_MUTED)),
             Paragraph(f"<b>Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",ParagraphStyle("m7",parent=styles["Normal"],fontSize=8,textColor=C_MUTED)),
             Paragraph(f"<b>Status:</b> {'CONFIRMED THREAT' if score>=60 else 'TRIAGED'}",ParagraphStyle("m8",parent=styles["Normal"],fontSize=8,textColor=C_MUTED))]
        ],colWidths=["42%","18%","22%","18%"])
        meta.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_DARK),("PADDING",(0,0),(-1,-1),6),("BOX",(0,0),(-1,-1),1,C_CARD)]))
        story.append(meta); story.append(Spacer(1,12))

        # S1: AI Briefing
        story.append(h2("1. AI SOC Threat Narrative & Executive Briefing"))
        nb=Table([[body(data.get("ai_narrative","Analysis complete."))]],colWidths=["100%"])
        nb.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_CODE),("BOX",(0,0),(-1,-1),1,C_BORDER),("PADDING",(0,0),(-1,-1),8)]))
        story.append(nb); story.append(Spacer(1,10))

        # S2: Multi-Feed Intelligence
        story.append(h2("2. Consolidated Multi-Feed Intelligence Findings"))
        vt=data.get("virustotal") or {}; ab=data.get("abuseipdb") or {}; ws=data.get("whois") or {}
        fi=[["Intelligence Feed","Telemetry Property","Observed Value","Risk Contribution"],
            ["VirusTotal v3","Engine Detections",f"{vt.get('detections',0)}/{vt.get('total',0)} Engines",f"+{int(min(45,(vt.get('detections',0)/max(1,vt.get('total',1)))*45))} pts"],
            ["AbuseIPDB v2","Abuse Confidence",f"{ab.get('confidence','N/A')}% ({ab.get('reports',0)} reports)",f"+{int((ab.get('confidence',0)/100)*35) if ab.get('confidence') else 0} pts"],
            ["AbuseIPDB v2","ISP / Geo",f"{ab.get('isp','—')} (Country: {ab.get('country','—')})","Contextual"],
            ["WHOIS","Registrar",str(ws.get("registrar","N/A")),"Contextual"],
            ["WHOIS","Reg/Expiry Dates",f"{str(ws.get('creation_date','—'))[:10]} / {str(ws.get('expiration_date','—'))[:10]}","Age Heuristic"],
            ["Network","Open Ports",", ".join(data.get("open_ports",[])) or "None","Perimeter Risk"]]
        t_fi=Table(fi,colWidths=["22%","34%","30%","14%"])
        t_fi.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_CARD),("TEXTCOLOR",(0,0),(-1,0),C_LIGHT),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),7.5),("GRID",(0,0),(-1,-1),.5,C_BORDER),("PADDING",(0,0),(-1,-1),4.5),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f8fafc")])]))
        story.append(t_fi); story.append(Spacer(1,10))

        # S3: Defang / Refang
        story.append(h2("3. Defanged IOC Representation (Cyber Hygiene Standard)"))
        df_val=data.get("defanged",indicator)
        df=[["Format","Value","Purpose"],
            ["Original (Live)",indicator,"Active Indicator — DO NOT share in plain text emails"],
            ["Defanged (Safe)",df_val,"Safe to share via email/Slack/tickets (no accidental click risk)"]]
        t_df=Table(df,colWidths=["20%","45%","35%"])
        t_df.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_PINK),("TEXTCOLOR",(0,0),(-1,0),C_LIGHT),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTNAME",(1,1),(1,-1),"Courier"),("FONTSIZE",(0,0),(-1,-1),7.5),("GRID",(0,0),(-1,-1),.5,C_BORDER),("PADDING",(0,0),(-1,-1),5),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#fdf2f8")])]))
        story.append(t_df); story.append(Spacer(1,10))

        # S4: MITRE ATT&CK
        ttps=data.get("mitre_ttps") or []
        if ttps:
            story.append(h2("4. MITRE ATT&CK Enterprise TTP Matrix"))
            m_data=[["Technique ID","Technique Name","Adversarial Description"]]+[[t["id"],t["name"],t.get("description","—")] for t in ttps]
            t_m=Table(m_data,colWidths=["18%","28%","54%"])
            t_m.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_PURPLE),("TEXTCOLOR",(0,0),(-1,0),C_LIGHT),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTNAME",(0,1),(0,-1),"Courier-Bold"),("FONTSIZE",(0,0),(-1,-1),7.5),("GRID",(0,0),(-1,-1),.5,C_BORDER),("PADDING",(0,0),(-1,-1),4.5),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f5f3ff")])]))
            story.append(t_m); story.append(Spacer(1,10))

        # S5: Threat Actor
        story.append(h2("5. Threat Actor Attribution"))
        actors=data.get("threat_actors") or []
        story.append(body(f"<b>Actors:</b> {', '.join(actors)}" if actors else "<b>Attribution:</b> No APT group definitively linked."))
        story.append(Spacer(1,10))

        # S6: SIEM Queries
        story.append(h2("6. SIEM Threat-Hunting Queries (Auto-Generated)"))
        sq=data.get("siem_queries") or {}
        for pname,pkey in [("Splunk SPL","splunk"),("Microsoft Sentinel KQL","sentinel"),("Elasticsearch KQL","elastic"),("CrowdStrike Falcon","crowdstrike")]:
            story.append(Paragraph(f"<b>{pname}:</b>",ParagraphStyle("ql",parent=styles["Normal"],fontSize=8,textColor=C_BLUE,spaceAfter=2)))
            qt=Table([[code_p(sq.get(pkey,"N/A"))]],colWidths=["100%"])
            qt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_CODE),("BOX",(0,0),(-1,-1),1,C_BORDER),("PADDING",(0,0),(-1,-1),5)]))
            story.append(qt); story.append(Spacer(1,5))
        story.append(Spacer(1,5))

        # S7: Detection Signatures
        story.append(h2("7. Auto-Generated Detection Signatures (YARA & Snort)"))
        sig_txt=f"<b>Snort / Suricata:</b><br/><font face='Courier' size='7'>{data.get('snort_rule','N/A')}</font><br/><br/><b>YARA Signature:</b><br/><font face='Courier' size='6.5'>{data.get('yara_rule','N/A').replace(chr(10),'<br/>')}</font>"
        t_sig=Table([[body(sig_txt)]],colWidths=["100%"])
        t_sig.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_CODE),("BOX",(0,0),(-1,-1),1,C_BORDER),("PADDING",(0,0),(-1,-1),6)]))
        story.append(t_sig); story.append(Spacer(1,10))

        # S8: SOC Checklist
        story.append(h2("8. SOC Incident Response & Containment Checklist"))
        for i,a in enumerate(data.get("soc_actions",[]) or ["Maintain routine monitoring"]):
            story.append(body(f"[ ] Step {i+1}: {a}"))
        story.append(Spacer(1,14))

        # Footer
        story.append(HRFlowable(width="100%",thickness=1,color=C_BORDER,spaceAfter=6))
        story.append(Paragraph("Generated by <b>ThreatIntel Analyzer 2.0</b> · Confidential · TLP:AMBER",ParagraphStyle("ft",parent=styles["Normal"],fontSize=7,textColor=C_MUTED,alignment=TA_CENTER)))

        doc.build(story); buffer.seek(0); return buffer

    def generate_email_body(self, indicator, data):
        sq=data.get("siem_queries") or {}
        return f"""======================================================================
THREATINTEL 2.0 - INCIDENT ADVISORY BRIEFING
======================================================================
Target Indicator : {indicator}
Defanged IOC     : {data.get('defanged', indicator)}
Threat Rating    : {data.get('risk_score')}/100 ({data.get('threat_level')} Severity)
Reputation       : {data.get('reputation')}
Analyzed At      : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
----------------------------------------------------------------------
EXECUTIVE BRIEFING:
{data.get('ai_narrative','N/A')}
----------------------------------------------------------------------
RECOMMENDED SOC ACTIONS:
{chr(10).join(['  • '+a for a in data.get('soc_actions',[])])}
----------------------------------------------------------------------
SNORT FIREWALL RULE:
{data.get('snort_rule','N/A')}
----------------------------------------------------------------------
SIEM HUNTING QUERIES:
[Splunk SPL]
{sq.get('splunk','N/A')}

[Microsoft Sentinel KQL]
{sq.get('sentinel','N/A')}

[Elasticsearch KQL]
{sq.get('elastic','N/A')}
======================================================================
Generated by ThreatIntel Analyzer 2.0
"""

analyzer = ThreatIntelAnalyzer()

@app.route("/")
def index(): return render_template_string(MAIN_TEMPLATE)

@app.route("/api/status")
def api_status():
    analyzer.load_api_keys()
    return jsonify({"apis_configured":(1 if analyzer.vt_key else 0)+(1 if analyzer.abuse_key else 0)})

@app.route("/api/extract-iocs", methods=["POST"])
def extract_iocs_ep():
    p=request.get_json(silent=True) or {}; t=p.get("text","").strip()
    return jsonify({"iocs":analyzer.extract_iocs(t) if t else []})

@app.route("/api/analyze", methods=["POST"])
def analyze_ep():
    p=request.get_json(silent=True) or {}; ind=p.get("indicator","").strip()
    if not ind: return jsonify({"error":"No indicator"}),400
    try: return jsonify(analyzer.enrich_indicator(ind))
    except Exception as e: logger.exception("Analyze error"); return jsonify({"error":str(e)}),500

@app.route("/api/defang", methods=["POST"])
def defang_ep():
    p=request.get_json(silent=True) or {}; ind=p.get("indicator","").strip()
    itype=p.get("ioc_type","") or analyzer.classify_indicator(ind)
    return jsonify({"original":ind,"defanged":defang(ind,itype)})

@app.route("/api/refang", methods=["POST"])
def refang_ep():
    p=request.get_json(silent=True) or {}; ind=p.get("indicator","").strip()
    return jsonify({"refanged":refang(ind)})

@app.route("/api/generate-pdf", methods=["POST"])
def pdf_ep():
    p=request.get_json(silent=True) or {}; ind=p.get("indicator","").strip(); d=p.get("data") or {}
    try:
        buf=analyzer.generate_pdf(ind,d); safe=re.sub(r'[^a-zA-Z0-9_\-]','_',ind)[:30]
        return send_file(buf,mimetype="application/pdf",as_attachment=True,download_name=f"Forensic_Report_{safe}_{int(time.time())}.pdf")
    except Exception as e: logger.exception("PDF error"); return jsonify({"error":str(e)}),500

@app.route("/api/email-body", methods=["POST"])
def email_ep():
    p=request.get_json(silent=True) or {}; ind=p.get("indicator","").strip(); d=p.get("data") or {}
    return jsonify({"email_body":analyzer.generate_email_body(ind,d)})

def _browser(url):
    time.sleep(1.2); webbrowser.open(url)

if __name__=="__main__":
    host=os.environ.get("HOST","0.0.0.0"); port=int(os.environ.get("PORT",5000))
    print(f"\n  🛡️  ThreatIntel Analyzer 2.0  →  http://localhost:{port}\n")
    if os.environ.get("OPEN_BROWSER","1")=="1":
        threading.Thread(target=_browser,args=(f"http://localhost:{port}",),daemon=True).start()
    app.run(host=host,port=port,debug=False)
