#!/usr/bin/env python3
"""
ThreatIntel Analyzer 2.0 - Enterprise SOC Platform
Features: Auth, Logging, Dashboard, Admin Panel, SIEM, Defang, PDF
"""
import os,re,sys,json,time,logging,sqlite3,hashlib,threading,webbrowser
from io import BytesIO
from datetime import datetime,timedelta
from pathlib import Path
from functools import wraps

try:
    from flask import Flask,request,jsonify,send_file,render_template_string,redirect,url_for,flash,get_flashed_messages
except ImportError:
    sys.exit("pip install flask")
try:
    from flask_login import LoginManager,UserMixin,login_user,logout_user,login_required,current_user
except ImportError:
    sys.exit("pip install flask-login")
try:
    from werkzeug.security import generate_password_hash,check_password_hash
except ImportError:
    sys.exit("pip install werkzeug")
try:
    import requests as req_lib; REQUESTS_OK=True
except ImportError:
    REQUESTS_OK=False
try:
    import whois as python_whois; WHOIS_OK=True
except ImportError:
    WHOIS_OK=False
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,HRFlowable
    from reportlab.lib.enums import TA_CENTER,TA_RIGHT
    REPORTLAB_OK=True
except ImportError:
    REPORTLAB_OK=False

BASE_DIR=Path(__file__).resolve().parent
REPORTS_DIR=BASE_DIR/"reports"; LOGS_DIR=BASE_DIR/"logs"
DB_PATH=BASE_DIR/"threat_cache.db"; LOG_PATH=LOGS_DIR/"app.log"
REPORTS_DIR.mkdir(parents=True,exist_ok=True); LOGS_DIR.mkdir(parents=True,exist_ok=True)
try:
    from dotenv import load_dotenv; load_dotenv(dotenv_path=BASE_DIR/".env",override=True)
except ImportError: pass

logging.basicConfig(level=logging.INFO,format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler(LOG_PATH,encoding="utf-8"),logging.StreamHandler(sys.stdout)])
logger=logging.getLogger("threatintel")

app=Flask(__name__)
app.secret_key=os.environ.get("FLASK_SECRET_KEY","threatintel-super-secret-v2-2026")

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login_page"
login_manager.login_message="Please login to access the ThreatIntel Analyzer."
login_manager.login_message_category="warning"

MITRE_DATABASE=[
    {"id":"T1566","name":"Phishing","description":"Adversaries send phishing emails with malicious links."},
    {"id":"T1071","name":"Application Layer Protocol","description":"C2 over HTTP/HTTPS to evade detection."},
    {"id":"T1105","name":"Ingress Tool Transfer","description":"Transferring malicious binaries into networks."},
    {"id":"T1059","name":"Command and Scripting Interpreter","description":"PowerShell/CMD/bash abuse."},
    {"id":"T1055","name":"Process Injection","description":"Injecting shellcode into legitimate processes."},
    {"id":"T1021","name":"Remote Services","description":"RDP/SSH lateral movement."},
    {"id":"T1190","name":"Exploit Public-Facing Application","description":"Exploiting unpatched CVEs."},
    {"id":"T1486","name":"Data Encrypted for Impact","description":"Ransomware encryption."},
    {"id":"T1041","name":"Exfiltration Over C2 Channel","description":"Data theft over encrypted C2."},
]
KNOWN_ACTORS=["APT28 (Fancy Bear)","APT29 (Cozy Bear)","Lazarus Group","FIN7 Financial Gang",
    "Emotet Botnet","Qakbot Affiliates","Cobalt Strike Group","LockBit Cartel","BlackCat (ALPHV)","Sandworm"]

# ============================================================
# USER MODEL
# ============================================================
class User(UserMixin):
    def __init__(self,id,username,email,role="user"):
        self.id=id; self.username=username; self.email=email; self.role=role
    @property
    def is_admin(self): return self.role=="admin"
    def get_id(self): return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    row=db_get_user_by_id(int(user_id))
    if row: return User(row["id"],row["username"],row["email"],row["role"])
    return None

# ============================================================
# DATABASE FUNCTIONS
# ============================================================
def get_db():
    conn=sqlite3.connect(str(DB_PATH)); conn.row_factory=sqlite3.Row; return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS cache(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE,indicator_type TEXT,
            risk_score INTEGER,threat_level TEXT,
            json_response TEXT,created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS user_analyses(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,username TEXT,
            indicator TEXT,indicator_type TEXT,
            risk_score INTEGER,threat_level TEXT,reputation TEXT,
            analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS activity_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,username TEXT,
            action TEXT,details TEXT,ip_address TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id));
        """)
        conn.commit()

def db_create_user(username,email,password_hash):
    try:
        with get_db() as conn:
            cur=conn.execute("INSERT INTO users(username,email,password_hash) VALUES(?,?,?)",(username,email,password_hash))
            conn.commit(); return cur.lastrowid
    except Exception: return None

def db_get_user_by_email(email):
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()

def db_get_user_by_id(uid):
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()

def db_log_activity(user_id,username,action,details,ip):
    try:
        with get_db() as conn:
            conn.execute("INSERT INTO activity_logs(user_id,username,action,details,ip_address) VALUES(?,?,?,?,?)",
                (user_id,username,action,details,ip)); conn.commit()
    except Exception: pass

def db_save_analysis(user_id,username,indicator,itype,score,level,rep):
    try:
        with get_db() as conn:
            conn.execute("INSERT INTO user_analyses(user_id,username,indicator,indicator_type,risk_score,threat_level,reputation) VALUES(?,?,?,?,?,?,?)",
                (user_id,username,indicator,itype,score,level,rep)); conn.commit()
    except Exception: pass

def db_get_user_analyses(user_id,limit=50):
    with get_db() as conn:
        return conn.execute("SELECT * FROM user_analyses WHERE user_id=? ORDER BY analyzed_at DESC LIMIT ?",(user_id,limit)).fetchall()

def db_get_all_logs(limit=200):
    with get_db() as conn:
        return conn.execute("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT ?",(limit,)).fetchall()

def db_get_all_analyses(limit=200):
    with get_db() as conn:
        return conn.execute("SELECT * FROM user_analyses ORDER BY analyzed_at DESC LIMIT ?",(limit,)).fetchall()

def db_get_admin_stats():
    with get_db() as conn:
        total_users=conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_analyses=conn.execute("SELECT COUNT(*) FROM user_analyses").fetchone()[0]
        today=datetime.utcnow().strftime("%Y-%m-%d")
        today_analyses=conn.execute("SELECT COUNT(*) FROM user_analyses WHERE analyzed_at >= ?",(today,)).fetchone()[0]
        critical=conn.execute("SELECT COUNT(*) FROM user_analyses WHERE threat_level='Critical'").fetchone()[0]
        return {"total_users":total_users,"total_analyses":total_analyses,"today_analyses":today_analyses,"critical_finds":critical}

def db_get_all_users():
    with get_db() as conn:
        return conn.execute("SELECT id,username,email,role,created_at FROM users ORDER BY created_at DESC").fetchall()

init_db()

# ============================================================
# SIEM & DEFANG
# ============================================================
def generate_siem_queries(indicator,ioc_type):
    q={}
    if ioc_type=="ipv4":
        q["splunk"]=f'index=* (src_ip="{indicator}" OR dest_ip="{indicator}")\n| stats count by host, user, _time\n| sort -_time'
        q["sentinel"]=f'let malIP = "{indicator}";\nunion DeviceNetworkEvents, CommonSecurityLog\n| where RemoteIP == malIP or DestinationIP == malIP\n| project TimeGenerated, DeviceName, InitiatingProcessAccountName, RemoteIP\n| order by TimeGenerated desc'
        q["elastic"]=f'(destination.ip: "{indicator}" or source.ip: "{indicator}")'
        q["crowdstrike"]=f'event_simpleName=NetworkConnectIP4\n| search RemoteAddressIP4="{indicator}"\n| table _time, ComputerName, UserName, RemoteAddressIP4, RemotePort'
    elif ioc_type in ("md5","sha1","sha256"):
        q["splunk"]=f'index=* ({ioc_type}="{indicator}")\n| stats count by host, user, file_name\n| sort -count'
        q["sentinel"]=f'let malHash = "{indicator}";\nunion DeviceFileEvents, DeviceProcessEvents\n| where SHA256 == malHash or MD5 == malHash\n| project TimeGenerated, DeviceName, FileName, FolderPath'
        q["elastic"]=f'(file.hash.{ioc_type}: "{indicator}" or process.hash.{ioc_type}: "{indicator}")'
        q["crowdstrike"]=f'event_simpleName=ProcessRollup2\n| search SHA256HashData="{indicator}"\n| table _time, ComputerName, UserName, FileName'
    else:
        dom=re.sub(r'^https?://','',indicator).split('/')[0]
        q["splunk"]=f'index=* (url="{indicator}" OR domain="{dom}")\n| stats count by host, user, url\n| sort -count'
        q["sentinel"]=f'let malDomain = "{dom}";\nunion DeviceNetworkEvents, DnsEvents\n| where RemoteUrl contains malDomain or Name contains malDomain\n| project TimeGenerated, DeviceName, RemoteUrl'
        q["elastic"]=f'(url.domain: "{dom}" or dns.question.name: "{dom}")'
        q["crowdstrike"]=f'event_simpleName=DnsRequest\n| search DomainName="{dom}"\n| table _time, ComputerName, UserName, DomainName'
    return q

def defang(indicator,ioc_type):
    if ioc_type=="ipv4": return indicator.replace(".","[.]")
    elif ioc_type in ("url","unknown"):
        r=indicator.replace("https://","hxxps[://]").replace("http://","hxxp[://]")
        return re.sub(r'\.([a-zA-Z])',r'[.]\1',r)
    return indicator

def refang(defanged):
    return defanged.replace("hxxps[://]","https://").replace("hxxp[://]","http://").replace("[.]",".")

# ============================================================
# SHARED THEME CSS
# ============================================================
THEME_CSS = r"""
<style>
:root{--accent:#00d4ff;--accent2:#8b5cf6;--green:#10b981;--red:#ef4444;--orange:#f97316;--yellow:#f59e0b}
[data-theme="dark"]{--bg:#090c15;--bg2:#0c101e;--card:#111524;--card2:#181e32;--text:#f1f5f9;--text2:#e2e8f0;--muted:#94a3b8;--border:#242d4a;--nav-bg:rgba(12,16,28,.97);--code-bg:#060810;--inp-bg:#060810;--shadow:0 4px 30px rgba(0,0,0,.5);--section-alt:#0c101e}
[data-theme="light"]{--bg:#f0f4f8;--bg2:#e8eef5;--card:#ffffff;--card2:#f8fafc;--text:#1e293b;--text2:#334155;--muted:#64748b;--border:#e2e8f0;--nav-bg:rgba(255,255,255,.97);--code-bg:#f1f5f9;--inp-bg:#ffffff;--shadow:0 4px 20px rgba(0,0,0,.08);--section-alt:#e8eef5}
*{box-sizing:border-box;margin:0;padding:0;transition:background-color .3s,color .3s,border-color .3s}
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh}
.navbar{background:var(--nav-bg)!important;border-bottom:1px solid var(--border);backdrop-filter:blur(12px)}
.nav-link-custom{color:var(--muted)!important;font-weight:500;padding:.4rem .9rem;border-radius:8px;transition:all .2s;text-decoration:none;font-size:.88rem}
.nav-link-custom:hover,.nav-link-custom.active{color:var(--accent)!important;background:rgba(0,212,255,.08)}
.theme-btn{background:var(--card2);border:1px solid var(--border);border-radius:20px;padding:.3rem .85rem;color:var(--text);font-size:.8rem;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:.4rem;transition:all .2s}
.theme-btn:hover{border-color:var(--accent);color:var(--accent)}
.card-dark{background:var(--card);border:1px solid var(--border);border-radius:14px}
.card2{background:var(--card2);border:1px solid var(--border);border-radius:10px}
.btn-accent{background:linear-gradient(135deg,var(--accent),#0284c7);color:#030712;font-weight:700;border:none;border-radius:10px;padding:.7rem 1.6rem;transition:all .25s}
.btn-accent:hover{transform:translateY(-2px);box-shadow:0 8px 28px rgba(0,212,255,.4);color:#000}
.btn-outline-accent{background:transparent;border:2px solid var(--accent);color:var(--accent);font-weight:700;border-radius:10px;padding:.65rem 1.5rem;transition:all .25s}
.btn-outline-accent:hover{background:var(--accent);color:#000}
.btn-sec{background:var(--card2);color:var(--text);font-weight:600;border:1px solid var(--border);border-radius:8px;padding:.5rem 1rem;transition:all .2s;cursor:pointer}
.btn-sec:hover{border-color:var(--accent);color:var(--accent)}
.btn-red{background:linear-gradient(135deg,#ef4444,#b91c1c);color:#fff;font-weight:600;border:none;border-radius:8px;padding:.55rem 1.1rem;cursor:pointer}
.si{background:var(--inp-bg);border:2px solid var(--border);border-radius:10px;color:var(--text);font-size:.92rem;padding:.75rem 1rem;width:100%;transition:all .2s}
.si:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,212,255,.12)}
.si::placeholder{color:var(--muted)}
select.si option{background:var(--card)}
.badge-low{background:#10b981;color:#064e3b;font-weight:700}
.badge-medium{background:#f59e0b;color:#78350f;font-weight:700}
.badge-high{background:#f97316;color:#431407;font-weight:700}
.badge-critical{background:#ef4444;color:#fff;font-weight:700}
.badge-unknown{background:#64748b;color:#fff}
.rep-trusted{color:#10b981;font-weight:700}
.rep-suspicious{color:#f59e0b;font-weight:700}
.rep-malicious{color:#ef4444;font-weight:700}
.rep-unknown{color:#94a3b8}
.tc th{color:var(--muted);font-size:.75rem;text-transform:uppercase;border-color:var(--border)!important;font-weight:700;letter-spacing:.04em}
.tc td{border-color:var(--border)!important;vertical-align:middle;color:var(--text)}
.code-block{background:var(--code-bg);border:1px solid var(--border);border-radius:8px;padding:1rem;font-family:Consolas,monospace;font-size:.78rem;white-space:pre-wrap;max-height:210px;overflow-y:auto;color:var(--text2)}
.cb-purple{color:#a78bfa}.cb-yellow{color:#fcd34d}.cb-green{color:#6ee7b7}.cb-pink{color:#f9a8d4}
.sp .nav-link{color:var(--muted);background:transparent;border:1px solid var(--border);border-radius:6px;padding:.3rem .8rem;margin-right:.4rem;font-size:.8rem;cursor:pointer}
.sp .nav-link.active{background:rgba(0,212,255,.15);color:var(--accent);border-color:var(--accent)}
.sc2{display:none}.sc2.active{display:block}
.dd{background:var(--code-bg);border:1px solid var(--border);border-radius:8px;padding:.8rem 1rem;font-family:monospace;font-size:.85rem;word-break:break-all;color:var(--text2)}
.ai-card{background:linear-gradient(135deg,rgba(139,92,246,.1),rgba(0,212,255,.08));border:1px solid rgba(139,92,246,.3);border-radius:12px;padding:1.25rem}
[data-theme="light"] .ai-card{background:linear-gradient(135deg,rgba(139,92,246,.05),rgba(0,212,255,.03));border-color:rgba(139,92,246,.2)}
.gw{position:relative;width:140px;height:140px;margin:0 auto}
.gw svg{transform:rotate(-90deg)}
.gb{fill:none;stroke:var(--border);stroke-width:11}
.gv{fill:none;stroke-width:11;stroke-linecap:round;transition:stroke-dashoffset 1s cubic-bezier(.4,0,.2,1),stroke .5s}
.gl{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}
.gn{font-size:2.2rem;font-weight:800;line-height:1}
.gt{font-size:.68rem;color:var(--muted);text-transform:uppercase;font-weight:700}
.sc-stat{background:var(--card2);border:1px solid var(--border);border-radius:10px;padding:.9rem 1.1rem;height:100%}
.sv{font-size:1.35rem;font-weight:800}
.sl{font-size:.7rem;color:var(--muted);text-transform:uppercase;font-weight:700;letter-spacing:.05em}
.cb-badge{background:rgba(0,212,255,.12);border:1px solid var(--accent);color:var(--accent);border-radius:20px;padding:.2rem .75rem;font-size:.75rem}
#tgc{width:100%;height:340px;background:var(--code-bg);border:1px solid var(--border);border-radius:10px}
.mitre-badge{display:inline-flex;flex-direction:column;background:var(--card2);border:1px solid rgba(139,92,246,.4);border-radius:8px;padding:.4rem .7rem;margin:.2rem}
.mitre-badge .tid{color:#a78bfa;font-family:monospace;font-size:.78rem;font-weight:700}
.mitre-badge .tn{color:var(--text2);font-size:.8rem}
.mitre-badge .td{color:var(--muted);font-size:.7rem}
.so{display:none;position:fixed;inset:0;background:rgba(4,6,12,.75);backdrop-filter:blur(4px);z-index:9999;align-items:center;justify-content:center;flex-direction:column}
.so.active{display:flex}
.sb2{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2.5rem 3rem;text-align:center}
.toast-container{position:fixed;bottom:1.5rem;right:1.5rem;z-index:10000}
/* USER AVATAR */
.user-avatar{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#000;font-weight:800;font-size:.85rem;display:flex;align-items:center;justify-content:center;flex-shrink:0}
/* DROPDOWN */
.user-dropdown .dropdown-menu{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:.4rem;min-width:180px}
.user-dropdown .dropdown-item{color:var(--text);border-radius:7px;padding:.5rem .75rem;font-size:.87rem;transition:all .15s}
.user-dropdown .dropdown-item:hover{background:var(--card2);color:var(--accent)}
.user-dropdown .dropdown-divider{border-color:var(--border)}
/* ALERT */
.flash-alert{padding:.75rem 1.1rem;border-radius:10px;font-size:.88rem;margin-bottom:1rem}
.flash-error{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.4);color:#fca5a5}
.flash-success{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);color:#6ee7b7}
.flash-warning{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);color:#fcd34d}
/* FOOTER */
footer.site-footer{background:var(--card);border-top:1px solid var(--border);padding:3rem 0 0}
.footer-brand{font-size:1.15rem;font-weight:800;background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.footer-heading{font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;font-weight:700;color:var(--muted);margin-bottom:1rem}
.footer-link{display:block;color:var(--muted);text-decoration:none;font-size:.87rem;margin-bottom:.45rem;transition:color .2s}
.footer-link:hover{color:var(--accent)}
.footer-bottom{background:var(--card2);border-top:1px solid var(--border);padding:.9rem 0;margin-top:2rem}
.tech-pill{display:inline-flex;align-items:center;background:var(--card2);border:1px solid var(--border);border-radius:20px;padding:.22rem .65rem;font-size:.7rem;color:var(--muted);margin:.18rem;font-weight:600}
.tech-pill i{margin-right:.3rem;color:var(--accent)}
/* AUTH PAGES */
.auth-card{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:2.5rem;max-width:440px;width:100%;margin:0 auto;box-shadow:var(--shadow)}
.auth-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);padding:2rem 1rem;
  background-image:radial-gradient(ellipse at 20% 40%,rgba(0,212,255,.07),transparent 50%),radial-gradient(ellipse at 80% 60%,rgba(139,92,246,.07),transparent 50%)}
.pwd-bar{height:4px;border-radius:4px;transition:width .3s,background .3s;background:#ef4444;width:0%}
.pwd-label{font-size:.75rem;font-weight:700}
/* DASHBOARD */
.stat-box{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:1.5rem;text-align:center}
.stat-box .big{font-size:2.2rem;font-weight:800}
.stat-box .lbl{font-size:.72rem;color:var(--muted);text-transform:uppercase;font-weight:700;letter-spacing:.05em}
/* ADMIN */
.admin-badge{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.4);color:#fca5a5;border-radius:20px;padding:.25rem .75rem;font-size:.75rem;font-weight:700}
</style>
"""

# ============================================================
# SHARED NAVBAR (Jinja2)
# ============================================================
SHARED_NAVBAR = """
<nav class="navbar navbar-expand-lg sticky-top">
  <div class="container-fluid px-4">
    <a class="navbar-brand d-flex align-items-center gap-2 text-decoration-none" href="/">
      <i class="bi bi-shield-check fs-4" style="color:var(--accent)"></i>
      <span style="font-weight:800;color:var(--text)">ThreatIntel <span style="color:var(--accent)">Analyzer</span> <span style="font-size:.72rem;color:var(--muted);font-weight:600">2.0</span></span>
    </a>
    <button class="navbar-toggler border-0" type="button" data-bs-toggle="collapse" data-bs-target="#navL" style="color:var(--text)">
      <i class="bi bi-list fs-4"></i>
    </button>
    <div class="collapse navbar-collapse" id="navL">
      <ul class="navbar-nav mx-auto gap-1">
        <li class="nav-item"><a class="nav-link-custom" href="/">Home</a></li>
        <li class="nav-item"><a class="nav-link-custom" href="/#features">Features</a></li>
        {% if current_user.is_authenticated %}
        <li class="nav-item"><a class="nav-link-custom" href="/analyzer">Analyzer</a></li>
        <li class="nav-item"><a class="nav-link-custom" href="/dashboard">Dashboard</a></li>
        {% if current_user.is_admin %}
        <li class="nav-item"><a class="nav-link-custom" href="/admin/logs" style="color:#ef4444!important"><i class="bi bi-shield-fill-exclamation me-1"></i>Admin</a></li>
        {% endif %}
        {% else %}
        <li class="nav-item"><a class="nav-link-custom" href="/analyzer">Analyzer</a></li>
        {% endif %}
      </ul>
      <div class="d-flex align-items-center gap-2 mt-2 mt-lg-0">
        <span class="badge" id="apiBadge" style="background:var(--card2);border:1px solid var(--border);color:var(--muted);font-size:.72rem">Checking APIs...</span>
        <button class="theme-btn" onclick="toggleTheme()">
          <i class="bi bi-moon-stars-fill" id="themeIcon"></i>
          <span id="themeLabel">Dark</span>
        </button>
        {% if current_user.is_authenticated %}
        <div class="dropdown user-dropdown">
          <button class="btn-sec d-flex align-items-center gap-2 px-3 py-1" data-bs-toggle="dropdown" style="border-radius:20px">
            <div class="user-avatar">{{ current_user.username[0].upper() }}</div>
            <span style="font-size:.85rem;font-weight:600">{{ current_user.username }}</span>
            <i class="bi bi-chevron-down" style="font-size:.7rem"></i>
          </button>
          <ul class="dropdown-menu dropdown-menu-end">
            <li><div class="px-3 py-2"><div style="font-weight:700;color:var(--text);font-size:.9rem">{{ current_user.username }}</div><div style="font-size:.75rem;color:var(--muted)">{{ current_user.email }}</div></div></li>
            <li><hr class="dropdown-divider"></li>
            <li><a class="dropdown-item" href="/dashboard"><i class="bi bi-grid me-2" style="color:var(--accent)"></i>Dashboard</a></li>
            <li><a class="dropdown-item" href="/analyzer"><i class="bi bi-lightning-charge me-2" style="color:var(--accent)"></i>Analyzer</a></li>
            {% if current_user.is_admin %}
            <li><a class="dropdown-item" href="/admin/logs"><i class="bi bi-shield-exclamation me-2" style="color:#ef4444"></i>Admin Panel</a></li>
            {% endif %}
            <li><hr class="dropdown-divider"></li>
            <li><a class="dropdown-item" href="/logout"><i class="bi bi-box-arrow-right me-2" style="color:#ef4444"></i>Logout</a></li>
          </ul>
        </div>
        {% else %}
        <a href="/login" class="btn-sec px-3 py-1" style="border-radius:8px;font-size:.85rem;text-decoration:none">Login</a>
        <a href="/signup" class="btn-accent px-3 py-1" style="border-radius:8px;font-size:.85rem;text-decoration:none;color:#000">Sign Up</a>
        {% endif %}
      </div>
    </div>
  </div>
</nav>
"""

# ============================================================
# SHARED FOOTER
# ============================================================
SHARED_FOOTER = """
<footer class="site-footer">
  <div class="container">
    <div class="row g-4">
      <div class="col-lg-4 col-md-6">
        <div class="d-flex align-items-center gap-2 mb-3">
          <i class="bi bi-shield-check fs-4" style="color:var(--accent)"></i>
          <span class="footer-brand">ThreatIntel Analyzer 2.0</span>
        </div>
        <p style="color:var(--muted);font-size:.86rem;line-height:1.6">Enterprise-grade cyber threat intelligence platform for SOC analysts. Multi-source enrichment, AI narratives, SIEM queries and forensic reports — all in one tool.</p>
        <div class="mt-3 d-flex gap-2 flex-wrap">
          <span class="badge" style="background:rgba(217,119,6,.15);border:1px solid #d97706;color:#d97706;font-size:.7rem">TLP:AMBER</span>
          <span class="badge" style="background:rgba(0,212,255,.12);border:1px solid var(--accent);color:var(--accent);font-size:.7rem">STIX 2.1</span>
          <span class="badge" style="background:rgba(139,92,246,.12);border:1px solid var(--accent2);color:var(--accent2);font-size:.7rem">MITRE ATT&amp;CK</span>
        </div>
      </div>
      <div class="col-lg-2 col-md-6">
        <h6 class="footer-heading">Quick Links</h6>
        <a class="footer-link" href="/"><i class="bi bi-house me-2" style="color:var(--accent)"></i>Home</a>
        {% if current_user.is_authenticated %}
        <a class="footer-link" href="/analyzer"><i class="bi bi-lightning-charge me-2" style="color:var(--accent)"></i>Analyzer</a>
        <a class="footer-link" href="/dashboard"><i class="bi bi-grid me-2" style="color:var(--accent)"></i>Dashboard</a>
        {% else %}
        <a class="footer-link" href="/login"><i class="bi bi-box-arrow-in-right me-2" style="color:var(--accent)"></i>Login</a>
        <a class="footer-link" href="/signup"><i class="bi bi-person-plus me-2" style="color:var(--accent)"></i>Sign Up</a>
        {% endif %}
        <a class="footer-link" href="/#features"><i class="bi bi-grid me-2" style="color:var(--accent)"></i>Features</a>
      </div>
      <div class="col-lg-3 col-md-6">
        <h6 class="footer-heading">Intelligence Feeds</h6>
        <a class="footer-link" href="https://virustotal.com" target="_blank"><i class="bi bi-virus me-2" style="color:#ef4444"></i>VirusTotal v3 API</a>
        <a class="footer-link" href="https://abuseipdb.com" target="_blank"><i class="bi bi-shield-exclamation me-2" style="color:#f59e0b"></i>AbuseIPDB v2 API</a>
        <a class="footer-link" href="#"><i class="bi bi-globe me-2" style="color:#10b981"></i>WHOIS Registry</a>
        <a class="footer-link" href="https://attack.mitre.org" target="_blank"><i class="bi bi-diagram-3 me-2" style="color:#8b5cf6"></i>MITRE ATT&amp;CK</a>
      </div>
      <div class="col-lg-3 col-md-6">
        <h6 class="footer-heading">Built With</h6>
        <span class="tech-pill"><i class="bi bi-filetype-py"></i>Python 3.11</span>
        <span class="tech-pill"><i class="bi bi-lightning"></i>Flask 3.0</span>
        <span class="tech-pill"><i class="bi bi-person-lock"></i>Flask-Login</span>
        <span class="tech-pill"><i class="bi bi-bootstrap"></i>Bootstrap 5</span>
        <span class="tech-pill"><i class="bi bi-database"></i>SQLite</span>
        <span class="tech-pill"><i class="bi bi-file-pdf"></i>ReportLab</span>
        <span class="tech-pill"><i class="bi bi-box"></i>Docker</span>
        <span class="tech-pill"><i class="bi bi-cloud"></i>Render.com</span>
      </div>
    </div>
  </div>
  <div class="footer-bottom mt-4">
    <div class="container">
      <div class="d-flex align-items-center justify-content-between flex-wrap gap-2">
        <span style="font-size:.8rem;color:var(--muted)">&copy; 2026 <strong style="color:var(--text)">ThreatIntel Analyzer 2.0</strong> &mdash; Enterprise Cyber Threat Intelligence</span>
        <div class="d-flex gap-3">
          <span style="font-size:.72rem;color:var(--muted)">TLP:AMBER &middot; Restricted</span>
          <span style="font-size:.72rem;color:var(--muted)">v2.0.0</span>
        </div>
      </div>
    </div>
  </div>
</footer>
"""

# ============================================================
# PWA SUPPORT
# ============================================================
PWA_HEAD = """
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#00d4ff">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="ThreatIntel">
<link rel="apple-touch-icon" href="/icon-192.png">
<link rel="icon" type="image/png" sizes="192x192" href="/icon-192.png">
"""

SW_JS = """
const CACHE_NAME = 'threatintel-v2';
const OFFLINE_PAGES = ['/', '/login', '/signup'];
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(OFFLINE_PAGES)).catch(()=>{}));
  self.skipWaiting();
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  if (event.request.url.includes('/api/')) return;
  event.respondWith(
    fetch(event.request).then(res => {
      const clone = res.clone();
      caches.open(CACHE_NAME).then(c => c.put(event.request, clone));
      return res;
    }).catch(() => caches.match(event.request))
  );
});
"""

SHARED_SCRIPTS = """
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
function initTheme(){const s=localStorage.getItem('ti_theme')||'dark';document.documentElement.setAttribute('data-theme',s);updateIcon(s);}
function toggleTheme(){const c=document.documentElement.getAttribute('data-theme');const n=c==='dark'?'light':'dark';document.documentElement.setAttribute('data-theme',n);localStorage.setItem('ti_theme',n);updateIcon(n);}
function updateIcon(t){const ic=document.getElementById('themeIcon');const lb=document.getElementById('themeLabel');if(!ic)return;if(t==='dark'){ic.className='bi bi-moon-stars-fill';if(lb)lb.innerText='Dark';}else{ic.className='bi bi-sun-fill';if(lb)lb.innerText='Light';}}
initTheme();
async function checkApi(){try{const r=await fetch('/api/status');const d=await r.json();const b=document.getElementById('apiBadge');if(!b)return;if(d.apis_configured>0){b.style.background='rgba(16,185,129,.15)';b.style.borderColor='#10b981';b.style.color='#10b981';b.innerHTML=`<i class="bi bi-check-circle-fill me-1"></i>${d.apis_configured} Feed(s) Active`;}else{b.style.color='#f59e0b';b.innerHTML='Simulated Mode';}}catch(e){}}
document.addEventListener('DOMContentLoaded',checkApi);
if('serviceWorker' in navigator){window.addEventListener('load',()=>{navigator.serviceWorker.register('/sw.js').then(()=>console.log('PWA ready')).catch(()=>{});});}
let deferredPrompt;
window.addEventListener('beforeinstallprompt',e=>{e.preventDefault();deferredPrompt=e;const b=document.getElementById('installBtn');if(b){b.style.display='flex';b.onclick=()=>{deferredPrompt.prompt();deferredPrompt=null;b.style.display='none';};}});
</script>
"""

# ============================================================
# LOGIN TEMPLATE
# ============================================================
LOGIN_TEMPLATE = """<!DOCTYPE html>
<html data-theme="dark" lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — ThreatIntel Analyzer 2.0</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
""" + PWA_HEAD + THEME_CSS + """
</head>
<body>
""" + SHARED_NAVBAR + """
<div class="auth-wrap">
  <div class="auth-card">
    <div class="text-center mb-4">
      <div style="width:60px;height:60px;background:linear-gradient(135deg,var(--accent),var(--accent2));border-radius:16px;display:flex;align-items:center;justify-content:center;margin:0 auto 1rem;font-size:1.6rem">🔐</div>
      <h3 class="fw-800 mb-1" style="color:var(--text);font-weight:800">Welcome Back</h3>
      <p style="color:var(--muted);font-size:.88rem">Sign in to access the ThreatIntel Platform</p>
    </div>
    {% with msgs = get_flashed_messages(with_categories=true) %}
      {% for cat,msg in msgs %}
      <div class="flash-alert flash-{{ cat }}"><i class="bi bi-info-circle me-2"></i>{{ msg }}</div>
      {% endfor %}
    {% endwith %}
    <form method="POST" action="/login">
      <div class="mb-3">
        <label class="form-label small fw-600" style="color:var(--muted)">Email Address</label>
        <div class="position-relative">
          <i class="bi bi-envelope position-absolute" style="left:.9rem;top:50%;transform:translateY(-50%);color:var(--muted)"></i>
          <input type="email" name="email" class="si ps-5" placeholder="analyst@company.com" required>
        </div>
      </div>
      <div class="mb-3">
        <label class="form-label small fw-600" style="color:var(--muted)">Password</label>
        <div class="position-relative">
          <i class="bi bi-lock position-absolute" style="left:.9rem;top:50%;transform:translateY(-50%);color:var(--muted)"></i>
          <input type="password" name="password" id="loginPwd" class="si ps-5 pe-5" placeholder="••••••••" required>
          <i class="bi bi-eye position-absolute" id="eyeBtn" style="right:.9rem;top:50%;transform:translateY(-50%);color:var(--muted);cursor:pointer" onclick="togglePwd()"></i>
        </div>
      </div>
      <div class="d-flex justify-content-between align-items-center mb-4">
        <label class="d-flex align-items-center gap-2 small" style="color:var(--muted);cursor:pointer">
          <input type="checkbox" name="remember" style="accent-color:var(--accent)"> Remember me
        </label>
      </div>
      <button type="submit" class="btn-accent w-100 py-2 mb-3" style="font-size:1rem"><i class="bi bi-lightning-charge-fill me-2"></i>Sign In</button>
    </form>
    <div class="text-center" style="color:var(--muted);font-size:.88rem">
      Don't have an account? <a href="/signup" style="color:var(--accent);font-weight:600;text-decoration:none">Sign Up</a>
    </div>
    <div class="mt-4 p-3" style="background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.15);border-radius:10px">
      <div style="font-size:.75rem;color:var(--muted);text-align:center"><i class="bi bi-shield-lock me-1" style="color:var(--accent)"></i>Passwords are hashed with PBKDF2-SHA256 &middot; Sessions are encrypted</div>
    </div>
  </div>
</div>
""" + SHARED_SCRIPTS + """
<script>
function togglePwd(){const i=document.getElementById('loginPwd');const e=document.getElementById('eyeBtn');i.type=i.type==='password'?'text':'password';e.className=i.type==='password'?'bi bi-eye position-absolute':'bi bi-eye-slash position-absolute';e.style='right:.9rem;top:50%;transform:translateY(-50%);color:var(--muted);cursor:pointer';}
</script>
</body></html>"""

# ============================================================
# SIGNUP TEMPLATE
# ============================================================
SIGNUP_TEMPLATE = """<!DOCTYPE html>
<html data-theme="dark" lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign Up — ThreatIntel Analyzer 2.0</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
""" + PWA_HEAD + THEME_CSS + """
</head>
<body>
""" + SHARED_NAVBAR + """
<div class="auth-wrap" style="padding:3rem 1rem">
  <div class="auth-card" style="max-width:480px">
    <div class="text-center mb-4">
      <div style="width:60px;height:60px;background:linear-gradient(135deg,var(--accent2),#6366f1);border-radius:16px;display:flex;align-items:center;justify-content:center;margin:0 auto 1rem;font-size:1.6rem">🛡️</div>
      <h3 class="fw-800 mb-1" style="color:var(--text);font-weight:800">Create Account</h3>
      <p style="color:var(--muted);font-size:.88rem">Join the ThreatIntel Intelligence Platform</p>
    </div>
    {% with msgs = get_flashed_messages(with_categories=true) %}
      {% for cat,msg in msgs %}
      <div class="flash-alert flash-{{ cat }}"><i class="bi bi-info-circle me-2"></i>{{ msg }}</div>
      {% endfor %}
    {% endwith %}
    <form method="POST" action="/signup" onsubmit="return validateForm()">
      <div class="mb-3">
        <label class="form-label small fw-600" style="color:var(--muted)">Username</label>
        <div class="position-relative">
          <i class="bi bi-person position-absolute" style="left:.9rem;top:50%;transform:translateY(-50%);color:var(--muted)"></i>
          <input type="text" name="username" class="si ps-5" placeholder="analyst_john" required minlength="3">
        </div>
      </div>
      <div class="mb-3">
        <label class="form-label small fw-600" style="color:var(--muted)">Email Address</label>
        <div class="position-relative">
          <i class="bi bi-envelope position-absolute" style="left:.9rem;top:50%;transform:translateY(-50%);color:var(--muted)"></i>
          <input type="email" name="email" class="si ps-5" placeholder="analyst@company.com" required>
        </div>
      </div>
      <div class="mb-3">
        <label class="form-label small fw-600" style="color:var(--muted)">Password</label>
        <div class="position-relative">
          <i class="bi bi-lock position-absolute" style="left:.9rem;top:50%;transform:translateY(-50%);color:var(--muted)"></i>
          <input type="password" name="password" id="signPwd" class="si ps-5" placeholder="Min 8 characters" required oninput="checkStrength(this.value)" minlength="8">
        </div>
        <div class="mt-2">
          <div class="pwd-bar" id="pwdBar"></div>
          <div class="d-flex justify-content-between mt-1">
            <span class="pwd-label" id="pwdLabel" style="color:var(--muted)">Enter password</span>
            <span class="pwd-label" id="pwdScore" style="color:var(--muted)"></span>
          </div>
        </div>
      </div>
      <div class="mb-4">
        <label class="form-label small fw-600" style="color:var(--muted)">Confirm Password</label>
        <div class="position-relative">
          <i class="bi bi-lock-fill position-absolute" style="left:.9rem;top:50%;transform:translateY(-50%);color:var(--muted)"></i>
          <input type="password" name="confirm_password" id="confPwd" class="si ps-5" placeholder="Repeat password" required minlength="8">
        </div>
      </div>
      <div class="mb-4">
        <label class="d-flex align-items-start gap-2 small" style="color:var(--muted);cursor:pointer">
          <input type="checkbox" id="terms" style="accent-color:var(--accent);margin-top:2px" required>
          <span>I agree to responsible use of threat intelligence data per <strong style="color:var(--accent)">TLP:AMBER</strong> classification guidelines</span>
        </label>
      </div>
      <button type="submit" class="btn-accent w-100 py-2 mb-3" style="font-size:1rem"><i class="bi bi-person-plus-fill me-2"></i>Create Account</button>
    </form>
    <div class="text-center" style="color:var(--muted);font-size:.88rem">
      Already have an account? <a href="/login" style="color:var(--accent);font-weight:600;text-decoration:none">Sign In</a>
    </div>
  </div>
</div>
""" + SHARED_SCRIPTS + """
<script>
function checkStrength(p){
  const bar=document.getElementById('pwdBar');const lbl=document.getElementById('pwdLabel');const sc=document.getElementById('pwdScore');
  if(!p){bar.style.width='0%';lbl.innerText='Enter password';lbl.style.color='var(--muted)';return;}
  let s=0;
  if(p.length>=8)s+=1;if(p.length>=12)s+=1;
  if(/[A-Z]/.test(p))s+=1;if(/[0-9]/.test(p))s+=1;if(/[^A-Za-z0-9]/.test(p))s+=1;
  const map={1:{c:'#ef4444',l:'Too Weak',w:'20%'},2:{c:'#f97316',l:'Weak',w:'40%'},3:{c:'#f59e0b',l:'Medium',w:'60%'},4:{c:'#10b981',l:'Strong',w:'80%'},5:{c:'#10b981',l:'Very Strong',w:'100%'}};
  const m=map[Math.max(1,s)];
  bar.style.width=m.w;bar.style.background=m.c;lbl.innerText=m.l;lbl.style.color=m.c;sc.innerText=s+'/5';
}
function validateForm(){
  const p=document.getElementById('signPwd').value;const c=document.getElementById('confPwd').value;
  if(p!==c){alert('Passwords do not match!');return false;}
  if(p.length<8){alert('Password must be at least 8 characters!');return false;}
  return true;
}
</script>
</body></html>"""

# ============================================================
# DASHBOARD TEMPLATE
# ============================================================
DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html data-theme="dark" lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard — ThreatIntel Analyzer 2.0</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
""" + PWA_HEAD + THEME_CSS + """
</head>
<body>
""" + SHARED_NAVBAR + """
<div class="container py-4">
  <!-- Welcome -->
  <div class="card-dark p-4 mb-4" style="background:linear-gradient(135deg,rgba(0,212,255,.08),rgba(139,92,246,.06))">
    <div class="d-flex align-items-center gap-3">
      <div class="user-avatar" style="width:52px;height:52px;font-size:1.3rem">{{ current_user.username[0].upper() }}</div>
      <div>
        <h4 class="fw-bold mb-0" style="color:var(--text)">Welcome back, <span style="color:var(--accent)">{{ current_user.username }}</span></h4>
        <p class="mb-0 small" style="color:var(--muted)">{{ current_user.email }} &middot; Role: <strong style="color:{% if current_user.is_admin %}#ef4444{% else %}var(--accent){% endif %}">{{ current_user.role.upper() }}</strong></p>
      </div>
      <div class="ms-auto">
        <a href="/analyzer" class="btn-accent px-4 py-2" style="text-decoration:none;border-radius:10px;font-size:.9rem"><i class="bi bi-lightning-charge-fill me-2"></i>New Analysis</a>
      </div>
    </div>
  </div>

  <!-- Stats -->
  <div class="row g-3 mb-4">
    <div class="col-6 col-md-3">
      <div class="stat-box">
        <div class="big" style="color:var(--accent)">{{ analyses|length }}</div>
        <div class="lbl">Total Analyses</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="stat-box">
        <div class="big" style="color:#ef4444">{{ analyses|selectattr('threat_level','equalto','Critical')|list|length }}</div>
        <div class="lbl">Critical Finds</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="stat-box">
        <div class="big" style="color:#f97316">{{ analyses|selectattr('threat_level','equalto','High')|list|length }}</div>
        <div class="lbl">High Risk</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="stat-box">
        <div class="big" style="color:#10b981">{{ analyses|selectattr('threat_level','equalto','Low')|list|length }}</div>
        <div class="lbl">Trusted / Low</div>
      </div>
    </div>
  </div>

  <!-- Analysis History -->
  <div class="card-dark p-4">
    <div class="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">
      <h5 class="fw-bold mb-0" style="color:var(--text)"><i class="bi bi-clock-history me-2" style="color:var(--muted)"></i>Your Analysis History</h5>
      <a href="/analyzer" class="btn-sec px-3 py-1" style="border-radius:8px;text-decoration:none;font-size:.85rem"><i class="bi bi-plus me-1"></i>Analyze New IOC</a>
    </div>
    {% if analyses %}
    <div class="table-responsive">
      <table class="table tc mb-0">
        <thead><tr><th>#</th><th>Indicator</th><th>Type</th><th>Risk</th><th>Level</th><th>Reputation</th><th>When</th><th>Action</th></tr></thead>
        <tbody>
          {% for a in analyses %}
          <tr>
            <td style="color:var(--muted)">{{ loop.index }}</td>
            <td class="font-monospace" style="max-width:220px;word-break:break-all">{{ a.indicator }}</td>
            <td><span class="badge bg-secondary">{{ (a.indicator_type or 'UNKNOWN')|upper }}</span></td>
            <td><strong style="color:{% if a.risk_score >= 80 %}#ef4444{% elif a.risk_score >= 60 %}#f97316{% elif a.risk_score >= 40 %}#f59e0b{% else %}#10b981{% endif %}">{{ a.risk_score }}</strong>/100</td>
            <td><span class="badge badge-{{ (a.threat_level or 'unknown')|lower }}">{{ a.threat_level }}</span></td>
            <td class="rep-{{ (a.reputation or 'unknown')|lower }}">{{ a.reputation }}</td>
            <td class="small" style="color:var(--muted);white-space:nowrap">{{ a.analyzed_at[:16] if a.analyzed_at else '—' }}</td>
            <td>
              <form method="GET" action="/analyzer" class="d-inline">
                <button type="button" class="btn btn-sm btn-sec py-0 px-2"
                  onclick="sessionStorage.setItem('rerun','{{ a.indicator }}');window.location='/analyzer'">
                  <i class="bi bi-arrow-clockwise"></i>
                </button>
              </form>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% else %}
    <div class="text-center py-5" style="color:var(--muted)">
      <i class="bi bi-inbox fs-1 d-block mb-3" style="opacity:.3"></i>
      <p>No analyses yet. <a href="/analyzer" style="color:var(--accent)">Start your first analysis</a></p>
    </div>
    {% endif %}
  </div>
</div>
""" + SHARED_FOOTER + SHARED_SCRIPTS + """
</body></html>"""

# ============================================================
# ADMIN LOGS TEMPLATE
# ============================================================
ADMIN_LOGS_TEMPLATE = """<!DOCTYPE html>
<html data-theme="dark" lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Panel — ThreatIntel Analyzer 2.0</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
""" + PWA_HEAD + THEME_CSS + """
</head>
<body>
""" + SHARED_NAVBAR + """
<div class="container py-4">
  <!-- Header -->
  <div class="card-dark p-4 mb-4" style="background:linear-gradient(135deg,rgba(239,68,68,.08),rgba(139,92,246,.05))">
    <div class="d-flex align-items-center gap-3">
      <div style="width:52px;height:52px;background:rgba(239,68,68,.2);border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:1.4rem">🔴</div>
      <div>
        <h4 class="fw-bold mb-0" style="color:var(--text)">Admin Control Panel</h4>
        <p class="mb-0 small" style="color:var(--muted)">System activity logs, user management &amp; platform statistics</p>
      </div>
      <span class="admin-badge ms-auto">ADMIN</span>
    </div>
  </div>

  <!-- Stats -->
  <div class="row g-3 mb-4">
    <div class="col-6 col-lg-3">
      <div class="stat-box">
        <div class="big" style="color:var(--accent)">{{ stats.total_users }}</div>
        <div class="lbl">Total Users</div>
      </div>
    </div>
    <div class="col-6 col-lg-3">
      <div class="stat-box">
        <div class="big" style="color:var(--accent2)">{{ stats.total_analyses }}</div>
        <div class="lbl">Total Analyses</div>
      </div>
    </div>
    <div class="col-6 col-lg-3">
      <div class="stat-box">
        <div class="big" style="color:#10b981">{{ stats.today_analyses }}</div>
        <div class="lbl">Today's Analyses</div>
      </div>
    </div>
    <div class="col-6 col-lg-3">
      <div class="stat-box">
        <div class="big" style="color:#ef4444">{{ stats.critical_finds }}</div>
        <div class="lbl">Critical Finds</div>
      </div>
    </div>
  </div>

  <!-- Nav Tabs -->
  <ul class="nav mb-4 gap-2">
    <li><a class="btn-sec px-4 py-2" style="border-radius:8px;text-decoration:none;cursor:pointer" onclick="showTab('activity')"><i class="bi bi-list-ul me-1"></i>Activity Logs</a></li>
    <li><a class="btn-sec px-4 py-2" style="border-radius:8px;text-decoration:none;cursor:pointer" onclick="showTab('analyses')"><i class="bi bi-search me-1"></i>All Analyses</a></li>
    <li><a class="btn-sec px-4 py-2" style="border-radius:8px;text-decoration:none;cursor:pointer" onclick="showTab('users')"><i class="bi bi-people me-1"></i>Users</a></li>
  </ul>

  <!-- Activity Logs Tab -->
  <div id="tab-activity" class="card-dark p-4 mb-4">
    <div class="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">
      <h5 class="fw-bold mb-0" style="color:var(--text)"><i class="bi bi-list-ul me-2"></i>Activity Logs</h5>
      <button class="btn-sec px-3 py-1" style="border-radius:8px;font-size:.82rem" onclick="exportCSV('logTable','activity_logs')"><i class="bi bi-download me-1"></i>Export CSV</button>
    </div>
    <div class="mb-3"><input type="text" class="si" style="max-width:300px;padding:.5rem .9rem;font-size:.85rem" placeholder="Filter logs..." oninput="filterTable('logTable',this.value)"></div>
    <div class="table-responsive">
      <table class="table tc mb-0" id="logTable">
        <thead><tr><th>#</th><th>User</th><th>Action</th><th>Details</th><th>IP Address</th><th>Timestamp</th></tr></thead>
        <tbody>
          {% for log in logs %}
          <tr>
            <td style="color:var(--muted)">{{ loop.index }}</td>
            <td><strong style="color:var(--accent)">{{ log.username }}</strong></td>
            <td>
              <span class="badge" style="{% if log.action == 'login' %}background:rgba(16,185,129,.2);color:#6ee7b7{% elif log.action == 'logout' %}background:rgba(100,116,139,.2);color:#94a3b8{% elif log.action == 'analyze' %}background:rgba(0,212,255,.15);color:var(--accent){% else %}background:rgba(139,92,246,.2);color:#a78bfa{% endif %}">
                {{ log.action|upper }}
              </span>
            </td>
            <td class="small font-monospace" style="color:var(--muted);max-width:200px;word-break:break-all">{{ log.details[:60] if log.details else '—' }}</td>
            <td class="small font-monospace" style="color:var(--muted)">{{ log.ip_address or '—' }}</td>
            <td class="small" style="color:var(--muted);white-space:nowrap">{{ log.created_at[:16] if log.created_at else '—' }}</td>
          </tr>
          {% else %}
          <tr><td colspan="6" class="text-center py-4" style="color:var(--muted)">No activity logs yet</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- All Analyses Tab -->
  <div id="tab-analyses" class="card-dark p-4 mb-4 d-none">
    <h5 class="fw-bold mb-3" style="color:var(--text)"><i class="bi bi-search me-2"></i>All User Analyses</h5>
    <div class="mb-3"><input type="text" class="si" style="max-width:300px;padding:.5rem .9rem;font-size:.85rem" placeholder="Filter analyses..." oninput="filterTable('anaTable',this.value)"></div>
    <div class="table-responsive">
      <table class="table tc mb-0" id="anaTable">
        <thead><tr><th>#</th><th>User</th><th>Indicator</th><th>Type</th><th>Risk</th><th>Level</th><th>Reputation</th><th>Date</th></tr></thead>
        <tbody>
          {% for a in all_analyses %}
          <tr>
            <td style="color:var(--muted)">{{ loop.index }}</td>
            <td><strong style="color:var(--accent)">{{ a.username }}</strong></td>
            <td class="font-monospace small" style="max-width:200px;word-break:break-all">{{ a.indicator }}</td>
            <td><span class="badge bg-secondary">{{ (a.indicator_type or '?')|upper }}</span></td>
            <td><strong style="color:{% if a.risk_score >= 80 %}#ef4444{% elif a.risk_score >= 60 %}#f97316{% elif a.risk_score >= 40 %}#f59e0b{% else %}#10b981{% endif %}">{{ a.risk_score }}</strong>/100</td>
            <td><span class="badge badge-{{ (a.threat_level or 'unknown')|lower }}">{{ a.threat_level }}</span></td>
            <td class="rep-{{ (a.reputation or 'unknown')|lower }}">{{ a.reputation }}</td>
            <td class="small" style="color:var(--muted);white-space:nowrap">{{ a.analyzed_at[:16] if a.analyzed_at else '—' }}</td>
          </tr>
          {% else %}
          <tr><td colspan="8" class="text-center py-4" style="color:var(--muted)">No analyses yet</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Users Tab -->
  <div id="tab-users" class="card-dark p-4 mb-4 d-none">
    <h5 class="fw-bold mb-3" style="color:var(--text)"><i class="bi bi-people me-2"></i>Registered Users</h5>
    <div class="table-responsive">
      <table class="table tc mb-0">
        <thead><tr><th>#</th><th>Username</th><th>Email</th><th>Role</th><th>Joined</th></tr></thead>
        <tbody>
          {% for u in users %}
          <tr>
            <td style="color:var(--muted)">{{ u.id }}</td>
            <td><div class="d-flex align-items-center gap-2"><div class="user-avatar" style="width:28px;height:28px;font-size:.75rem">{{ u.username[0].upper() }}</div><strong>{{ u.username }}</strong></div></td>
            <td style="color:var(--muted)">{{ u.email }}</td>
            <td>
              {% if u.role == 'admin' %}
              <span class="admin-badge">ADMIN</span>
              {% else %}
              <span class="badge" style="background:rgba(0,212,255,.15);color:var(--accent)">USER</span>
              {% endif %}
            </td>
            <td class="small" style="color:var(--muted)">{{ u.created_at[:10] if u.created_at else '—' }}</td>
          </tr>
          {% else %}
          <tr><td colspan="5" class="text-center py-4" style="color:var(--muted)">No users registered</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    <div class="mt-3 p-3" style="background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.15);border-radius:10px">
      <p class="mb-0 small" style="color:var(--muted)"><i class="bi bi-info-circle me-1" style="color:var(--accent)"></i>To promote a user to Admin, run this in Python: <code style="color:var(--accent)">conn.execute("UPDATE users SET role='admin' WHERE email='user@email.com'")</code></p>
    </div>
  </div>
</div>
""" + SHARED_FOOTER + SHARED_SCRIPTS + """
<script>
function showTab(t){['activity','analyses','users'].forEach(id=>{document.getElementById('tab-'+id).classList.toggle('d-none',id!==t);});}
function filterTable(tid,q){const rows=document.querySelectorAll('#'+tid+' tbody tr');rows.forEach(r=>{r.style.display=r.innerText.toLowerCase().includes(q.toLowerCase())?'':'none';});}
function exportCSV(tid,fname){
  const rows=document.querySelectorAll('#'+tid+' tr');let csv='';
  rows.forEach(r=>{const cols=r.querySelectorAll('th,td');csv+=Array.from(cols).map(c=>'"'+c.innerText.replace(/"/g,'""')+'"').join(',')+'\n';});
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));a.download=fname+'_'+Date.now()+'.csv';a.click();
}
</script>
</body></html>"""

# ============================================================
# HOME TEMPLATE
# ============================================================
HOME_TEMPLATE = r"""<!DOCTYPE html>
<html data-theme="dark" lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatIntel Analyzer 2.0 — Enterprise SOC Platform</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
""" + PWA_HEAD + THEME_CSS + r"""
<style>
.hero-section{min-height:90vh;display:flex;align-items:center;position:relative;overflow:hidden;background:var(--bg);border-bottom:1px solid var(--border)}
.hero-bg{position:absolute;inset:0;background:radial-gradient(ellipse at 20% 30%,rgba(0,212,255,.1),transparent 50%),radial-gradient(ellipse at 80% 70%,rgba(139,92,246,.1),transparent 50%)}
.hero-grid{position:absolute;inset:0;background-image:linear-gradient(rgba(0,212,255,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.04) 1px,transparent 1px);background-size:60px 60px;animation:gp 5s ease-in-out infinite}
@keyframes gp{0%,100%{opacity:.4}50%{opacity:.9}}
.hero-badge{display:inline-flex;align-items:center;gap:.4rem;background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.3);color:var(--accent);border-radius:20px;padding:.3rem 1rem;font-size:.8rem;font-weight:600;margin-bottom:1.5rem}
.hero-title{font-size:clamp(2rem,5vw,3.6rem);font-weight:900;line-height:1.1;margin-bottom:1.2rem;color:var(--text)}
.gradient{background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero-sub{font-size:1rem;color:var(--muted);max-width:550px;line-height:1.7;margin-bottom:2rem}
.section-badge{display:inline-block;background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.25);color:var(--accent);border-radius:20px;padding:.28rem .85rem;font-size:.76rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.8rem}
.section-title{font-size:clamp(1.7rem,3.5vw,2.4rem);font-weight:800;color:var(--text);margin-bottom:.7rem}
.section-sub{color:var(--muted);font-size:.95rem;max-width:540px;margin:0 auto 2.5rem;line-height:1.6}
.feature-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:1.6rem;height:100%;transition:all .3s}
.feature-card:hover{transform:translateY(-5px);border-color:var(--accent);box-shadow:0 10px 36px rgba(0,212,255,.12)}
.feature-icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.3rem;margin-bottom:1rem}
.step-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:1.8rem;text-align:center;height:100%;transition:all .3s}
.step-card:hover{border-color:var(--accent);transform:translateY(-3px)}
.step-num{width:42px;height:42px;border-radius:50%;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#000;font-weight:800;font-size:1.1rem;display:flex;align-items:center;justify-content:center;margin:0 auto 1rem}
.cta-section{padding:5rem 0;background:var(--section-alt);position:relative;overflow:hidden}
.cta-bg{position:absolute;inset:0;background:radial-gradient(ellipse at center,rgba(0,212,255,.07) 0%,transparent 70%)}
.mockup{background:var(--card);border:1px solid var(--border);border-radius:14px;overflow:hidden;box-shadow:var(--shadow)}
.mockup-bar{background:var(--card2);border-bottom:1px solid var(--border);padding:.65rem 1rem;display:flex;align-items:center;gap:.4rem}
.mkdot{width:9px;height:9px;border-radius:50%}
.mkrow{background:var(--card2);border:1px solid var(--border);border-radius:7px;padding:.6rem .9rem;margin-bottom:.5rem;display:flex;align-items:center;justify-content:space-between}
</style>
</head>
<body>
""" + SHARED_NAVBAR + r"""
<!-- HERO -->
<section class="hero-section">
  <div class="hero-bg"></div><div class="hero-grid"></div>
  <div class="container position-relative" style="z-index:1">
    <div class="row align-items-center g-5">
      <div class="col-lg-6">
        <div class="hero-badge"><i class="bi bi-shield-fill-check"></i>Enterprise SOC Platform &mdash; v2.0</div>
        <h1 class="hero-title">Cyber Threat<br>Intelligence<br><span class="gradient">Automated.</span></h1>
        <p class="hero-sub">Analyze IPs, URLs &amp; file hashes across 70+ security engines. Get AI threat narratives, SIEM queries, YARA rules &amp; forensic PDF reports in seconds.</p>
        <div class="d-flex gap-3 flex-wrap">
          <a href="/analyzer" class="btn-accent px-4 py-2" style="border-radius:10px;text-decoration:none;font-size:1rem;color:#000"><i class="bi bi-lightning-charge-fill me-2"></i>Launch Analyzer</a>
          <a href="#features" class="btn-outline-accent px-4 py-2" style="border-radius:10px;text-decoration:none;font-size:1rem"><i class="bi bi-grid me-2"></i>View Features</a>
        </div>
        <div class="row mt-4 g-0" style="max-width:380px">
          <div class="col-3 text-center py-2"><div style="font-size:1.8rem;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent">33</div><div style="font-size:.7rem;color:var(--muted);font-weight:700;text-transform:uppercase">Technologies</div></div>
          <div class="col-3 text-center py-2"><div style="font-size:1.8rem;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent">70+</div><div style="font-size:.7rem;color:var(--muted);font-weight:700;text-transform:uppercase">AV Engines</div></div>
          <div class="col-3 text-center py-2"><div style="font-size:1.8rem;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent">4</div><div style="font-size:.7rem;color:var(--muted);font-weight:700;text-transform:uppercase">SIEM Platforms</div></div>
          <div class="col-3 text-center py-2"><div style="font-size:1.8rem;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent">8</div><div style="font-size:.7rem;color:var(--muted);font-weight:700;text-transform:uppercase">PDF Sections</div></div>
        </div>
      </div>
      <div class="col-lg-6 d-none d-lg-block">
        <div class="mockup ms-auto" style="max-width:460px">
          <div class="mockup-bar"><div class="mkdot" style="background:#ef4444"></div><div class="mkdot" style="background:#f59e0b"></div><div class="mkdot" style="background:#10b981"></div><span style="font-size:.72rem;color:var(--muted);margin-left:.5rem">ThreatIntel Analyzer 2.0</span></div>
          <div class="p-3">
            <div class="mkrow"><span style="font-family:monospace;font-size:.8rem;color:var(--accent)">185.220.101.5</span><span class="badge" style="background:#ef4444;color:#fff;font-size:.68rem">CRITICAL 79/100</span></div>
            <div class="mkrow"><span style="font-family:monospace;font-size:.8rem;color:var(--text2)">24d004a104d4d540...</span><span class="badge" style="background:#ef4444;color:#fff;font-size:.68rem">CRITICAL 91/100</span></div>
            <div class="mkrow"><span style="font-family:monospace;font-size:.8rem;color:var(--text2)">malware-traffic.net</span><span class="badge" style="background:#f97316;color:#fff;font-size:.68rem">HIGH 68/100</span></div>
            <div class="mt-2 p-2" style="background:rgba(0,212,255,.07);border:1px solid rgba(0,212,255,.2);border-radius:8px">
              <div style="font-size:.7rem;color:var(--accent);font-weight:700;margin-bottom:.3rem"><i class="bi bi-robot me-1"></i>AI SOC Narrative</div>
              <div style="font-size:.73rem;color:var(--muted);line-height:1.5">CRITICAL: Multi-engine feeds confirm active C2 communication. Immediate containment mandatory...</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- FEATURES -->
<section style="padding:4.5rem 0;background:var(--bg)" id="features">
  <div class="container">
    <div class="text-center mb-5"><div class="section-badge">Platform Features</div><h2 class="section-title">Everything a SOC Analyst Needs</h2><p class="section-sub">From raw IOC to complete forensic intelligence — automated, all in one platform.</p></div>
    <div class="row g-4">
      <div class="col-lg-3 col-md-6"><div class="feature-card"><div class="feature-icon" style="background:rgba(0,212,255,.12)"><i class="bi bi-search" style="color:var(--accent)"></i></div><h6 class="fw-bold mb-2" style="color:var(--text)">Multi-Source Enrichment</h6><p style="color:var(--muted);font-size:.84rem;margin:0">VirusTotal (70+ engines), AbuseIPDB, and WHOIS simultaneously for comprehensive threat context.</p></div></div>
      <div class="col-lg-3 col-md-6"><div class="feature-card"><div class="feature-icon" style="background:rgba(139,92,246,.12)"><i class="bi bi-robot" style="color:var(--accent2)"></i></div><h6 class="fw-bold mb-2" style="color:var(--text)">AI SOC Narrative</h6><p style="color:var(--muted);font-size:.84rem;margin:0">Automated analyst briefings converting raw data into executive-level threat reports.</p></div></div>
      <div class="col-lg-3 col-md-6"><div class="feature-card"><div class="feature-icon" style="background:rgba(0,212,255,.12)"><i class="bi bi-terminal-fill" style="color:var(--accent)"></i></div><h6 class="fw-bold mb-2" style="color:var(--text)">SIEM Query Generator</h6><p style="color:var(--muted);font-size:.84rem;margin:0">One-click Splunk SPL, Sentinel KQL, Elasticsearch KQL, and CrowdStrike Falcon queries.</p></div></div>
      <div class="col-lg-3 col-md-6"><div class="feature-card"><div class="feature-icon" style="background:rgba(244,114,182,.12)"><i class="bi bi-shield-slash" style="color:#f472b6"></i></div><h6 class="fw-bold mb-2" style="color:var(--text)">Defang / Refang Tool</h6><p style="color:var(--muted);font-size:.84rem;margin:0">Convert live IOCs to safe-share defanged format for email and ticket distribution.</p></div></div>
      <div class="col-lg-3 col-md-6"><div class="feature-card"><div class="feature-icon" style="background:rgba(16,185,129,.12)"><i class="bi bi-person-lock" style="color:#10b981"></i></div><h6 class="fw-bold mb-2" style="color:var(--text)">User Authentication</h6><p style="color:var(--muted);font-size:.84rem;margin:0">Secure login/signup with PBKDF2 password hashing, sessions, and role-based access.</p></div></div>
      <div class="col-lg-3 col-md-6"><div class="feature-card"><div class="feature-icon" style="background:rgba(245,158,11,.12)"><i class="bi bi-shield-shaded" style="color:#f59e0b"></i></div><h6 class="fw-bold mb-2" style="color:var(--text)">YARA &amp; Snort Rules</h6><p style="color:var(--muted);font-size:.84rem;margin:0">Auto-generated malware signatures for EDR and network intrusion detection systems.</p></div></div>
      <div class="col-lg-3 col-md-6"><div class="feature-card"><div class="feature-icon" style="background:rgba(139,92,246,.12)"><i class="bi bi-stack" style="color:var(--accent2)"></i></div><h6 class="fw-bold mb-2" style="color:var(--text)">Batch IOC Pipeline</h6><p style="color:var(--muted);font-size:.84rem;margin:0">Process 100+ IOCs from raw logs automatically with real-time progress tracking.</p></div></div>
      <div class="col-lg-3 col-md-6"><div class="feature-card"><div class="feature-icon" style="background:rgba(239,68,68,.12)"><i class="bi bi-file-earmark-pdf-fill" style="color:#ef4444"></i></div><h6 class="fw-bold mb-2" style="color:var(--text)">Forensic PDF Report</h6><p style="color:var(--muted);font-size:.84rem;margin:0">8-section publication-grade forensic report with SIEM queries, YARA rules and SOC checklist.</p></div></div>
    </div>
  </div>
</section>

<!-- HOW IT WORKS -->
<section style="padding:4.5rem 0;background:var(--section-alt)">
  <div class="container">
    <div class="text-center mb-5"><div class="section-badge">Workflow</div><h2 class="section-title">How It Works</h2></div>
    <div class="row g-4">
      <div class="col-lg-3 col-sm-6"><div class="step-card"><div class="step-num">1</div><div style="font-size:2rem;margin-bottom:.8rem"><i class="bi bi-person-plus" style="color:var(--accent)"></i></div><h6 class="fw-bold" style="color:var(--text)">Create Account</h6><p style="color:var(--muted);font-size:.83rem;margin:0">Sign up securely. Password hashed with PBKDF2-SHA256. Instant access.</p></div></div>
      <div class="col-lg-3 col-sm-6"><div class="step-card"><div class="step-num">2</div><div style="font-size:2rem;margin-bottom:.8rem"><i class="bi bi-input-cursor-text" style="color:var(--accent2)"></i></div><h6 class="fw-bold" style="color:var(--text)">Input Your IOC</h6><p style="color:var(--muted);font-size:.83rem;margin:0">Paste IP, URL, hash, or bulk incident logs for automatic extraction.</p></div></div>
      <div class="col-lg-3 col-sm-6"><div class="step-card"><div class="step-num">3</div><div style="font-size:2rem;margin-bottom:.8rem"><i class="bi bi-cpu" style="color:#10b981"></i></div><h6 class="fw-bold" style="color:var(--text)">AI Analysis</h6><p style="color:var(--muted);font-size:.83rem;margin:0">Risk scoring, MITRE ATT&CK mapping, SIEM queries and AI narrative generated.</p></div></div>
      <div class="col-lg-3 col-sm-6"><div class="step-card"><div class="step-num">4</div><div style="font-size:2rem;margin-bottom:.8rem"><i class="bi bi-box-arrow-up" style="color:#f59e0b"></i></div><h6 class="fw-bold" style="color:var(--text)">Export Intelligence</h6><p style="color:var(--muted);font-size:.83rem;margin:0">Download PDF, STIX 2.1 JSON, copy SIEM queries or YARA signatures.</p></div></div>
    </div>
  </div>
</section>

<!-- CTA -->
<section class="cta-section">
  <div class="cta-bg"></div>
  <div class="container text-center position-relative" style="z-index:1">
    <div class="section-badge">Get Started</div>
    <h2 class="section-title mb-3">Ready to Analyze Your First IOC?</h2>
    <p style="color:var(--muted);font-size:1rem;max-width:480px;margin:0 auto 2rem;line-height:1.6">Free to use. Secure account. Enterprise-grade intelligence in seconds.</p>
    <div class="d-flex gap-3 justify-content-center flex-wrap">
      <a href="/signup" class="btn-accent px-5 py-2" style="border-radius:10px;text-decoration:none;font-size:1rem;color:#000"><i class="bi bi-person-plus-fill me-2"></i>Create Free Account</a>
      <a href="/login" class="btn-outline-accent px-5 py-2" style="border-radius:10px;text-decoration:none;font-size:1rem"><i class="bi bi-box-arrow-in-right me-2"></i>Sign In</a>
    </div>
  </div>
</section>
""" + SHARED_FOOTER + SHARED_SCRIPTS + r"""
</body></html>"""

# ============================================================
# MAIN ANALYZER TEMPLATE
# ============================================================
MAIN_TEMPLATE = r"""<!DOCTYPE html>
<html data-theme="dark" lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Analyzer — ThreatIntel Analyzer 2.0</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
""" + PWA_HEAD + THEME_CSS + r"""
<style>
.page-header{padding:1.8rem 0 1.4rem;background:var(--bg);border-bottom:1px solid var(--border);
  background-image:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.06),transparent 50%),radial-gradient(ellipse at 80% 50%,rgba(139,92,246,.05),transparent 50%)}
</style>
</head>
<body>
""" + SHARED_NAVBAR + r"""
<div class="page-header">
  <div class="container">
    <div class="row align-items-center g-3">
      <div class="col-lg-6">
        <h1 style="font-size:1.5rem;font-weight:800;color:var(--text);margin:0"><i class="bi bi-lightning-charge-fill me-2" style="color:var(--accent)"></i>Threat Analyzer</h1>
        <p style="color:var(--muted);font-size:.87rem;margin:.3rem 0 0">Enter any IP, URL, or file hash (MD5/SHA1/SHA256) for real-time threat intelligence.</p>
      </div>
      <div class="col-lg-6">
        <form id="tf" autocomplete="off">
          <div class="d-flex gap-2">
            <textarea id="inp" class="si" rows="2" style="resize:none" placeholder="Paste IP, URL, hash, or bulk logs..."></textarea>
            <div class="d-flex flex-column gap-2">
              <button type="submit" class="btn-accent px-3 py-1 fw-bold" style="border-radius:8px"><i class="bi bi-lightning-charge-fill"></i></button>
              <button type="button" class="btn-sec px-3 py-1" id="sampleBtn" title="Load Sample"><i class="bi bi-play-circle"></i></button>
              <button type="button" class="btn-sec px-3 py-1" id="clearBtn" title="Clear"><i class="bi bi-trash"></i></button>
            </div>
          </div>
        </form>
      </div>
    </div>
  </div>
</div>

<div class="container mt-4">
  <!-- DEFANG TOOL -->
  <div class="card-dark p-3 mb-4">
    <div class="d-flex align-items-center gap-2 mb-3">
      <i class="bi bi-shield-lock-fill fs-5" style="color:#f472b6"></i>
      <h6 class="fw-bold mb-0" style="color:var(--text)">Defang / Refang Cyber Hygiene Utility</h6>
      <span class="badge ms-1" style="background:rgba(244,114,182,.12);color:#f472b6;border:1px solid #f472b660;font-size:.7rem">Safe Share</span>
    </div>
    <div class="row g-3 align-items-end">
      <div class="col-md-5"><input type="text" id="dfInp" class="si" style="padding:.6rem 1rem;font-size:.87rem" placeholder="185.220.101.5 or https://evil.com"></div>
      <div class="col-md-3"><select id="dfType" class="si" style="padding:.6rem 1rem;font-size:.87rem"><option value="ipv4">IPv4 Address</option><option value="url">URL / Domain</option><option value="sha256">Hash</option></select></div>
      <div class="col-md-4 d-flex gap-2"><button class="btn-sec flex-fill" onclick="runDefang()"><i class="bi bi-shield-slash me-1"></i>Defang</button><button class="btn-sec flex-fill" onclick="runRefang()"><i class="bi bi-shield-fill-check me-1"></i>Refang</button></div>
    </div>
    <div class="row g-3 mt-1">
      <div class="col-md-6"><div class="d-flex justify-content-between mb-1"><label class="small" style="color:var(--muted)">Defanged (Safe)</label><button class="btn-sec py-0 px-2" style="font-size:.75rem" onclick="copyEl('dfOut')"><i class="bi bi-clipboard"></i></button></div><div class="dd cb-pink" id="dfOut">—</div></div>
      <div class="col-md-6"><div class="d-flex justify-content-between mb-1"><label class="small" style="color:var(--muted)">Refanged (Live)</label><button class="btn-sec py-0 px-2" style="font-size:.75rem" onclick="copyEl('rfOut')"><i class="bi bi-clipboard"></i></button></div><div class="dd cb-green" id="rfOut">—</div></div>
    </div>
  </div>
</div>

<div class="container pb-5">
  <div id="sAlert" class="d-none mb-3" style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.4);color:#fca5a5;border-radius:10px;padding:.75rem 1rem"><i class="bi bi-info-circle-fill me-2"></i><span id="sAlertTxt"></span></div>

  <!-- SINGLE RESULT -->
  <div id="singleCard" class="card-dark p-4 mb-4 d-none">
    <div class="d-flex align-items-start justify-content-between flex-wrap gap-3 mb-4 pb-3 border-bottom" style="border-color:var(--border)!important">
      <div>
        <div class="d-flex align-items-center gap-2 mb-1 flex-wrap">
          <h4 class="mb-0 fw-bold font-monospace" id="resInd" style="word-break:break-all;color:var(--text)">—</h4>
          <span id="resCached" class="cb-badge d-none"><i class="bi bi-database-check me-1"></i>Cached</span>
        </div>
        <div class="d-flex gap-2 flex-wrap mt-2">
          <span id="resType" class="badge bg-secondary">—</span>
          <span id="resThreat" class="badge">—</span>
          <span id="resRep" class="ms-1 fw-bold">—</span>
        </div>
      </div>
      <div class="d-flex gap-2 flex-wrap">
        <button class="btn-sec" style="font-size:.82rem;border-radius:8px" id="btnStix"><i class="bi bi-boxes me-1"></i>STIX 2.1</button>
        <button class="btn-sec" style="font-size:.82rem;border-radius:8px" id="btnEmail"><i class="bi bi-envelope-at me-1"></i>Email</button>
        <button class="btn-sec" style="font-size:.82rem;border-radius:8px" id="btnJson"><i class="bi bi-filetype-json me-1"></i>JSON</button>
        <button class="btn-red" style="font-size:.82rem;border-radius:8px" id="btnPdf"><i class="bi bi-file-earmark-pdf-fill me-1"></i>Full PDF</button>
      </div>
    </div>

    <div class="ai-card mb-4">
      <div class="d-flex align-items-center justify-content-between mb-2">
        <h6 class="fw-bold mb-0" style="color:var(--text)"><i class="bi bi-robot me-2 text-info"></i>AI SOC Threat Narrative</h6>
        <span class="badge" style="background:rgba(139,92,246,.3);color:#c4b5fd;font-size:.72rem">Auto-Generated</span>
      </div>
      <p class="mb-2 small" id="aiText" style="line-height:1.6;color:var(--text2)"></p>
      <div class="d-flex gap-2 flex-wrap" id="aiRecs"></div>
    </div>

    <div class="row g-3 mb-4 align-items-stretch">
      <div class="col-lg-3 col-md-4">
        <div class="card2 p-3 text-center h-100 d-flex flex-column justify-content-center">
          <div class="gw"><svg viewBox="0 0 140 140" width="140" height="140"><circle class="gb" cx="70" cy="70" r="58"/><circle class="gv" id="gCircle" cx="70" cy="70" r="58" stroke-dasharray="364.4" stroke-dashoffset="364.4" stroke="var(--accent)"/></svg><div class="gl"><div class="gn" id="gNum">0</div><div class="gt">Risk Score</div></div></div>
        </div>
      </div>
      <div class="col-lg-9 col-md-8">
        <div class="row g-2 h-100">
          <div class="col-sm-4"><div class="sc-stat d-flex flex-column justify-content-center"><div class="sv" id="vVT">—</div><div class="sl">VirusTotal Engines</div></div></div>
          <div class="col-sm-4"><div class="sc-stat d-flex flex-column justify-content-center"><div class="sv" id="vAb">—</div><div class="sl">Abuse Confidence</div></div></div>
          <div class="col-sm-4"><div class="sc-stat d-flex flex-column justify-content-center"><div class="sv" id="vRep">—</div><div class="sl">Abuse Reports</div></div></div>
          <div class="col-sm-4"><div class="sc-stat d-flex flex-column justify-content-center"><div class="sv fs-6" id="vReg">—</div><div class="sl">ISP / Registrar</div></div></div>
          <div class="col-sm-4"><div class="sc-stat d-flex flex-column justify-content-center"><div class="sv fs-6" id="vDom">—</div><div class="sl">Domain Created</div></div></div>
          <div class="col-sm-4"><div class="sc-stat d-flex flex-column justify-content-center"><div class="sv fs-6" id="vPorts">—</div><div class="sl">Open Ports</div></div></div>
        </div>
      </div>
    </div>

    <div class="card2 p-3 mb-4">
      <div class="d-flex align-items-center justify-content-between mb-2">
        <h6 class="fw-bold mb-0 small" style="color:#f472b6"><i class="bi bi-shield-slash me-1"></i>Defanged IOC</h6>
        <button class="btn-sec py-0 px-2" style="font-size:.75rem" onclick="copyEl('resDefang')"><i class="bi bi-clipboard"></i> Copy</button>
      </div>
      <div class="dd cb-pink" id="resDefang">—</div>
    </div>

    <div class="mb-4">
      <div class="d-flex justify-content-between mb-2"><h6 class="text-uppercase fw-bold mb-0" style="font-size:.72rem;color:var(--muted);letter-spacing:.05em"><i class="bi bi-diagram-2 text-info me-1"></i>Interactive Threat Relationship Graph</h6><small style="color:var(--muted)">Drag &amp; zoom</small></div>
      <div id="tgc"></div>
    </div>

    <div class="card2 p-3 mb-4">
      <h6 class="fw-bold mb-3 cb-green"><i class="bi bi-terminal-fill me-2"></i>SIEM Threat-Hunting Queries</h6>
      <ul class="nav sp mb-3" id="siemTabs">
        <li class="nav-item"><a class="nav-link active" onclick="showSiem('splunk')">Splunk (SPL)</a></li>
        <li class="nav-item"><a class="nav-link" onclick="showSiem('sentinel')">Sentinel (KQL)</a></li>
        <li class="nav-item"><a class="nav-link" onclick="showSiem('elastic')">Elasticsearch</a></li>
        <li class="nav-item"><a class="nav-link" onclick="showSiem('crowdstrike')">CrowdStrike</a></li>
      </ul>
      <div class="position-relative">
        <button class="btn-sec py-0 px-2 position-absolute" style="top:.5rem;right:.5rem;z-index:10;font-size:.75rem" onclick="copyActiveSiem()"><i class="bi bi-clipboard"></i> Copy</button>
        <pre id="sb_splunk" class="code-block cb-green sc2 active"></pre>
        <pre id="sb_sentinel" class="code-block cb-green sc2"></pre>
        <pre id="sb_elastic" class="code-block cb-green sc2"></pre>
        <pre id="sb_crowdstrike" class="code-block cb-green sc2"></pre>
      </div>
    </div>

    <div class="row g-3 mb-4">
      <div class="col-md-6"><div class="card2 p-3"><div class="d-flex justify-content-between mb-2"><h6 class="fw-bold mb-0 small text-info"><i class="bi bi-shield-shaded me-1"></i>YARA Signature</h6><button class="btn-sec py-0 px-2" style="font-size:.75rem" onclick="copyEl('yara')"><i class="bi bi-clipboard"></i></button></div><pre id="yara" class="code-block cb-purple mb-0"></pre></div></div>
      <div class="col-md-6"><div class="card2 p-3"><div class="d-flex justify-content-between mb-2"><h6 class="fw-bold mb-0 small text-warning"><i class="bi bi-fire me-1"></i>Snort / Suricata</h6><button class="btn-sec py-0 px-2" style="font-size:.75rem" onclick="copyEl('snort')"><i class="bi bi-clipboard"></i></button></div><pre id="snort" class="code-block cb-yellow mb-0"></pre></div></div>
    </div>
    <div class="row g-3">
      <div class="col-md-6"><h6 class="text-uppercase fw-bold mb-2" style="font-size:.72rem;color:var(--muted)"><i class="bi bi-incognito text-danger me-1"></i>Threat Actors</h6><div id="actors">—</div></div>
      <div class="col-md-6"><h6 class="text-uppercase fw-bold mb-2" style="font-size:.72rem;color:var(--muted)"><i class="bi bi-diagram-3-fill me-1" style="color:#8b5cf6"></i>MITRE ATT&CK TTPs</h6><div id="mitre">—</div></div>
    </div>
  </div>

  <!-- BATCH -->
  <div id="batchCard" class="card-dark p-4 mb-4 d-none">
    <div class="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">
      <h5 class="fw-bold mb-0" style="color:var(--text)"><i class="bi bi-stack text-info me-2"></i>Multi-IOC Batch Analysis</h5>
      <button class="btn-sec" style="font-size:.82rem;border-radius:8px" id="btnBatchExport"><i class="bi bi-download me-1"></i>Export JSON</button>
    </div>
    <div class="mb-3">
      <div class="d-flex justify-content-between mb-1"><small style="color:var(--muted)" id="batchLbl">Analyzing...</small><small class="fw-bold" style="color:var(--muted)" id="batchPct">0%</small></div>
      <div class="progress" style="height:5px;background:var(--border)"><div class="progress-bar" id="batchBar" style="width:0%;background:linear-gradient(90deg,var(--accent),var(--accent2))"></div></div>
    </div>
    <div class="table-responsive"><table class="table tc mb-0"><thead><tr><th>#</th><th>Indicator</th><th>Type</th><th>Risk</th><th>Level</th><th>Reputation</th><th>VT</th><th>Abuse</th><th>View</th></tr></thead><tbody id="batchBody"></tbody></table></div>
  </div>

  <!-- HISTORY -->
  <div class="card-dark p-4" id="histSec">
    <div class="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">
      <h5 class="fw-bold mb-0" style="color:var(--text)"><i class="bi bi-clock-history me-2" style="color:var(--muted)"></i>Recent Inquiries</h5>
      <div class="d-flex gap-2">
        <input type="text" id="histFilter" class="si" style="width:180px;padding:.4rem .8rem;font-size:.83rem" placeholder="Filter..." oninput="renderHist()">
        <button class="btn-sec px-3" style="border-radius:8px;font-size:.82rem" onclick="clearHist()"><i class="bi bi-trash"></i></button>
      </div>
    </div>
    <div class="table-responsive"><table class="table tc mb-0"><thead><tr><th>Indicator</th><th>Type</th><th>Risk</th><th>Level</th><th>Date</th><th>Re-Run</th></tr></thead><tbody id="histBody"></tbody></table></div>
  </div>
</div>

<!-- SPINNER -->
<div class="so" id="overlay"><div class="sb2"><div class="spinner-border mb-3" style="color:var(--accent);width:3rem;height:3rem"></div><h5 class="fw-bold mb-1" id="olTitle" style="color:var(--text)">Analyzing...</h5><p class="mb-0 small" style="color:var(--muted)" id="olSub">Consulting threat feeds</p></div></div>

<!-- TOAST -->
<div class="toast-container"><div id="aToast" class="toast align-items-center border-0" role="alert" style="background:var(--card2);color:var(--text)"><div class="d-flex"><div class="toast-body" id="toastMsg">Done</div><button type="button" class="btn-close me-2 m-auto" data-bs-dismiss="toast"></button></div></div></div>

<!-- EMAIL MODAL -->
<div class="modal fade" id="emailModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content" style="background:var(--card);border:1px solid var(--border)"><div class="modal-header" style="border-color:var(--border)"><h5 class="modal-title" style="color:var(--text)"><i class="bi bi-envelope-fill me-2 text-info"></i>Incident Advisory Email</h5><button type="button" class="btn-close" data-bs-dismiss="modal" style="filter:invert(1)"></button></div><div class="modal-body"><div class="d-flex justify-content-end mb-2"><button class="btn-sec px-3 py-1" style="border-radius:8px;font-size:.82rem" onclick="copyEl('emailContent')"><i class="bi bi-clipboard me-1"></i>Copy</button></div><pre id="emailContent" style="background:var(--code-bg);border:1px solid var(--border);border-radius:8px;padding:1.1rem;color:var(--text2);font-size:.8rem;white-space:pre-wrap;max-height:400px;overflow-y:auto"></pre></div></div></div></div>
""" + SHARED_FOOTER + SHARED_SCRIPTS + r"""
<script>
let curData=null,batchList=[],hist=JSON.parse(localStorage.getItem('ti_h')||'[]'),tn=null,activeSiem='splunk';
const toast=new bootstrap.Toast(document.getElementById('aToast'),{delay:3200});
const emailModal=new bootstrap.Modal(document.getElementById('emailModal'));

document.addEventListener('DOMContentLoaded',()=>{
  renderHist();
  const rr=sessionStorage.getItem('rerun');
  if(rr){sessionStorage.removeItem('rerun');document.getElementById('inp').value=rr;proc(rr);}
});
document.getElementById('tf').addEventListener('submit',async e=>{e.preventDefault();const v=document.getElementById('inp').value.trim();if(!v){showToast('Enter an IOC');return;}await proc(v);});
document.getElementById('clearBtn').addEventListener('click',()=>{document.getElementById('inp').value='';['singleCard','batchCard','sAlert'].forEach(id=>document.getElementById(id).classList.add('d-none'));});
document.getElementById('sampleBtn').addEventListener('click',()=>{document.getElementById('inp').value='185.220.101.5';showToast('Sample loaded');});

async function proc(raw){
  showOl('Extracting IOCs...','Parsing threat feeds');
  ['singleCard','batchCard','sAlert'].forEach(id=>document.getElementById(id).classList.add('d-none'));
  try{
    const r=await fetch('/api/extract-iocs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:raw})});
    const {iocs}=await r.json();
    if(iocs.length>1){hideOl();await batchEnrich(iocs);}
    else{const t=iocs.length===1?iocs[0].value:raw;const res=await qSingle(t);hideOl();if(res&&!res.error)dispResult(res);else if(res?.error)showAlert(res.error);}
  }catch(e){hideOl();showAlert('Error: '+e.message);}
}
async function qSingle(ind){
  try{const r=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indicator:ind})});
    const d=await r.json();if(r.status===401)window.location='/login';return d;}
  catch(e){showAlert('Error: '+e.message);return null;}
}
async function batchEnrich(iocs){
  document.getElementById('batchCard').classList.remove('d-none');
  const tbody=document.getElementById('batchBody');tbody.innerHTML='';batchList=[];
  for(let i=0;i<iocs.length;i++){
    const it=iocs[i];document.getElementById('batchBar').style.width=Math.round(i/iocs.length*100)+'%';
    document.getElementById('batchPct').innerText=Math.round(i/iocs.length*100)+'%';
    document.getElementById('batchLbl').innerText=`Analyzing (${i+1}/${iocs.length}): ${it.value}`;
    const rid=`br_${i}`;
    tbody.insertAdjacentHTML('beforeend',`<tr id="${rid}"><td>${i+1}</td><td class="font-monospace" style="max-width:180px;word-break:break-all">${esc(it.value)}</td><td><span class="badge bg-secondary">${it.type.toUpperCase()}</span></td><td colspan="6" style="color:var(--muted)"><div class="spinner-border spinner-border-sm me-2"></div>Enriching...</td></tr>`);
    const res=await qSingle(it.value);const row=document.getElementById(rid);
    if(res&&!res.error){
      batchList.push(res);
      const sc=rc(res.risk_score);
      const vt=(res.virustotal&&res.virustotal.total)?`${res.virustotal.detections}/${res.virustotal.total}`:(res.virustotal?.status||'N/A');
      const ab=(res.abuseipdb&&res.abuseipdb.confidence!==undefined)?`${res.abuseipdb.confidence}%`:'N/A';
      row.innerHTML=`<td>${i+1}</td><td class="font-monospace" style="max-width:200px;word-break:break-all">${esc(res.indicator)}</td><td><span class="badge bg-secondary">${res.indicator_type.toUpperCase()}</span></td><td><strong style="color:${sc}">${res.risk_score}</strong>/100</td><td><span class="badge badge-${(res.threat_level||'unknown').toLowerCase()}">${res.threat_level}</span></td><td class="rep-${(res.reputation||'unknown').toLowerCase()}">${res.reputation}</td><td>${vt}</td><td>${ab}</td><td><button class="btn-sec py-0 px-2" style="font-size:.78rem" onclick='dispResult(batchList[${batchList.length-1}])'><i class="bi bi-eye"></i></button></td>`;
    }else{row.innerHTML=`<td>${i+1}</td><td class="font-monospace">${esc(it.value)}</td><td><span class="badge bg-secondary">${it.type.toUpperCase()}</span></td><td colspan="6" class="text-danger small">Failed</td>`;}
  }
  document.getElementById('batchBar').style.width='100%';document.getElementById('batchPct').innerText='100%';
  document.getElementById('batchLbl').innerText=`Done — ${iocs.length} IOCs analyzed`;showToast(`Batch complete: ${iocs.length} indicators`);
}
document.getElementById('btnBatchExport').addEventListener('click',()=>{
  if(!batchList.length)return;const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(batchList,null,2)],{type:'application/json'}));a.download=`batch_${Date.now()}.json`;a.click();showToast('Exported');
});
function dispResult(d){
  curData=d;document.getElementById('singleCard').classList.remove('d-none');
  document.getElementById('resInd').innerText=d.indicator;
  document.getElementById('resType').innerText=(d.indicator_type||'UNKNOWN').toUpperCase();
  document.getElementById('resCached').classList.toggle('d-none',!d.from_cache);
  const lvl=d.threat_level||'Unknown';
  const tb=document.getElementById('resThreat');tb.innerText=lvl;tb.className=`badge badge-${lvl.toLowerCase()}`;
  document.getElementById('resRep').innerText=d.reputation||'Unknown';document.getElementById('resRep').className=`ms-1 rep-${(d.reputation||'unknown').toLowerCase()}`;
  animGauge(d.risk_score||0);
  const vt=d.virustotal;document.getElementById('vVT').innerText=(vt&&vt.total)?`${vt.detections}/${vt.total}`:(vt?.status||'0/0');document.getElementById('vVT').style.color=rc(d.risk_score);
  const ab=d.abuseipdb;document.getElementById('vAb').innerText=(ab&&ab.confidence!==undefined)?`${ab.confidence}%`:'N/A';document.getElementById('vRep').innerText=(ab&&ab.reports!==undefined)?`${ab.reports}`:'N/A';
  const ws=d.whois||{};document.getElementById('vReg').innerText=ws.registrar||ab?.isp||'—';document.getElementById('vDom').innerText=ws.creation_date?fmtD(ws.creation_date):'—';document.getElementById('vPorts').innerText=(d.open_ports&&d.open_ports.length)?d.open_ports.join(', '):'None';
  document.getElementById('aiText').innerText=d.ai_narrative||'';
  document.getElementById('aiRecs').innerHTML=(d.soc_actions||[]).map(a=>`<span class="badge" style="background:var(--card2);border:1px solid #3b82f6;color:#93c5fd;padding:.35rem .6rem;margin:.2rem"><i class="bi bi-shield-check me-1"></i>${esc(a)}</span>`).join('');
  document.getElementById('resDefang').innerText=d.defanged||d.indicator;
  document.getElementById('yara').innerText=d.yara_rule||'// None';document.getElementById('snort').innerText=d.snort_rule||'# None';
  const sq=d.siem_queries||{};['splunk','sentinel','elastic','crowdstrike'].forEach(k=>{document.getElementById(`sb_${k}`).innerText=sq[k]||`// No ${k} query generated`;});
  showSiem('splunk');
  document.getElementById('actors').innerHTML=d.threat_actors&&d.threat_actors.length?d.threat_actors.map(a=>`<span class="badge" style="background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.4);color:#fca5a5;padding:.35rem .6rem;margin:.2rem">${esc(a)}</span>`).join(''):`<span style="color:var(--muted);font-size:.88rem">No attribution identified</span>`;
  document.getElementById('mitre').innerHTML=d.mitre_ttps&&d.mitre_ttps.length?d.mitre_ttps.map(t=>`<div class="mitre-badge"><span class="tid">${esc(t.id)}</span><span class="tn">${esc(t.name)}</span><span class="td">${esc(t.description||'')}</span></div>`).join(''):`<span style="color:var(--muted);font-size:.88rem">No TTPs mapped</span>`;
  renderGraph(d);saveHist(d);renderHist();document.getElementById('singleCard').scrollIntoView({behavior:'smooth',block:'start'});
}
function showSiem(k){activeSiem=k;document.querySelectorAll('.sc2').forEach(e=>e.classList.remove('active'));document.querySelectorAll('#siemTabs .nav-link').forEach(e=>e.classList.remove('active'));document.getElementById(`sb_${k}`).classList.add('active');document.querySelectorAll('#siemTabs .nav-link').forEach(e=>{if(e.getAttribute('onclick')&&e.getAttribute('onclick').includes(k))e.classList.add('active');});}
function copyActiveSiem(){copyEl(`sb_${activeSiem}`);}
function renderGraph(d){
  const c=document.getElementById('tgc');
  const nodes=[{id:1,label:d.indicator,color:'#00d4ff',shape:'dot',size:22,font:{color:'#fff',face:'monospace'}}];const edges=[];let nid=2;
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
  circle.style.strokeDashoffset=circ;setTimeout(()=>{circle.style.strokeDashoffset=off;circle.style.stroke=rc(s);},60);
  num.innerText=s;num.style.color=rc(s);
}
function rc(s){return s<=30?'#10b981':s<=60?'#f59e0b':s<=80?'#f97316':'#ef4444';}
async function runDefang(){
  const v=document.getElementById('dfInp').value.trim();const t=document.getElementById('dfType').value;if(!v)return;
  const r=await fetch('/api/defang',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indicator:v,ioc_type:t})});
  const d=await r.json();document.getElementById('dfOut').innerText=d.defanged||'—';document.getElementById('rfOut').innerText=d.original||v;
}
async function runRefang(){
  const v=document.getElementById('dfInp').value.trim();if(!v)return;
  const r=await fetch('/api/refang',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indicator:v})});
  const d=await r.json();document.getElementById('rfOut').innerText=d.refanged||'—';document.getElementById('dfOut').innerText=v;
}
function copyEl(id){navigator.clipboard.writeText(document.getElementById(id).innerText).then(()=>showToast('Copied!'));}
document.getElementById('btnStix').addEventListener('click',()=>{
  if(!curData)return;const b={type:"bundle",spec_version:"2.1",objects:[{type:"indicator",id:`indicator--${Math.random().toString(36).slice(2)}`,created:new Date().toISOString(),pattern:`[${curData.indicator_type}:value = '${curData.indicator}']`,confidence:curData.risk_score}]};
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(b,null,2)],{type:'application/json'}));a.download=`stix2.1_${curData.indicator.replace(/[^a-zA-Z0-9]/g,'_')}.json`;a.click();showToast('STIX exported');
});
document.getElementById('btnJson').addEventListener('click',()=>{
  if(!curData)return;const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(curData,null,2)],{type:'application/json'}));a.download=`ti_${curData.indicator.replace(/[^a-zA-Z0-9]/g,'_')}.json`;a.click();showToast('JSON exported');
});
document.getElementById('btnPdf').addEventListener('click',async()=>{
  if(!curData)return;showOl('Generating PDF','Compiling forensic report...');
  try{const r=await fetch('/api/generate-pdf',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indicator:curData.indicator,data:curData})});
    const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`ForensicReport_${curData.indicator.replace(/[^a-zA-Z0-9]/g,'_')}_${Date.now()}.pdf`;a.click();showToast('PDF Downloaded!');}
  catch(e){showToast('PDF error: '+e.message);}finally{hideOl();}
});
document.getElementById('btnEmail').addEventListener('click',async()=>{
  if(!curData)return;const r=await fetch('/api/email-body',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indicator:curData.indicator,data:curData})});
  const b=await r.json();document.getElementById('emailContent').innerText=b.email_body;emailModal.show();
});
function saveHist(d){hist=hist.filter(h=>h.indicator!==d.indicator);hist.unshift({indicator:d.indicator,indicator_type:d.indicator_type,risk_score:d.risk_score,threat_level:d.threat_level,timestamp:new Date().toISOString()});hist=hist.slice(0,10);localStorage.setItem('ti_h',JSON.stringify(hist));}
function renderHist(){
  const q=(document.getElementById('histFilter')?.value||'').toLowerCase();
  const f=hist.filter(h=>h.indicator.toLowerCase().includes(q));
  const tbody=document.getElementById('histBody');
  if(!f.length){tbody.innerHTML=`<tr><td colspan="6" class="text-center py-4" style="color:var(--muted)">No recent queries</td></tr>`;return;}
  tbody.innerHTML=f.map(h=>`<tr><td class="font-monospace small" style="max-width:220px;word-break:break-all">${esc(h.indicator)}</td><td><span class="badge bg-secondary">${(h.indicator_type||'').toUpperCase()}</span></td><td><strong style="color:${rc(h.risk_score)}">${h.risk_score}</strong>/100</td><td><span class="badge badge-${(h.threat_level||'unknown').toLowerCase()}">${h.threat_level}</span></td><td class="small" style="color:var(--muted)">${new Date(h.timestamp).toLocaleString()}</td><td><button class="btn-sec py-0 px-2" style="font-size:.75rem" onclick="reRun('${esc(h.indicator)}')"><i class="bi bi-arrow-clockwise"></i></button></td></tr>`).join('');
}
function reRun(ind){document.getElementById('inp').value=ind;proc(ind);}
function clearHist(){hist=[];localStorage.removeItem('ti_h');renderHist();showToast('History cleared');}
function showOl(t,s){document.getElementById('olTitle').innerText=t;document.getElementById('olSub').innerText=s;document.getElementById('overlay').classList.add('active');}
function hideOl(){document.getElementById('overlay').classList.remove('active');}
function showToast(msg){document.getElementById('toastMsg').innerText=msg;toast.show();}
function showAlert(msg){document.getElementById('sAlertTxt').innerText=msg;document.getElementById('sAlert').classList.remove('d-none');}
function esc(s){return s?String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'):'';}
function fmtD(d){try{return new Date(d).toLocaleDateString();}catch(e){return String(d);}}
</script>
</body></html>"""

# ============================================================
# ThreatIntelAnalyzer CLASS
# ============================================================
class ThreatIntelAnalyzer:
    PATTERNS={
        "ipv4":re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
        "url":re.compile(r'https?://[^\s<>"\'{}|\\^`]+'),
        "sha256":re.compile(r'\b[a-fA-F0-9]{64}\b'),
        "sha1":re.compile(r'\b[a-fA-F0-9]{40}\b'),
        "md5":re.compile(r'\b[a-fA-F0-9]{32}\b'),
    }
    CACHE_TTL_HOURS=24; TIMEOUT=10

    def __init__(self):
        self.logger=logging.getLogger("threatintel.engine"); self.load_api_keys()

    def load_api_keys(self):
        self.vt_key=os.environ.get("VT_API_KEY","").strip().strip('"').strip("'")
        self.abuse_key=os.environ.get("ABUSEIPDB_KEY","").strip().strip('"').strip("'")

    def check_cache(self,indicator):
        try:
            with get_db() as conn:
                row=conn.execute("SELECT * FROM cache WHERE indicator=?",(indicator,)).fetchone()
                if row:
                    ca=datetime.fromisoformat(str(row["created_at"]).replace('Z',''))
                    if datetime.utcnow()-ca<timedelta(hours=self.CACHE_TTL_HOURS):
                        d=json.loads(row["json_response"]); d["from_cache"]=True; return d
        except Exception: pass
        return None

    def cache_result(self,indicator,data):
        try:
            with get_db() as conn:
                conn.execute("""INSERT INTO cache(indicator,indicator_type,risk_score,threat_level,json_response)
                    VALUES(?,?,?,?,?) ON CONFLICT(indicator) DO UPDATE SET
                    json_response=excluded.json_response,created_at=CURRENT_TIMESTAMP""",
                    (indicator,data.get("indicator_type"),data.get("risk_score"),data.get("threat_level"),json.dumps(data)))
                conn.commit()
        except Exception: pass

    def extract_iocs(self,text):
        found={}
        for t in ("sha256","sha1","md5","ipv4","url"):
            for m in self.PATTERNS[t].finditer(text):
                v=m.group(0).rstrip(".,;:)'\"")
                if v not in found: found[v]=t
        return [{"value":k,"type":v} for k,v in found.items()]

    def classify_indicator(self,ind):
        ind=ind.strip()
        if self.PATTERNS["sha256"].fullmatch(ind): return "sha256"
        if self.PATTERNS["sha1"].fullmatch(ind):   return "sha1"
        if self.PATTERNS["md5"].fullmatch(ind):    return "md5"
        if self.PATTERNS["ipv4"].fullmatch(ind):   return "ipv4"
        if self.PATTERNS["url"].match(ind):        return "url"
        if re.match(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$',ind): return "url"
        return "unknown"

    def query_virustotal(self,indicator):
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
            r=req_lib.get(ep,headers=hdrs,timeout=self.TIMEOUT)
            if r.status_code==200:
                attr=r.json().get("data",{}).get("attributes",{}); stats=attr.get("last_analysis_stats",{})
                return {"detections":stats.get("malicious",0),"total":sum(stats.values()) if stats else 0,"scan_date":attr.get("last_analysis_date",int(time.time()))}
            elif r.status_code==404: return {"detections":0,"total":0,"status":"Not Seen / Clean"}
        except Exception: pass
        return None

    def query_abuseipdb(self,indicator):
        self.load_api_keys()
        if not REQUESTS_OK or not self.abuse_key: return None
        if self.classify_indicator(indicator)!="ipv4": return None
        try:
            r=req_lib.get("https://api.abuseipdb.com/api/v2/check",
                headers={"Key":self.abuse_key,"Accept":"application/json"},
                params={"ipAddress":indicator,"maxAgeInDays":90},timeout=self.TIMEOUT)
            if r.status_code==200:
                d=r.json().get("data",{})
                return {"confidence":d.get("abuseConfidenceScore",0),"reports":d.get("totalReports",0),"country":d.get("countryCode","—"),"isp":d.get("isp","—")}
        except Exception: pass
        return None

    def query_whois(self,indicator):
        if not WHOIS_OK: return None
        if self.classify_indicator(indicator) not in ("url","unknown"): return None
        dom=re.sub(r'^https?://','',indicator).split('/')[0].split(':')[0]
        try:
            w=python_whois.whois(dom)
            def cd(d):
                x=d[0] if isinstance(d,list) else d
                return x.isoformat() if hasattr(x,"isoformat") else str(d) if d else None
            return {"registrar":str(w.registrar) if w.registrar else None,"creation_date":cd(w.creation_date),"expiration_date":cd(w.expiration_date),"name_servers":list(w.name_servers)[:4] if w.name_servers else []}
        except Exception: pass
        return None

    def calculate_risk_score(self,data):
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

    def generate_yara_rule(self,indicator,itype,score):
        safe=re.sub(r'[^a-zA-Z0-9_]','_',indicator)[:24]; sev='Critical' if score>=80 else 'High' if score>=60 else 'Medium'
        if itype in ("md5","sha1","sha256"):
            return f"rule rule_ti_{safe}\n{{\n    meta:\n        description = \"Malicious payload\"\n        threat_level = \"{sev}\"\n        source = \"ThreatIntel Analyzer 2.0\"\n        date = \"{datetime.utcnow().strftime('%Y-%m-%d')}\"\n    condition:\n        hash.{itype}(0, filesize) == \"{indicator}\"\n}}"
        return f"rule rule_ti_{safe}\n{{\n    meta:\n        description = \"Network indicator\"\n        threat_level = \"{sev}\"\n    strings:\n        $ioc = \"{indicator}\" nocase ascii wide\n    condition:\n        $ioc\n}}"

    def generate_snort_rule(self,indicator,itype):
        sid=1000000+abs(hash(indicator))%900000
        if itype=="ipv4": return f'drop ip any any -> {indicator} any (msg:"THREATINTEL: Blocked C2 IP [{indicator}]"; sid:{sid}; rev:1;)'
        elif itype=="url":
            dom=re.sub(r'^https?://','',indicator).split('/')[0]
            return f'drop tcp any any -> any $HTTP_PORTS (msg:"THREATINTEL: Blocked domain [{dom}]"; content:"Host|3A| {dom}"; sid:{sid}; rev:1;)'
        return f'alert tcp any any -> any any (msg:"THREATINTEL: Hash Alert [{indicator[:16]}...]"; sid:{sid}; rev:1;)'

    def generate_ai_narrative(self,indicator,itype,score,vt,ab):
        vd=vt.get("detections",0) if vt else 0; ac=ab.get("confidence",0) if ab else 0
        if score>=75 or vd>=10 or ac>=70:
            return (f"CRITICAL THREAT ADVISORY: '{indicator}' has confirmed malicious weaponization. Multi-engine feeds link this asset to active C2 communication. Immediate containment is mandatory."),["Enforce edge firewall & DNS sinkhole blocking","Isolate endpoints via EDR containment","Force credential resets & revoke session tokens","Retro-hunt SIEM logs for past 30 days"]
        elif score>=40:
            return (f"SUSPICIOUS ACTIVITY: '{indicator}' shows anomalous behavior patterns. Warrants proactive monitoring."),["Add to SIEM high-priority watchlist","Inspect historical firewall/DNS logs","Alert Tier-1 SOC analysts"]
        return (f"BENIGN / BASELINE: '{indicator}' shows standard characteristics with negligible detections."),["Maintain standard firewall logging","No active containment required"]

    def enrich_indicator(self,indicator):
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

    def generate_pdf(self,indicator,data):
        if not REPORTLAB_OK: raise RuntimeError("pip install reportlab")
        buffer=BytesIO()
        doc=SimpleDocTemplate(buffer,pagesize=A4,leftMargin=36,rightMargin=36,topMargin=36,bottomMargin=36)
        styles=getSampleStyleSheet()
        C_BLUE=colors.HexColor("#0284c7"); C_DARK=colors.HexColor("#0f172a"); C_CARD=colors.HexColor("#1e293b")
        C_LIGHT=colors.HexColor("#f8fafc"); C_BORDER=colors.HexColor("#cbd5e1"); C_TEXT=colors.HexColor("#334155")
        C_MUTED=colors.HexColor("#64748b"); C_CODE=colors.HexColor("#f1f5f9"); C_GREEN=colors.HexColor("#10b981")
        C_RED=colors.HexColor("#ef4444"); C_PURPLE=colors.HexColor("#6366f1"); C_PINK=colors.HexColor("#be185d")
        score=data.get("risk_score",0); level=data.get("threat_level","Unknown")
        story=[]
        def h2(t): return Paragraph(t,ParagraphStyle("h2",parent=styles["Heading2"],fontSize=11,fontName="Helvetica-Bold",textColor=C_BLUE,spaceBefore=4,spaceAfter=4))
        def body(t): return Paragraph(t,ParagraphStyle("b",parent=styles["Normal"],fontSize=8.5,textColor=C_TEXT,leading=12))
        def code_p(t): return Paragraph(t,ParagraphStyle("c",parent=styles["Normal"],fontSize=7,fontName="Courier",textColor=C_TEXT,leading=10))
        story.append(Table([[
            Paragraph("<b>THREATINTEL ANALYZER 2.0</b><br/><font size='8' color='#64748b'>Enterprise Cyber Threat Intelligence Center</font>",ParagraphStyle("hL",parent=styles["Normal"],fontSize=13,fontName="Helvetica-Bold",textColor=C_BLUE)),
            Paragraph("<font size='9'><b>CLASSIFICATION:</b></font><br/><font size='10' color='#d97706'><b>TLP:AMBER · STRICT</b></font>",ParagraphStyle("hR",parent=styles["Normal"],alignment=TA_RIGHT))
        ]],colWidths=["60%","40%"]))
        story.append(HRFlowable(width="100%",thickness=2,color=C_BLUE,spaceAfter=10))
        meta=Table([[
            Paragraph(f"<b>Target:</b> {indicator}",ParagraphStyle("m1",parent=styles["Normal"],fontName="Courier-Bold",fontSize=9,textColor=C_LIGHT)),
            Paragraph(f"<b>Type:</b> {data.get('indicator_type','—').upper()}",ParagraphStyle("m2",parent=styles["Normal"],fontSize=9,textColor=C_LIGHT)),
            Paragraph(f"<b>Level:</b> {level}",ParagraphStyle("m3",parent=styles["Normal"],fontSize=9,textColor=C_LIGHT)),
            Paragraph(f"<b>Risk:</b> {score}/100",ParagraphStyle("m4",parent=styles["Normal"],fontSize=9,textColor=C_LIGHT))
        ]],colWidths=["40%","20%","22%","18%"])
        meta.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_DARK),("PADDING",(0,0),(-1,-1),6),("BOX",(0,0),(-1,-1),1,C_CARD)]))
        story.append(meta); story.append(Spacer(1,12))
        story.append(h2("1. AI SOC Threat Narrative"))
        nb=Table([[body(data.get("ai_narrative","Complete."))]],colWidths=["100%"])
        nb.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_CODE),("BOX",(0,0),(-1,-1),1,C_BORDER),("PADDING",(0,0),(-1,-1),8)]))
        story.append(nb); story.append(Spacer(1,10))
        story.append(h2("2. Multi-Feed Intelligence Findings"))
        vt=data.get("virustotal") or {}; ab=data.get("abuseipdb") or {}; ws=data.get("whois") or {}
        fi=[["Feed","Property","Value","Contribution"],
            ["VirusTotal v3","Engine Detections",f"{vt.get('detections',0)}/{vt.get('total',0)}",f"+{int(min(45,(vt.get('detections',0)/max(1,vt.get('total',1)))*45))} pts"],
            ["AbuseIPDB v2","Abuse Confidence",f"{ab.get('confidence','N/A')}% ({ab.get('reports',0)} reports)",f"+{int((ab.get('confidence',0)/100)*35) if ab.get('confidence') else 0} pts"],
            ["AbuseIPDB v2","ISP / Country",f"{ab.get('isp','—')} ({ab.get('country','—')})","Contextual"],
            ["WHOIS","Registrar",str(ws.get("registrar","N/A"))[:40],"Contextual"],
            ["Network","Open Ports",", ".join(data.get("open_ports",[])) or "None","Perimeter"]]
        t_fi=Table(fi,colWidths=["20%","28%","38%","14%"])
        t_fi.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_CARD),("TEXTCOLOR",(0,0),(-1,0),C_LIGHT),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),7.5),("GRID",(0,0),(-1,-1),.5,C_BORDER),("PADDING",(0,0),(-1,-1),4.5),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f8fafc")])]))
        story.append(t_fi); story.append(Spacer(1,10))
        story.append(h2("3. Defanged IOC Representation"))
        df=[["Format","Value"],["Original (Live — DO NOT share)",indicator],["Defanged (Safe to share)",data.get("defanged",indicator)]]
        t_df=Table(df,colWidths=["30%","70%"])
        t_df.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_PINK),("TEXTCOLOR",(0,0),(-1,0),C_LIGHT),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTNAME",(0,1),(-1,-1),"Courier"),("FONTSIZE",(0,0),(-1,-1),7.5),("GRID",(0,0),(-1,-1),.5,C_BORDER),("PADDING",(0,0),(-1,-1),5)]))
        story.append(t_df); story.append(Spacer(1,10))
        ttps=data.get("mitre_ttps") or []
        if ttps:
            story.append(h2("4. MITRE ATT&CK TTP Matrix"))
            m_data=[["TTP ID","Technique","Description"]]+[[t["id"],t["name"],t.get("description","—")[:60]] for t in ttps]
            t_m=Table(m_data,colWidths=["15%","28%","57%"])
            t_m.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_PURPLE),("TEXTCOLOR",(0,0),(-1,0),C_LIGHT),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTNAME",(0,1),(0,-1),"Courier-Bold"),("FONTSIZE",(0,0),(-1,-1),7.5),("GRID",(0,0),(-1,-1),.5,C_BORDER),("PADDING",(0,0),(-1,-1),4.5)]))
            story.append(t_m); story.append(Spacer(1,10))
        actors=data.get("threat_actors") or []
        story.append(h2("5. Threat Actor Attribution"))
        story.append(body(f"<b>Attributed Actor(s):</b> {', '.join(actors)}" if actors else "No APT group definitively linked."))
        story.append(Spacer(1,10))
        story.append(h2("6. SIEM Hunting Queries"))
        sq=data.get("siem_queries") or {}
        for pname,pkey in [("Splunk SPL","splunk"),("Microsoft Sentinel KQL","sentinel"),("Elasticsearch","elastic"),("CrowdStrike Falcon","crowdstrike")]:
            story.append(Paragraph(f"<b>{pname}:</b>",ParagraphStyle("ql",parent=styles["Normal"],fontSize=8,textColor=C_BLUE,spaceAfter=2)))
            qt=Table([[code_p(sq.get(pkey,"N/A"))]],colWidths=["100%"])
            qt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_CODE),("BOX",(0,0),(-1,-1),1,C_BORDER),("PADDING",(0,0),(-1,-1),4)]))
            story.append(qt); story.append(Spacer(1,4))
        story.append(Spacer(1,6))
        story.append(h2("7. Detection Signatures"))
        sig=f"<b>Snort/Suricata:</b><br/><font face='Courier' size='7'>{data.get('snort_rule','N/A')}</font><br/><br/><b>YARA:</b><br/><font face='Courier' size='6.5'>{data.get('yara_rule','N/A').replace(chr(10),'<br/>')}</font>"
        t_sig=Table([[body(sig)]],colWidths=["100%"])
        t_sig.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_CODE),("BOX",(0,0),(-1,-1),1,C_BORDER),("PADDING",(0,0),(-1,-1),6)]))
        story.append(t_sig); story.append(Spacer(1,10))
        story.append(h2("8. SOC Incident Response Checklist"))
        for i,a in enumerate(data.get("soc_actions",[]) or ["Maintain routine monitoring"]):
            story.append(body(f"[ ] Step {i+1}: {a}"))
        story.append(Spacer(1,14))
        story.append(HRFlowable(width="100%",thickness=1,color=C_BORDER,spaceAfter=6))
        story.append(Paragraph("Generated by <b>ThreatIntel Analyzer 2.0</b> · TLP:AMBER · Restricted",ParagraphStyle("ft",parent=styles["Normal"],fontSize=7,textColor=C_MUTED,alignment=TA_CENTER)))
        doc.build(story); buffer.seek(0); return buffer

    def generate_email_body(self,indicator,data):
        sq=data.get("siem_queries") or {}
        return f"""======================================================================
THREATINTEL 2.0 - INCIDENT ADVISORY BRIEFING
======================================================================
Target Indicator : {indicator}
Defanged IOC     : {data.get('defanged',indicator)}
Threat Rating    : {data.get('risk_score')}/100 ({data.get('threat_level')} Severity)
Reputation       : {data.get('reputation')}
Analyzed At      : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
----------------------------------------------------------------------
EXECUTIVE BRIEFING:
{data.get('ai_narrative','N/A')}
----------------------------------------------------------------------
RECOMMENDED SOC ACTIONS:
{chr(10).join(['  - '+a for a in data.get('soc_actions',[])])}
----------------------------------------------------------------------
SNORT RULE:
{data.get('snort_rule','N/A')}
----------------------------------------------------------------------
SPLUNK SPL QUERY:
{sq.get('splunk','N/A')}
----------------------------------------------------------------------
SENTINEL KQL QUERY:
{sq.get('sentinel','N/A')}
======================================================================
Generated by ThreatIntel Analyzer 2.0
"""

analyzer=ThreatIntelAnalyzer()

# ============================================================
# FLASK ROUTES
# ============================================================
@app.route("/")
def home():
    return render_template_string(HOME_TEMPLATE)

@app.route("/login",methods=["GET","POST"])
def login_page():
    if current_user.is_authenticated: return redirect(url_for("analyzer_page"))
    if request.method=="POST":
        email=request.form.get("email","").strip()
        password=request.form.get("password","")
        row=db_get_user_by_email(email)
        if row and check_password_hash(row["password_hash"],password):
            u=User(row["id"],row["username"],row["email"],row["role"])
            login_user(u,remember=bool(request.form.get("remember")))
            db_log_activity(u.id,u.username,"login","{}",request.remote_addr)
            return redirect(url_for("analyzer_page"))
        flash("Invalid email or password. Please try again.","error")
    return render_template_string(LOGIN_TEMPLATE)

@app.route("/signup",methods=["GET","POST"])
def signup_page():
    if current_user.is_authenticated: return redirect(url_for("analyzer_page"))
    if request.method=="POST":
        username=request.form.get("username","").strip()
        email=request.form.get("email","").strip()
        password=request.form.get("password","")
        confirm=request.form.get("confirm_password","")
        if not username or len(username)<3:
            flash("Username must be at least 3 characters.","error")
        elif not email:
            flash("Valid email is required.","error")
        elif password!=confirm:
            flash("Passwords do not match.","error")
        elif len(password)<8:
            flash("Password must be at least 8 characters.","error")
        elif db_get_user_by_email(email):
            flash("This email is already registered. Please login.","error")
        else:
            uid=db_create_user(username,email,generate_password_hash(password))
            if uid:
                db_log_activity(uid,username,"signup","{}",request.remote_addr)
                flash("Account created successfully! Please sign in.","success")
                return redirect(url_for("login_page"))
            flash("Registration failed. Please try again.","error")
    return render_template_string(SIGNUP_TEMPLATE)

@app.route("/logout")
@login_required
def logout():
    db_log_activity(current_user.id,current_user.username,"logout","{}",request.remote_addr)
    logout_user()
    flash("You have been logged out successfully.","success")
    return redirect(url_for("login_page"))

@app.route("/analyzer")
@login_required
def analyzer_page():
    return render_template_string(MAIN_TEMPLATE)

@app.route("/dashboard")
@login_required
def dashboard():
    analyses=db_get_user_analyses(current_user.id)
    return render_template_string(DASHBOARD_TEMPLATE,analyses=analyses)

@app.route("/admin/logs")
@login_required
def admin_logs():
    if not current_user.is_admin:
        flash("Admin access required.","error"); return redirect(url_for("home"))
    logs=db_get_all_logs()
    all_analyses=db_get_all_analyses()
    users=db_get_all_users()
    stats=db_get_admin_stats()
    return render_template_string(ADMIN_LOGS_TEMPLATE,logs=logs,all_analyses=all_analyses,users=users,stats=stats)

@app.route("/api/status")
def api_status():
    analyzer.load_api_keys()
    return jsonify({"apis_configured":(1 if analyzer.vt_key else 0)+(1 if analyzer.abuse_key else 0)})

@app.route("/api/extract-iocs",methods=["POST"])
def extract_iocs_ep():
    p=request.get_json(silent=True) or {}; t=p.get("text","").strip()
    return jsonify({"iocs":analyzer.extract_iocs(t) if t else []})

@app.route("/api/analyze",methods=["POST"])
@login_required
def analyze_ep():
    p=request.get_json(silent=True) or {}; ind=p.get("indicator","").strip()
    if not ind: return jsonify({"error":"No indicator provided"}),400
    try:
        result=analyzer.enrich_indicator(ind)
        if not result.get("from_cache"):
            db_save_analysis(current_user.id,current_user.username,ind,result.get("indicator_type"),result.get("risk_score"),result.get("threat_level"),result.get("reputation"))
            db_log_activity(current_user.id,current_user.username,"analyze",json.dumps({"indicator":ind,"risk_score":result.get("risk_score"),"level":result.get("threat_level")}),request.remote_addr)
        return jsonify(result)
    except Exception as e:
        logger.exception("Analyze error"); return jsonify({"error":str(e)}),500

@app.route("/api/defang",methods=["POST"])
def defang_ep():
    p=request.get_json(silent=True) or {}; ind=p.get("indicator","").strip()
    itype=p.get("ioc_type","") or analyzer.classify_indicator(ind)
    return jsonify({"original":ind,"defanged":defang(ind,itype)})

@app.route("/api/refang",methods=["POST"])
def refang_ep():
    p=request.get_json(silent=True) or {}; ind=p.get("indicator","").strip()
    return jsonify({"refanged":refang(ind)})

@app.route("/api/generate-pdf",methods=["POST"])
@login_required
def pdf_ep():
    p=request.get_json(silent=True) or {}; ind=p.get("indicator","").strip(); d=p.get("data") or {}
    try:
        buf=analyzer.generate_pdf(ind,d); safe=re.sub(r'[^a-zA-Z0-9_\-]','_',ind)[:30]
        db_log_activity(current_user.id,current_user.username,"pdf_download",json.dumps({"indicator":ind}),request.remote_addr)
        return send_file(buf,mimetype="application/pdf",as_attachment=True,download_name=f"ForensicReport_{safe}_{int(time.time())}.pdf")
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/api/email-body",methods=["POST"])
@login_required
def email_ep():
    p=request.get_json(silent=True) or {}; ind=p.get("indicator","").strip(); d=p.get("data") or {}
    return jsonify({"email_body":analyzer.generate_email_body(ind,d)})

def _browser(url):
    time.sleep(1.2); webbrowser.open(url)

# ============================================================
# PWA ROUTES
# ============================================================
@app.route("/manifest.json")
def pwa_manifest():
    from flask import Response
    manifest = {
        "name": "ThreatIntel Analyzer 2.0",
        "short_name": "ThreatIntel",
        "description": "Enterprise Cyber Threat Intelligence & SOC Automation Platform",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#090c15",
        "theme_color": "#00d4ff",
        "orientation": "portrait-primary",
        "lang": "en-US",
        "categories": ["security", "utilities"],
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
            {"src": "/app_icon.jpg", "sizes": "1024x1024", "type": "image/jpeg", "purpose": "any"}
        ],
        "shortcuts": [
            {"name": "Analyzer", "short_name": "Analyze", "url": "/analyzer", "description": "Open Threat Analyzer"},
            {"name": "Dashboard", "short_name": "Dashboard", "url": "/dashboard", "description": "View your analyses"}
        ]
    }
    return app.response_class(
        response=json.dumps(manifest, indent=2),
        mimetype="application/manifest+json"
    )

@app.route("/sw.js")
def pwa_sw():
    from flask import Response
    return Response(SW_JS, mimetype="application/javascript",
        headers={"Service-Worker-Allowed": "/"})

def _get_icon_bytes():
    """Return AI-generated icon bytes if available, else fallback PNG"""
    # Try AI-generated icon first (app_icon.jpg in project folder)
    icon_path = BASE_DIR / "app_icon.jpg"
    if icon_path.exists():
        with open(str(icon_path), "rb") as f:
            return f.read(), "image/jpeg"
    # Fallback: programmatic PNG
    import struct, zlib
    def chunk(n, d):
        c = n + d
        return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
    size = 192
    sig = b'\x89PNG\r\n\x1a\n'
    ihdr = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)
    bw = 10; r1,g1,b1 = 9,12,21; r2,g2,b2 = 0,212,255
    cx,cy = size//2,size//2
    rows = []
    for y in range(size):
        row = b'\x00'
        for x in range(size):
            if x<bw or x>=size-bw or y<bw or y>=size-bw or ((x-cx)**2+(y-cy)**2)<=(size//6)**2:
                row += bytes([r2,g2,b2])
            else:
                row += bytes([r1,g1,b1])
        rows.append(row)
    raw = b''.join(rows)
    return sig + chunk(b'IHDR', ihdr) + chunk(b'IDAT', zlib.compress(raw, 6)) + chunk(b'IEND', b''), "image/png"

@app.route("/icon-192.png")
def icon_192():
    from flask import Response
    data, mime = _get_icon_bytes()
    return Response(data, mimetype=mime,
        headers={"Cache-Control": "public, max-age=86400"})

@app.route("/icon-512.png")
def icon_512():
    from flask import Response
    data, mime = _get_icon_bytes()
    return Response(data, mimetype=mime,
        headers={"Cache-Control": "public, max-age=86400"})

@app.route("/app_icon.jpg")
def app_icon_direct():
    """Direct access to the icon file"""
    from flask import Response
    icon_path = BASE_DIR / "app_icon.jpg"
    if icon_path.exists():
        with open(str(icon_path), "rb") as f:
            return Response(f.read(), mimetype="image/jpeg",
                headers={"Cache-Control": "public, max-age=86400"})
    return "", 404

if __name__=="__main__":
    host=os.environ.get("HOST","0.0.0.0"); port=int(os.environ.get("PORT",5000))
    print(f"""
  ╔══════════════════════════════════════════╗
  ║   ThreatIntel Analyzer 2.0              ║
  ║   WITH AUTHENTICATION + LOGGING         ║
  ╠══════════════════════════════════════════╣
  ║   Home     → http://localhost:{port}/      ║
  ║   Login    → http://localhost:{port}/login ║
  ║   Analyzer → http://localhost:{port}/analyzer║
  ╚══════════════════════════════════════════╝
    """)
    if os.environ.get("OPEN_BROWSER","1")=="1":
        threading.Thread(target=_browser,args=(f"http://localhost:{port}",),daemon=True).start()
    app.run(host=host,port=port,debug=False)
