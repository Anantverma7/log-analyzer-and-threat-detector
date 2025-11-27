import os
import re
import time
import sys
import threading
import random
import json
import logging
from urllib.parse import unquote
from collections import deque, defaultdict
from datetime import datetime

# --- CONFIGURATION ---
try:
    from flask import Flask, jsonify, render_template_string, request
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("[-] Missing required libraries.")
    print("[-] Please run: pip install flask watchdog")
    sys.exit(1)

# File Paths
LOG_FILE = "sentinel_traffic.log"

# State Flags
AUTO_SIMULATION = True
TARGET_CREDS = {"username": "admin", "password": "password123"}

# Initialize Log File
if not os.path.exists(LOG_FILE): open(LOG_FILE, "w").close()

# --- THREAT INTELLIGENCE ENGINE ---
THREAT_SIGNATURES = [
    {"type": "SQL Injection", "pat": r"(?i)union\s+select", "score": 85, "desc": "Union-Based Extraction"},
    {"type": "SQL Injection", "pat": r"(?i)'\s+or\s+1=1", "score": 65, "desc": "Tautology Auth Bypass"},
    {"type": "SQL Injection", "pat": r"(?i)drop\s+table", "score": 100, "desc": "Destructive Schema Change"},
    {"type": "SQL Injection", "pat": r"(?i)insert\s+into", "score": 75, "desc": "Data Injection Attempt"},
    {"type": "XSS", "pat": r"(?i)<script>", "score": 90, "desc": "Script Tag Injection"},
    {"type": "XSS", "pat": r"(?i)alert\(", "score": 75, "desc": "JS Execution Test"},
    {"type": "Path Traversal", "pat": r"\.\./\.\./", "score": 80, "desc": "Directory Traversal"},
    {"type": "Command Injection", "pat": r";\s*ls", "score": 95, "desc": "OS Command Injection"},
    {"type": "Command Injection", "pat": r"\|\s*cat", "score": 95, "desc": "OS Command Chaining"}
]

# Adjusted Brute Force limit to 6 (>= 6 will ban)
RATE_LIMITS = {
    "Brute Force": {"limit": 6, "window": 30, "ban_duration": 60},
    "DDoS": {"limit": 30, "window": 5, "ban_duration": 120}
}

class SentinelEngine:
    def __init__(self):
        self.logs = deque(maxlen=60)
        self.alerts = deque(maxlen=20)
        self.stats = defaultdict(int)
        self.ip_tracking = defaultdict(lambda: {"timestamps": [], "fails": []})
        self.banned_ips = {} # IP -> Expiry Timestamp
        self.traffic_history = deque(maxlen=20) # For charts
        self.start_time = time.time()

    def is_banned(self, ip):
        if ip in self.banned_ips:
            if time.time() > self.banned_ips[ip]:
                del self.banned_ips[ip] # Expire ban
                return False
            return True
        return False

    def ban_ip(self, ip, duration, reason):
        if ip not in self.banned_ips:
            self.banned_ips[ip] = time.time() + duration
            self.add_alert("System Action", ip, f"BANNED: {reason}", "Critical")
            self.stats["bans"] += 1
            return True
        return False

    def add_alert(self, type, ip, msg, severity):
        self.stats[type] += 1
        self.alerts.appendleft({
            "id": int(time.time() * 100000) + random.randint(0, 999), # Unique ID for UI tracking
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": type,
            "ip": ip,
            "message": msg,
            "severity": severity
        })

    def analyze_log_entry(self, entry):
        """Analyzes a structured log entry (dict) loaded from the file."""
        ip = entry.get('ip')
        content = entry.get('content')
        method = entry.get('method')
        timestamp = entry.get('time')

        # 1. Ban Check - MODIFIED to still log blocked traffic
        if self.is_banned(ip):
            self.stats["blocked"] += 1
            entry['risk_score'] = 100
            entry['risk_level'] = "BLOCKED"
            self.logs.appendleft(entry) # Add to Live Feed even if blocked
            return

        self.stats["total_requests"] += 1
        risk_score = 0
        risk_level = "INFO"
        
        # 2. Signature Analysis
        decoded = unquote(content)
        for sig in THREAT_SIGNATURES:
            if re.search(sig["pat"], decoded):
                risk_score += sig["score"]
                self.add_alert(sig["type"], ip, sig['desc'], "High" if sig["score"] > 80 else "Medium")

        # 3. Heuristic / Rate Analysis (DDoS)
        now = time.time()
        tracker = self.ip_tracking[ip]
        tracker["timestamps"].append(now)
        tracker["timestamps"] = [t for t in tracker["timestamps"] if now - t < RATE_LIMITS["DDoS"]["window"]]
        
        if len(tracker["timestamps"]) > RATE_LIMITS["DDoS"]["limit"]:
            self.ban_ip(ip, RATE_LIMITS["DDoS"]["ban_duration"], "Rate Limit Exceeded (DDoS)")
            risk_level = "CRIT"
            risk_score = 100
        
        # 4. Brute Force Heuristic
        if "POST /login" in content or "LOGIN_FAILED" in content:
             tracker["fails"].append(now)
             tracker["fails"] = [t for t in tracker["fails"] if now - t < RATE_LIMITS["Brute Force"]["window"]]
             
             # Check threshold
             if len(tracker["fails"]) >= RATE_LIMITS["Brute Force"]["limit"]:
                 self.ban_ip(ip, RATE_LIMITS["Brute Force"]["ban_duration"], "Brute Force Detected")
                 risk_level = "CRIT"
                 risk_score = 100
             elif len(tracker["fails"]) > 2:
                 risk_level = "WARN"
                 risk_score = 40
        elif "LOGIN_SUCCESS" in content:
            # Optional: Reset fails on success? 
            # tracker["fails"] = [] 
            risk_level = "SAFE"
            risk_score = 0

        if risk_score > 0: 
            risk_level = "CRIT" if risk_score >= 80 else "WARN"

        # Update Live Log Feed in Memory
        entry['risk_score'] = risk_score
        entry['risk_level'] = risk_level
        self.logs.appendleft(entry)

    def update_history(self):
        # Called every second to snapshot stats for the chart
        self.traffic_history.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "requests": self.stats["total_requests"],
            "blocked": self.stats["blocked"]
        })

engine = SentinelEngine()

# --- WATCHDOG HANDLER ---
class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_file):
        self.log_file = log_file
        self.last_pos = 0

    def on_modified(self, event):
        if event.src_path.endswith(self.log_file):
            self.process_new_lines()

    def process_new_lines(self):
        try:
            with open(self.log_file, 'r') as f:
                f.seek(self.last_pos)
                new_lines = f.readlines()
                self.last_pos = f.tell()
                
                for line in new_lines:
                    try:
                        entry = json.loads(line.strip())
                        engine.analyze_log_entry(entry)
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"Error reading log file: {e}")

# --- SIMULATION UTILS ---
def write_log(ip, uri, method="GET", extra_info=""):
    """Writes a raw log line to the file. Watchdog will pick this up."""
    entry = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "ip": ip,
        "method": method,
        "content": uri + (" " + extra_info if extra_info else "")
    }
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush() # Flush python buffer
            os.fsync(f.fileno()) # Force write to disk immediately for Watchdog
    except: pass

# --- SIMULATION THREAD ---
def simulation_loop():
    print("[*] Simulation Engine Started (Writing to File)")
    normal_uris = ["/dashboard", "/login", "/api/v1/users", "/static/app.js", "/images/logo.png", "/about", "/contact"]
    
    while True:
        if AUTO_SIMULATION:
            try:
                # Generate Random Traffic
                if random.random() < 0.7: # 70% Normal
                    ip = f"192.168.1.{random.randint(2, 250)}"
                    uri = random.choice(normal_uris)
                    write_log(ip, uri)
                else: # 30% Malicious
                    ip = f"10.55.{random.randint(1, 20)}.{random.randint(1, 255)}"
                    attack = random.choice(["SQLi", "XSS", "Traversal"])
                    
                    if attack == "SQLi":
                        payload = random.choice(["' OR 1=1", "UNION SELECT 1,2,3", "admin'; --"])
                        write_log(ip, f"/login?user={payload}")
                    elif attack == "XSS":
                        payload = "<script>alert(1)</script>"
                        write_log(ip, f"/search?q={payload}")
                    elif attack == "Traversal":
                        write_log(ip, "/download?file=../../etc/passwd")
                            
            except Exception as e:
                print(f"Error: {e}")
                
        # Snapshot for charts
        engine.update_history()
        time.sleep(random.uniform(0.5, 1.5))

# --- FLASK APP ---
app = Flask(__name__)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Log Analyzer & Detector</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root { 
            --bg: #0d1117; --panel: #161b22; --border: #30363d; 
            --accent: #58a6ff; --danger: #f85149; --warn: #d29922; --success: #3fb950;
            --text-main: #c9d1d9; --text-dim: #8b949e;
        }
        * { box-sizing: border-box; }
        body { background: var(--bg); color: var(--text-main); font-family: 'JetBrains Mono', monospace; margin: 0; padding: 20px; height: 100vh; overflow: hidden; }
        
        .grid-container {
            display: grid;
            grid-template-columns: 300px 1fr 350px;
            grid-template-rows: 60px 250px 1fr;
            gap: 15px;
            height: calc(100vh - 40px);
        }

        .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 15px; overflow: hidden; display: flex; flex-direction: column; }
        .panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding-bottom: 10px; border-bottom: 1px solid var(--border); }
        h2 { margin: 0; font-size: 14px; text-transform: uppercase; color: var(--accent); letter-spacing: 1px; }
        
        .header { grid-column: 1 / -1; display: flex; justify-content: space-between; align-items: center; background: var(--panel); border: 1px solid var(--border); padding: 0 20px; border-radius: 6px; }
        .logo { font-size: 20px; font-weight: bold; color: var(--success); }
        .status-badge { background: rgba(63, 185, 80, 0.1); color: var(--success); padding: 5px 10px; border-radius: 4px; border: 1px solid var(--success); font-size: 12px; }
        
        .controls { grid-row: 2 / -1; overflow-y: auto; }
        .btn { 
            background: #21262d; border: 1px solid var(--border); color: var(--text-main); 
            padding: 10px; width: 100%; cursor: pointer; margin-bottom: 10px; 
            border-radius: 6px; font-family: inherit; font-size: 12px; transition: 0.2s;
            text-align: left; display: flex; justify-content: space-between; align-items: center;
        }
        .btn:hover { background: #30363d; border-color: var(--text-dim); }
        .btn-red { color: var(--danger); border-color: rgba(248, 81, 73, 0.3); }
        .btn-red:hover { background: rgba(248, 81, 73, 0.1); }
        .btn-green { color: var(--success); border-color: rgba(63, 185, 80, 0.3); }
        .btn-blue { color: var(--accent); border-color: rgba(88, 166, 255, 0.3); }
        
        /* Form Inputs */
        input, select {
            width: 100%; padding: 8px; margin-bottom: 10px; background: #0d1117; 
            border: 1px solid var(--border); color: var(--text-main); border-radius: 4px; font-family: inherit; font-size: 11px;
        }
        label { font-size: 11px; color: var(--text-dim); margin-bottom: 4px; display: block; }
        .attack-form { border: 1px solid var(--border); padding: 10px; border-radius: 6px; margin-bottom: 15px; }

        .chart-container { grid-column: 2 / 3; grid-row: 2 / 3; position: relative; transition: box-shadow 0.3s ease; }
        .chart-flash { box-shadow: 0 0 20px rgba(248, 81, 73, 0.5); border-color: #f85149; }
        
        .logs { grid-column: 2 / 3; grid-row: 3 / -1; overflow-y: auto; }
        .log-table { width: 100%; border-collapse: collapse; font-size: 12px; }
        .log-table th { text-align: left; color: var(--text-dim); padding: 8px; position: sticky; top: 0; background: var(--panel); }
        .log-table td { padding: 6px 8px; border-bottom: 1px solid #21262d; }
        .log-row:hover { background: #21262d; cursor: pointer; }
        .badge { padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: bold; }
        .CRIT { background: rgba(248, 81, 73, 0.15); color: var(--danger); }
        .WARN { background: rgba(210, 153, 34, 0.15); color: var(--warn); }
        .INFO { background: rgba(56, 139, 253, 0.15); color: var(--accent); }
        .SAFE { background: rgba(63, 185, 80, 0.15); color: var(--success); }
        .BLOCKED { background: rgba(139, 148, 158, 0.2); color: #8b949e; border: 1px solid #30363d; text-decoration: line-through; }

        .alerts { grid-column: 3 / -1; grid-row: 2 / -1; overflow-y: auto; scroll-behavior: smooth; }
        .alert-card { 
            background: #21262d; border-left: 3px solid var(--border); 
            padding: 10px; margin-bottom: 10px; font-size: 12px; position: relative;
        }
        .alert-card.new-item { animation: slideIn 0.3s ease-out; }
        .alert-card.Critical { border-color: var(--danger); }
        .alert-card.High { border-color: var(--warn); }
        .alert-time { font-size: 10px; color: var(--text-dim); float: right; }
        .alert-type { font-weight: bold; display: block; margin-bottom: 4px; }
        
        #toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 1000; }
        .toast {
            background: var(--panel); border: 1px solid var(--accent); color: var(--text-main);
            padding: 15px 20px; border-radius: 6px; margin-top: 10px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            animation: popUp 0.3s ease-out forwards;
        }
        
        /* Modals */
        .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.85); z-index: 2000; align-items: center; justify-content: center; backdrop-filter: blur(2px); }
        .modal { background: #161b22; padding: 25px; border-radius: 8px; width: 400px; border: 1px solid #30363d; box-shadow: 0 20px 50px rgba(0,0,0,0.7); animation: modalPop 0.3s ease-out; }
        .modal-lg { width: 800px; height: 600px; display: flex; flex-direction: column; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
        .modal h3 { margin: 0; color: #f85149; font-size: 16px; text-transform: uppercase; letter-spacing: 1px; }
        .close-btn { cursor: pointer; color: #8b949e; font-size: 20px; transition: 0.2s; }
        .close-btn:hover { color: #f0f6fc; }
        .log-dump { background: #0d1117; padding: 10px; border: 1px solid #30363d; font-family: monospace; font-size: 11px; overflow-y: auto; flex: 1; white-space: pre-wrap; color: #c9d1d9; }
        
        @keyframes slideIn { from { opacity: 0; transform: translateX(20px); } to { opacity: 1; transform: 0; } }
        @keyframes popUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: 0; } }
        @keyframes modalPop { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } }
        
        /* Scrollbar Styling */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #0d1117; }
        ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #8b949e; }
    </style>
</head>
<body>

<div class="grid-container">
    <!-- Config Modal -->
    <div id="config-modal" class="modal-overlay">
        <div class="modal">
            <div class="modal-header"><h3 style="color:var(--accent)">System Configuration</h3><span class="close-btn" onclick="closeModal('config-modal')">&times;</span></div>
            <div style="font-size:11px; color:#8b949e; margin-bottom:15px;">Set the valid credentials for the system. Attackers must guess these to succeed.</div>
            <label>Valid Username</label><input type="text" id="conf-user" value="admin">
            <label>Valid Password</label><input type="text" id="conf-pass" value="password123">
            <button class="btn btn-blue" onclick="updateConfig()">UPDATE CREDENTIALS</button>
        </div>
    </div>

    <!-- Attack Modals -->
    <div id="sqli-modal" class="modal-overlay">
        <div class="modal">
            <div class="modal-header"><h3>SQL Injection Tool</h3><span class="close-btn" onclick="closeModal('sqli-modal')">&times;</span></div>
            <label>Target IP (Simulated)</label><input type="text" value="172.16.66.6 (You)" disabled style="opacity:0.5">
            <label>Injection Payload</label>
            <input type="text" id="sqli-payload" value="' OR 1=1 --">
            <button class="btn btn-red" onclick="manualAttack('SQLi')">EXECUTE ATTACK</button>
        </div>
    </div>
    
    <div id="brute-modal" class="modal-overlay">
        <div class="modal">
            <div class="modal-header"><h3>Brute Force Tool</h3><span class="close-btn" onclick="closeModal('brute-modal')">&times;</span></div>
            <div style="background: #222; padding: 10px; border-radius: 4px; margin-bottom: 15px; color: #888; font-size: 11px;">
                <span style="color: #f85149;">INSTRUCTION:</span> Guess the credentials. 6 Wrong attempts = BAN.
            </div>
            <label>Username Guess</label>
            <input type="text" id="brute-user" placeholder="Enter username">
            <label>Password Guess</label>
            <input type="text" id="brute-pass" placeholder="Enter password">
            <button class="btn btn-red" onclick="manualAttack('Brute')">ATTEMPT LOGIN</button>
        </div>
    </div>

    <div id="ddos-modal" class="modal-overlay">
        <div class="modal">
            <div class="modal-header"><h3>DDoS Cannon</h3><span class="close-btn" onclick="closeModal('ddos-modal')">&times;</span></div>
            <label>Target Endpoint</label><input type="text" value="/api/v1/heavy-load" disabled style="opacity:0.5">
            <label>Packet Intensity (Burst Size)</label>
            <input type="number" id="ddos-count" value="50">
            <button class="btn btn-red" onclick="manualAttack('DDoS')">FIRE CANNON</button>
        </div>
    </div>

    <!-- Log Viewer Modal -->
    <div id="log-view-modal" class="modal-overlay">
        <div class="modal modal-lg">
            <div class="modal-header"><h3 style="color:var(--warn)">Detected Threat Logs</h3><span class="close-btn" onclick="closeModal('log-view-modal')">&times;</span></div>
            <div id="detected-logs-content" class="log-dump">Loading...</div>
            <div style="margin-top:10px; text-align:right;"><button class="btn btn-blue" style="width:auto; display:inline-block;" onclick="closeModal('log-view-modal')">CLOSE</button></div>
        </div>
    </div>

    <div class="header">
        <div class="logo">Log Analyzer & Detector</div>
        <div id="sys-status" class="status-badge">SYSTEM SECURE</div>
    </div>

    <div class="panel controls">
        <div class="panel-header"><h2>Red Team Console</h2></div>
        <button class="btn btn-red" onclick="openModal('sqli-modal')"><span>💉 SQL Injection Console</span> <span>OPEN</span></button>
        <button class="btn btn-red" onclick="openModal('brute-modal')"><span>🔓 Brute Force Console</span> <span>OPEN</span></button>
        <button class="btn btn-red" onclick="openModal('ddos-modal')"><span>🔥 DDoS Cannon</span> <span>OPEN</span></button>
        
        <div class="panel-header" style="margin-top:20px;"><h2>Blue Team Controls</h2></div>
        <button class="btn btn-green" id="sim-btn" onclick="toggleSim()">
            <span>🤖 Auto-Simulation</span> <span id="sim-status">ON</span>
        </button>
        <button class="btn btn-blue" onclick="openModal('config-modal')">
            <span>⚙️ System Configuration</span> <span>EDIT</span>
        </button>
        <button class="btn btn-blue" onclick="fetchDetectedLogs()">
            <span>📜 View Detected Logs</span> <span>VIEW</span>
        </button>
        <button class="btn" onclick="flushBans()">
            <span>🧹 Flush IP Bans</span> <span>Execute</span>
        </button>
        
        <div class="panel-header" style="margin-top:20px;"><h2>Stats</h2></div>
        <div style="font-size:12px; color:var(--text-dim);">
            <p>Total Requests: <span id="stat-req" style="color:var(--text-main)">0</span></p>
            <p>Threats Blocked: <span id="stat-block" style="color:var(--danger)">0</span></p>
            <p>Banned IPs: <span id="stat-bans" style="color:var(--warn)">0</span></p>
        </div>
    </div>

    <div class="panel chart-container" id="chart-panel">
        <canvas id="trafficChart"></canvas>
    </div>

    <div class="panel logs">
        <div class="panel-header"><h2>Live Traffic Feed (Click IP to Ban)</h2></div>
        <table class="log-table">
            <thead>
                <tr>
                    <th width="80">Time</th>
                    <th width="60">Risk</th>
                    <th width="120">Source IP</th>
                    <th>Payload / Content</th>
                </tr>
            </thead>
            <tbody id="log-body"></tbody>
        </table>
    </div>

    <div class="panel alerts">
        <div class="panel-header"><h2>Threat Detection Stream</h2></div>
        <div id="alert-feed"></div>
    </div>
</div>

<div id="toast-container"></div>

<script>
    const ctx = document.getElementById('trafficChart').getContext('2d');
    const trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Total Traffic',
                    data: [],
                    borderColor: '#58a6ff',
                    backgroundColor: 'rgba(88, 166, 255, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Blocked Threats',
                    data: [],
                    borderColor: '#f85149',
                    backgroundColor: 'rgba(248, 81, 73, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { display: false },
                y: { grid: { color: '#30363d' }, ticks: { color: '#8b949e' } }
            },
            plugins: { legend: { display: true, labels: { color: '#c9d1d9' } } },
            animation: { duration: 0 }
        }
    });

    let isSimulating = true;
    // Track rendered alerts to prevent blips
    const renderedAlertIds = new Set();

    function showToast(msg, type='info') {
        const container = document.getElementById('toast-container');
        const el = document.createElement('div');
        el.className = 'toast';
        el.style.borderColor = type === 'error' ? '#f85149' : '#58a6ff';
        el.innerHTML = `<span>${msg}</span>`;
        container.appendChild(el);
        setTimeout(() => el.remove(), 3000);
    }

    function openModal(id) { document.getElementById(id).style.display = 'flex'; }
    function closeModal(id) { document.getElementById(id).style.display = 'none'; }

    function updateConfig() {
        const user = document.getElementById('conf-user').value;
        const pass = document.getElementById('conf-pass').value;
        
        fetch('/api/config_target', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: user, password: pass})
        });
        closeModal('config-modal');
        showToast('System Credentials Updated', 'info');
    }

    function flashGraph() {
        const panel = document.getElementById('chart-panel');
        panel.classList.add('chart-flash');
        setTimeout(() => panel.classList.remove('chart-flash'), 500);
    }

    function fetchDetectedLogs() {
        openModal('log-view-modal');
        document.getElementById('detected-logs-content').innerText = "Fetching logs...";
        fetch('/api/get_detected_logs')
            .then(r => r.json())
            .then(data => {
                document.getElementById('detected-logs-content').innerText = data.logs || "No threats detected yet.";
            });
    }

    function manualAttack(type) {
        let payload = {};
        payload.type = type;
        
        if (type === 'SQLi') {
            payload.data = document.getElementById('sqli-payload').value;
            closeModal('sqli-modal');
        } else if (type === 'Brute') {
            payload.username = document.getElementById('brute-user').value;
            payload.password = document.getElementById('brute-pass').value;
            // Don't close brute modal so you can click multiple times
        } else if (type === 'DDoS') {
            payload.data = document.getElementById('ddos-count').value;
            closeModal('ddos-modal');
        }

        // Trigger visual flash immediately
        flashGraph();

        fetch('/api/manual_attack', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        }).then(r => r.json()).then(data => {
             if (type === 'DDoS') {
                 showToast('DDoS Attack Executed Successfully', 'error');
             } else if (type === 'Brute') {
                 if(data.result === 'success') showToast('LOGIN SUCCESSFUL!', 'info');
                 else showToast('Login Failed (Attempt Recorded)', 'error');
             } else {
                 showToast(`Executing ${type} Attack...`, 'error');
             }
        });
    }

    function toggleSim() {
        fetch('/api/toggle_sim', {method: 'POST'})
            .then(r => r.json())
            .then(d => {
                isSimulating = d.status;
                document.getElementById('sim-status').innerText = isSimulating ? "ON" : "OFF";
                showToast(`Simulation ${isSimulating ? 'Resumed' : 'Paused'}`);
            });
    }

    function banIP(ip) {
        fetch('/api/ban_ip', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip: ip})
        });
        showToast(`IP ${ip} Banned Manually`, 'error');
    }

    function flushBans() {
        fetch('/api/flush_bans', {method: 'POST'});
        showToast('All bans flushed. Hosts unblocked.', 'info');
    }

    setInterval(() => {
        fetch('/api/data')
            .then(r => r.json())
            .then(data => {
                document.getElementById('stat-req').innerText = data.stats.total_requests;
                document.getElementById('stat-block').innerText = data.stats.blocked;
                document.getElementById('stat-bans').innerText = data.bans;

                const statusEl = document.getElementById('sys-status');
                if (data.bans > 5) {
                    statusEl.innerText = "SYSTEM CRITICAL";
                    statusEl.style.color = "#f85149";
                    statusEl.style.borderColor = "#f85149";
                    statusEl.style.background = "rgba(248, 81, 73, 0.1)";
                } else {
                    statusEl.innerText = "SYSTEM SECURE";
                    statusEl.style.color = "#3fb950";
                    statusEl.style.borderColor = "#3fb950";
                    statusEl.style.background = "rgba(63, 185, 80, 0.1)";
                }

                const history = data.history;
                trafficChart.data.labels = history.map(h => h.time);
                trafficChart.data.datasets[0].data = history.map(h => h.requests);
                trafficChart.data.datasets[1].data = history.map(h => h.blocked);
                trafficChart.update();

                // Update Logs (Simple replacement is fine for logs as they scroll fast)
                const logBody = document.getElementById('log-body');
                logBody.innerHTML = data.logs.map(l => `
                    <tr class="log-row" onclick="banIP('${l.ip}')" title="Click to Ban IP">
                        <td>${l.time}</td>
                        <td><span class="badge ${l.risk_level}">${l.risk_level}</span></td>
                        <td style="color:var(--accent)">${l.ip}</td>
                        <td style="color:var(--text-dim)">${l.method} ${l.content}</td>
                    </tr>
                `).join('');

                // Smart Update for Alerts to prevent Blinking/Resetting Scroll
                const alertFeed = document.getElementById('alert-feed');
                
                data.alerts.slice().reverse().forEach(a => {
                    if (!renderedAlertIds.has(a.id)) {
                        const div = document.createElement('div');
                        div.className = `alert-card ${a.severity} new-item`;
                        div.innerHTML = `
                            <span class="alert-time">${a.time}</span>
                            <span class="alert-type" style="color:${a.severity === 'Critical' ? '#f85149' : '#d29922'}">${a.type}</span>
                            <div>${a.message}</div>
                            <div style="font-size:10px; margin-top:4px; color:#58a6ff">${a.ip}</div>
                        `;
                        alertFeed.insertAdjacentElement('afterbegin', div); // Insert at top
                        renderedAlertIds.add(a.id);
                    }
                });
                
                // Cleanup old alerts from DOM if too many (optional, keeps DOM light)
                if (alertFeed.children.length > 50) {
                    alertFeed.removeChild(alertFeed.lastChild);
                }
            });
    }, 1000);
</script>

</body>
</html>
"""

# --- API ROUTES ---
@app.route('/')
def index(): return render_template_string(DASHBOARD_HTML)

@app.route('/api/data')
def get_data():
    chart_data = list(engine.traffic_history)
    processed_chart = []
    if len(chart_data) > 1:
        for i in range(1, len(chart_data)):
            req_diff = chart_data[i]['requests'] - chart_data[i-1]['requests']
            block_diff = chart_data[i]['blocked'] - chart_data[i-1]['blocked']
            processed_chart.append({
                "time": chart_data[i]['time'], 
                "requests": max(0, req_diff),
                "blocked": max(0, block_diff)
            })
    
    return jsonify({
        "stats": engine.stats,
        "logs": list(engine.logs),
        "alerts": list(engine.alerts),
        "history": processed_chart,
        "bans": len(engine.banned_ips),
        "status": AUTO_SIMULATION
    })

@app.route('/api/toggle_sim', methods=['POST'])
def toggle_sim():
    global AUTO_SIMULATION
    AUTO_SIMULATION = not AUTO_SIMULATION
    return jsonify({"status": AUTO_SIMULATION})

@app.route('/api/config_target', methods=['POST'])
def config_target():
    global TARGET_CREDS
    data = request.json
    TARGET_CREDS = {"username": data.get('username'), "password": data.get('password')}
    return jsonify({"status": "Updated"})

@app.route('/api/get_detected_logs')
def get_detected_logs():
    """Reads the file and filters for logs that look like attacks."""
    suspicious_logs = []
    try:
        with open(LOG_FILE, 'r') as f:
            # Read last 1000 lines to avoid huge load
            lines = f.readlines()[-1000:]
            for line in lines:
                if any(s in line for s in ["SQL Injection", "XSS", "Traversal", "LOGIN_FAILED", "DDoS"]):
                    suspicious_logs.append(line)
                # Also check against signatures roughly
                elif "UNION SELECT" in line or "OR 1=1" in line or "<script>" in line:
                    suspicious_logs.append(line)
    except:
        return jsonify({"logs": "Error reading log file."})
        
    return jsonify({"logs": "".join(reversed(suspicious_logs)) if suspicious_logs else "No threats found in log file."})

@app.route('/api/manual_attack', methods=['POST'])
def manual_attack():
    """Handles manual attack triggering from the new console."""
    data = request.json
    attack_type = data.get('type')
    
    # Fixed IP for manual attacker to allow brute force tracking
    ip = "172.16.66.6"
    result = "executed"
    
    if attack_type == 'SQLi':
        payload = data.get('data')
        write_log(ip, f"/login?user={payload}")
    
    elif attack_type == 'Brute':
        user = data.get('username')
        password = data.get('password')
        
        if user == TARGET_CREDS['username'] and password == TARGET_CREDS['password']:
            write_log(ip, f"POST /login user={user}", "POST", "LOGIN_SUCCESS")
            result = "success"
        else:
            write_log(ip, f"POST /login user={user} pass={password}", "POST", "LOGIN_FAILED")
            result = "failed"

    elif attack_type == 'DDoS':
        payload = data.get('data')
        try:
            count = int(payload)
        except: count = 20
        # Cap for safety in demo
        if count > 100: count = 100
        for _ in range(count):
            # Added visual tag [DDoS Flood Packet] so it appears in logs
            write_log(ip, "GET /flood HTTP/1.1", "GET", "[DDoS Flood Packet]")
            
    return jsonify({"status": "Executed", "result": result})

@app.route('/api/ban_ip', methods=['POST'])
def manual_ban():
    ip = request.json.get('ip')
    engine.ban_ip(ip, 300, "Manual Ban via Console")
    return jsonify({"status": "Banned"})

@app.route('/api/flush_bans', methods=['POST'])
def flush_bans():
    engine.banned_ips.clear()
    engine.add_alert("System", "localhost", "MANUAL_RESET: Bans Flushed", "Info")
    return jsonify({"status": "Cleared"})

if __name__ == '__main__':
    # Start Watchdog
    event_handler = LogFileHandler(LOG_FILE)
    observer = Observer()
    observer.schedule(event_handler, path='.', recursive=False)
    observer.start()

    # Start Simulation
    threading.Thread(target=simulation_loop, daemon=True).start()
    
    print("\n" + "="*50)
    print(f" [>>] LOG ANALYZER & DETECTOR ONLINE")
    print(f" [>>] Access Dashboard: http://127.0.0.1:5000")
    print("="*50 + "\n")
    
    try:
        app.run(port=5000, debug=False)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
