import csv
import random
import time
from datetime import datetime
from faker import Faker
from flask import Flask, render_template_string, request, Response, jsonify
import socket
import os
import threading
import json

# Initialize Flask app and Faker
app = Flask(__name__)
fake = Faker()
HOSTNAME = socket.gethostname()
# These are now defaults that can be overridden by the form
DEFAULT_VENDOR = "Gambit"
LOG_DIR = "logs"

# Global state to manage the generation session
session_state = {
    'thread': None,
    'stop_event': threading.Event(),
    'pause_event': threading.Event(),
    'logs_queue': [],
    'is_running': False,
    'is_paused': False,
    'start_time': None
}
session_lock = threading.Lock()

# Define a list of departments for the user base
DEPARTMENTS = [
    "Engineering", "Marketing", "Sales", "Human Resources",
    "Finance", "IT Support", "Customer Service", "Product Management"
]

# Define Known Bad IPs and URLs for story generation
KNOWN_BAD_IPS = ["203.0.113.5", "198.51.100.12", "209.165.201.25"]
KNOWN_BAD_URLS = ["http://malicious-phishing.com/login", "http://exploit-kit.ru/payload", "http://ransomware-c2.net/checkin"]

# The updated HTML template is embedded here as a string
HTML = '''
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Gambit the Syslog Generator</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
  <style>
    body {
      background-color: #1a1a1a;
      color: #e0e0e0;
      font-family: 'Poppins', sans-serif;
    }
    .container {
      max-width: 900px;
    }
    .rounded {
      border-color: #333 !important;
      background-color: #2c2c2c;
    }
    .form-label, h5 {
      color: #e0e0e0;
    }
    .form-control, .form-select, .form-check-input[type="text"] {
      background-color: #3e3e3e;
      color: #e0e0e0;
      border-color: #555;
    }
    .form-control:focus, .form-select:focus, .form-check-input[type="text"]:focus {
      background-color: #3e3e3e;
      color: #e0e0e0;
      border-color: #555;
      box-shadow: 0 0 0 0.25rem rgba(76, 175, 80, 0.25);
    }
    .form-check-label {
      color: #e0e0e0;
    }
    .btn-success {
      background-color: #4caf50;
      border-color: #4caf50;
    }
    .btn-warning {
      background-color: #ff9800;
      border-color: #ff9800;
    }
    .btn-danger {
      background-color: #f44336;
      border-color: #f44336;
    }
    .btn-info {
        background-color: #03a9f4;
        border-color: #03a9f4;
    }
    #log_display {
      height: 400px;
      overflow-y: scroll;
      background-color: #121212;
      border: 1px solid #444;
      padding: 10px;
      font-family: monospace;
      white-space: pre-wrap;
      border-radius: 0.25rem;
    }
    .log-line {
      border-bottom: 1px dashed #333;
      padding-bottom: 5px;
      margin-bottom: 5px;
    }
    .alert-info {
        background-color: #2e2e2e;
        color: #e0e0e0;
        border-color: #444;
    }
    .alert-success {
        background-color: #2e2e2e;
        color: #4caf50;
        border-color: #444;
    }
    .alert-danger {
        background-color: #2e2e2e;
        color: #f44336;
        border-color: #444;
    }
    .alert-warning {
        background-color: #2e2e2e;
        color: #ff9800;
        border-color: #444;
    }
    .story-controls, .random-controls { display: none; }
    h5[data-bs-toggle="collapse"] {
        cursor: pointer;
    }
  </style>
</head>
<body class="p-4">
  <div class="container text-center">
    <h1>Gambit</h1>
    <p class="fs-5">The Syslog Generator</p>
    <br>
  </div>
  <div class="container">
    <form id="generator-form">
      <div class="row">
        <div class="col-md-6">
          <div class="mb-4 p-3 border rounded">
            <h5 class="mb-3">Log Destination & Format</h5>
            <div class="mb-3">
              <label for="dest_ip" class="form-label">Syslog receiver IP</label>
              <input type="text" class="form-control" id="dest_ip" name="dest_ip" required placeholder="127.0.0.1" value="">
              <small class="form-text text-muted">Enter Syslog Receiver IP</small>
            </div>
            <div class="row" id="log-format-sources-row">
              <div class="col-md-6">
                <div class="mb-3">
                  <label for="log_format" class="form-label">Log Format</label>
                  <select class="form-select" id="log_format" name="log_format" required>
                    <option value="" disabled selected>Select a format</option>
                    <option value="cef">CEF</option>
                    <option value="leef">LEEF</option>
                  </select>
                </div>
              </div>
              <div class="col-md-6">
                <div class="mb-3">
                  <label class="form-label">Log Sources</label><br>
                  <div class="form-check form-check-inline">
                    <input class="form-check-input" type="checkbox" name="sources" id="src_http" value="http">
                    <label class="form-check-label" for="src_http">Http</label>
                  </div>
                  <div class="form-check form-check-inline">
                    <input class="form-check-input" type="checkbox" name="sources" id="src_ftp" value="ftp">
                    <label class="form-check-label" for="src_ftp">Ftp</label>
                  </div>
                  <div class="form-check form-check-inline">
                    <input class="form-check-input" type="checkbox" name="sources" id="src_router" value="router">
                    <label class="form-check-label" for="src_router">Router</label>
                  </div>
                  <div class="form-check form-check-inline">
                    <input class="form-check-input" type="checkbox" name="sources" id="src_switch" value="switch">
                    <label class="form-check-label" for="src_switch">Switch</label>
                  </div>
                  <div class="form-check form-check-inline">
                    <input class="form-check-input" type="checkbox" name="sources" id="src_firewall" value="firewall">
                    <label class="form-check-label" for="src_firewall">Firewall</label>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div class="col-md-6">
          <div class="mb-4 p-3 border rounded">
            <h5 class="mb-3">Sending Options</h5>
            <div class="mb-3">
              <div class="form-check form-check-inline">
                <input class="form-check-input" type="radio" name="send_mode" id="mode_random" value="random" checked>
                <label class="form-check-label" for="mode_random">Randomization</label>
              </div>
              <div class="form-check form-check-inline">
                <input class="form-check-input" type="radio" name="send_mode" id="mode_story" value="story">
                <label class="form-check-label" for="mode_story">Story</label>
              </div>
            </div>
            <div class="random-controls">
                <div class="mb-3" id="random-settings">
                    <label for="duration_minutes" class="form-label">Session Duration (minutes)</label>
                    <input type="number" class="form-control" id="duration_minutes" name="duration_minutes" required value="">
                </div>
                <div class="mb-3">
                    <label for="messages_per_second" class="form-label">Messages per Second</label>
                    <input type="number" class="form-control" id="messages_per_second" name="messages_per_second" required value="">
                </div>
            </div>
            <div class="story-controls">
                <div class="mb-3">
                    <label for="story_type" class="form-label">Select a Story</label>
                    <select class="form-select" id="story_type" name="story_type">
                        <option value="rogue_insider_story">Rogue Insider Story</option>
                        <option value="web_server_breach_story">Web Server Breach Story</option>
                        <option value="brute_force_data_theft_story">Brute-Force & Data Theft Story</option>
                    </select>
                </div>
                <div class="form-check mb-3">
                    <input class="form-check-input" type="checkbox" id="add_noise" name="add_noise" checked>
                    <label class="form-check-label" for="add_noise">Add Noise (up to 100 logs total)</label>
                </div>
            </div>
            <div class="d-flex gap-2 mb-3">
                <button type="button" class="btn btn-success" id="start-btn">Start</button>
                <button type="button" class="btn btn-warning" id="pause-btn">Pause</button>
                <button type="button" class="btn btn-danger" id="stop-btn">Stop</button>
            </div>
            <div class="form-check mb-3">
              <input class="form-check-input" type="checkbox" id="save_file" name="save_file">
              <label class="form-check-label" for="save_file">Save generated logs to CSV file</label>
            </div>
          </div>
        </div>
      </div>
      <div class="row">
        <div class="col-md-12">
          <div class="mb-4 p-3 border rounded">
            <h5 class="mb-3">
              <a data-bs-toggle="collapse" href="#customize-collapse" role="button" aria-expanded="false" aria-controls="customize-collapse" style="text-decoration: none; color: inherit;">
                Customize Logs
                <span class="ms-2">
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-chevron-down" viewBox="0 0 16 16">
                      <path fill-rule="evenodd" d="M1.646 4.646a.5.5 0 0 1 .708 0L8 10.293l5.646-5.647a.5.5 0 0 1 .708.708l-6 6a.5.5 0 0 1-.708 0l-6-6a.5.5 0 0 1 0-.708z"/>
                  </svg>
                </span>
              </a>
            </h5>
            <div class="collapse" id="customize-collapse">
                <div class="row">
                    <div class="col-md-6">
                        <div class="mb-3">
                          <label for="vendor" class="form-label">Vendor</label>
                          <input type="text" class="form-control" id="vendor" name="vendor" value="Gambit">
                          <small class="form-text text-muted">Gambit (default)</small>
                        </div>
                        <div class="mb-3">
                          <label for="product_name" class="form-label">Product Name</label>
                          <input type="text" class="form-control" id="product_name" name="product_name" value="">
                          <small class="form-text text-muted">Auto-generated by log source (e.g., GambitHTTP)</small>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label for="custom_username" class="form-label">Custom Username</label>
                            <input type="text" class="form-control" id="custom_username" name="custom_username" value="">
                            <small class="form-text text-muted">Override the random user for randomization mode.</small>
                        </div>
                        <div class="mb-3">
                            <label for="custom_department" class="form-label">Custom Department</label>
                            <input type="text" class="form-control" id="custom_department" name="custom_department" value="">
                            <small class="form-text text-muted">Override the random department.</small>
                        </div>
                    </div>
                </div>
            </div>
          </div>
        </div>
      </div>
    </form>
    <div id="status-alert" class="alert mt-3 d-none"></div>
    <div class="mt-4">
        <div class="d-flex justify-content-between align-items-center mb-2">
            <h3>Live Log Display</h3>
            <button type="button" class="btn btn-info btn-sm" id="clear-btn">Clear Logs</button>
        </div>
        <div id="log_display"></div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    const form = document.getElementById('generator-form');
    const startBtn = document.getElementById('start-btn');
    const pauseBtn = document.getElementById('pause-btn');
    const stopBtn = document.getElementById('stop-btn');
    const clearBtn = document.getElementById('clear-btn');
    const statusAlert = document.getElementById('status-alert');
    const logDisplay = document.getElementById('log_display');
    const storyModeRadio = document.getElementById('mode_story');
    const randomModeRadio = document.getElementById('mode_random');
    const storyControls = document.querySelector('.story-controls');
    const randomControls = document.querySelector('.random-controls');
    const logFormatSelect = document.getElementById('log_format');
    const logFormatSourcesRow = document.getElementById('log-format-sources-row');

    let eventSource = null;

    function setButtonsState(running, paused) {
      startBtn.disabled = running;
      pauseBtn.disabled = !running;
      stopBtn.disabled = !running;
      pauseBtn.textContent = paused ? 'Resume' : 'Pause';
    }

    function showStatus(message, type = 'info') {
      statusAlert.textContent = message;
      statusAlert.className = `alert alert-${type} mt-3`;
      statusAlert.classList.remove('d-none');
    }

    function startStreaming(stream_url) {
      if (eventSource) {
        eventSource.close();
      }
      logDisplay.innerHTML = '';
      eventSource = new EventSource(stream_url);
      setupEventSource();
    }

    function setupEventSource() {
        eventSource.onmessage = function(event) {
          try {
            const data = JSON.parse(event.data);
            if (data.status) {
              showStatus(data.status, data.type);
              setButtonsState(data.is_running, data.is_paused);
              if (data.status.includes("completed") || data.status.includes("stopped")) {
                  if(eventSource) eventSource.close();
              }
            } else if (data.log) {
              const logElement = document.createElement('div');
              logElement.className = 'log-line';
              logElement.textContent = data.log;
              logDisplay.appendChild(logElement);
              logDisplay.scrollTop = logDisplay.scrollHeight;
            }
          } catch (e) {
            console.error("Failed to parse JSON:", event.data, e);
          }
        };
        eventSource.onerror = function(err) {
          console.error("EventSource failed:", err);
          eventSource.close();
          showStatus("Event stream failed. Check console for details.", 'danger');
        };
    }

    function updateUIMode(sendMode) {
      if (sendMode === 'story') {
        storyControls.style.display = 'block';
        randomControls.style.display = 'none';
        logFormatSourcesRow.style.display = 'none';
      } else {
        storyControls.style.display = 'none';
        randomControls.style.display = 'block';
        logFormatSourcesRow.style.display = 'flex'; // Or 'block' depending on layout
      }
    }
    
    randomModeRadio.addEventListener('change', (e) => updateUIMode(e.target.value));
    storyModeRadio.addEventListener('change', (e) => updateUIMode(e.target.value));
    
    startBtn.addEventListener('click', () => {
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());
        data.sources = formData.getAll('sources');
        
        if (data.send_mode === 'random' && data.sources.length === 0) {
            showStatus('Please select at least one log source for Randomization mode.', 'danger');
            return;
        }
        
        if (data.send_mode !== 'story' && !logFormatSelect.value) {
            showStatus('Please select a log format.', 'danger');
            return;
        }

        data.dest_port = 514; // Default port
        
        fetch('/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        }).then(response => response.json()).then(result => {
            if (result.success) {
                showStatus(result.message, 'success');
                setButtonsState(true, false);
                startStreaming('/stream');
            } else {
                showStatus(result.message, 'danger');
            }
        });
    });

    pauseBtn.addEventListener('click', () => {
        fetch('/pause', { method: 'POST' }).then(response => response.json()).then(result => {
            showStatus(result.message, 'warning');
            setButtonsState(result.is_running, result.is_paused);
        });
    });

    stopBtn.addEventListener('click', () => {
        fetch('/stop', { method: 'POST' }).then(response => response.json()).then(result => {
            showStatus(result.message, 'danger');
            setButtonsState(false, false);
            if (eventSource) {
                eventSource.close();
                eventSource = null;
            }
        });
    });

    clearBtn.addEventListener('click', () => {
        logDisplay.innerHTML = '';
        showStatus('Log display cleared.', 'info');
    });

    // Initial state check and UI update
    fetch('/status').then(response => response.json()).then(status => {
      setButtonsState(status.is_running, status.is_paused);
      if (status.is_running) {
        showStatus(status.message, 'info');
        startStreaming('/stream');
      }
      updateUIMode(form.elements.send_mode.value);
    });

  </script>
</body>
</html>
'''

# --- BACKEND LOGIC ---
SOURCES = ["http", "ftp", "router", "switch", "firewall"]

def format_log_line(vendor, product, severity, event_id, message_dict, fmt='cef'):
    """Formats a log message into a CEF or LEEF string."""
    now = datetime.now()
    
    # Common fields for CSV
    log_data = {
        'timestamp': now.isoformat(),
        'vendor': vendor,
        'product': product,
        'severity': severity,
        'event_id': event_id,
        'name': message_dict.get('name', 'N/A'),
        'username': message_dict.get('username', 'N/A'),
        'department': message_dict.get('department', 'N/A'),
        'src_ip': message_dict.get('src_ip', 'N/A'),
        'dst_ip': message_dict.get('dst_ip', 'N/A'),
        'request': message_dict.get('request', 'N/A'),
        'status': message_dict.get('status', 'N/A'),
        'action': message_dict.get('action', 'N/A'),
        'message': message_dict.get('message', 'N/A'),
        'filename': message_dict.get('filename', 'N/A'),
    }

    if fmt == 'cef':
        header = f'{now.strftime("%b %d %H:%M:%S")} {HOSTNAME} CEF:0|{vendor}|{product}|1.0|{event_id}|{message_dict["name"]}|{severity}|'
        
        custom_fields = []
        if message_dict.get('username'): custom_fields.append(f'suser={message_dict["username"]}')
        if message_dict.get('department'): custom_fields.append(f'dept={message_dict["department"]}')
        if message_dict.get('src_ip'): custom_fields.append(f'src={message_dict["src_ip"]}')
        if message_dict.get('dst_ip'): custom_fields.append(f'dst={message_dict["dst_ip"]}')
        if message_dict.get('request'): custom_fields.append(f'request={message_dict["request"]}')
        if message_dict.get('status'): custom_fields.append(f'outcome={message_dict["status"]}')
        if message_dict.get('action'): custom_fields.append(f'act={message_dict["action"]}')
        if message_dict.get('message'): custom_fields.append(f'msg={message_dict["message"]}')
        if message_dict.get('filename'): custom_fields.append(f'fname={message_dict["filename"]}')
        
        log_line = header + " ".join(custom_fields)
    elif fmt == 'leef':
        header = f'LEEF:1.0|{vendor}|{product}|1.0|{event_id}|'
        
        custom_fields = []
        if message_dict.get('username'): custom_fields.append(f'usrName={message_dict["username"]}')
        if message_dict.get('department'): custom_fields.append(f'dept={message_dict["department"]}')
        if message_dict.get('src_ip'): custom_fields.append(f'src={message_dict["src_ip"]}')
        if message_dict.get('dst_ip'): custom_fields.append(f'dst={message_dict["dst_ip"]}')
        if message_dict.get('request'): custom_fields.append(f'request={message_dict["request"]}')
        if message_dict.get('status'): custom_fields.append(f'outcome={message_dict["status"]}')
        if message_dict.get('action'): custom_fields.append(f'act={message_dict["action"]}')
        if message_dict.get('message'): custom_fields.append(f'msg={message_dict["message"]}')
        if message_dict.get('filename'): custom_fields.append(f'fname={message_dict["filename"]}')
        
        log_line = header + "\t".join(custom_fields)

    log_data['log_line'] = log_line
    return log_data

def gen_user_info(custom_username=None, custom_department=None):
    if custom_username:
        return {'username': custom_username, 'department': custom_department if custom_department else "N/A"}
    return {'username': fake.user_name(), 'department': random.choice(DEPARTMENTS)}

def gen_http(custom_username=None, custom_department=None, user_info=None, path=None, status=None, is_bad=False, src_ip=None, fmt='cef', vendor_name=DEFAULT_VENDOR, product_name=None):
    user = user_info if user_info else gen_user_info(custom_username, custom_department)
    src_ip = src_ip if src_ip else fake.ipv4_public()
    dst_ip = "10.1.2.30"
    
    if is_bad:
        path = KNOWN_BAD_URLS[0]
        dst_ip = KNOWN_BAD_IPS[0]
        message = "User visited known malicious URL"
        status = 200
        severity = 9
    else:
        path = path if path else random.choice(["/index.html", "/images/logo.png", "/about-us", "/contact", "/api/data"])
        status = status if status else random.choice([200, 404, 500])
        message = "User is browsing internal web server" if status == 200 else "Suspicious request"
        severity = 3 if status == 200 else 6

    message_dict = {
        'name': 'Web Activity', 'username': user['username'], 'department': user['department'],
        'src_ip': src_ip, 'dst_ip': dst_ip, 'request': f'GET {path}', 'status': status, 'message': message
    }
    return format_log_line(vendor_name, product_name or "HTTP", severity, 100, message_dict, fmt)

def gen_ftp(custom_username=None, custom_department=None, user_info=None, action=None, filename=None, is_exfil=False, src_ip=None, fmt='cef', vendor_name=DEFAULT_VENDOR, product_name=None, status='success'):
    user = user_info if user_info else gen_user_info(custom_username, custom_department)
    src_ip = src_ip if src_ip else fake.ipv4_private()
    action = action if action else random.choice(["DOWNLOAD", "UPLOAD", "LIST", "LOGIN"])
    filename = filename if filename else random.choice(["document.pdf", "image.jpg", "report.xlsx"])
    
    message = "File exfiltration detected" if is_exfil else "FTP transfer completed"
    severity = 9 if is_exfil else 3
    if status == 'fail':
        message = "FTP login failed"
        severity = 5
    
    message_dict = {
        'name': 'FTP Transfer', 'username': user['username'], 'department': user['department'],
        'src_ip': src_ip, 'action': action, 'filename': filename, 'message': message
    }
    return format_log_line(vendor_name, product_name or "FTP", severity, 200, message_dict, fmt)

def gen_event_log(custom_username=None, custom_department=None, user_info=None, event_type=None, message=None, severity=None, src_ip=None, fmt='cef', vendor_name=DEFAULT_VENDOR, product_name=None):
    user = user_info if user_info else gen_user_info(custom_username, custom_department)
    src_ip = src_ip if src_ip else fake.ipv4_private()
    event_type = event_type if event_type else "USER_EVENT"
    message = message if message else 'System event.'
    severity = severity if severity else 4

    message_dict = {
        'name': 'System Event', 'username': user['username'], 'department': user['department'],
        'event_type': event_type, 'message': message, 'src_ip': src_ip
    }
    return format_log_line(vendor_name, product_name or "System", severity, 300, message_dict, fmt)

def gen_firewall(custom_username=None, custom_department=None, user_info=None, src_ip=None, dst_ip=None, action=None, is_blocked=False, fmt='cef', vendor_name=DEFAULT_VENDOR, product_name=None):
    src_ip = src_ip if src_ip else fake.ipv4_public()
    dst_ip = dst_ip if dst_ip else fake.ipv4_public()
    action = action if action else random.choice(["ALLOWED", "DENIED", "DROPPED"])
    
    message = "Connection to known bad IP blocked." if is_blocked else "Firewall connection log."
    severity = 9 if is_blocked else 2
    
    message_dict = {
        'name': 'Firewall Log', 'src_ip': src_ip, 'dst_ip': dst_ip, 'action': action, 'message': message
    }
    return format_log_line(vendor_name, product_name or "Firewall", severity, 400, message_dict, fmt)

def gen_router(custom_username=None, custom_department=None, user_info=None, message=None, src_ip=None, fmt='cef', vendor_name=DEFAULT_VENDOR, product_name=None):
    user = user_info if user_info else gen_user_info(custom_username, custom_department)
    src_ip = src_ip if src_ip else fake.ipv4_private()
    message = message if message else "%LINK-3-UPDOWN: Interface FastEthernet0/1, changed state to up"
    severity = 5
    
    message_dict = {
        'name': 'Router Log', 'username': user['username'], 'message': message, 'src_ip': src_ip
    }
    return format_log_line(vendor_name, product_name or "Router", severity, 500, message_dict, fmt)

def gen_switch(state='up', fmt='cef', vendor_name=DEFAULT_VENDOR, product_name=None):
    """Generates a realistic switch log."""
    message = f"%SPANTREE-5-EXTENDED_SYSID: Extended SysId enabled for type vlan. Port Fa0/1 changed state to {state}."
    severity = 4 if state == 'up' else 6
    message_dict = {'name': 'Switch Port Status', 'message': message}
    return format_log_line(vendor_name, product_name or "Switch", severity, 600, message_dict, fmt)

def gen_noise_log(fmt, sources, vendor_name, product_name):
    """Generates a random log from any source for noise."""
    svc = random.choice(sources)
    if svc == 'http': return gen_http(fmt=fmt, vendor_name=vendor_name, product_name=product_name)
    if svc == 'ftp': return gen_ftp(fmt=fmt, vendor_name=vendor_name, product_name=product_name)
    if svc == 'router': return gen_router(fmt=fmt, vendor_name=vendor_name, product_name=product_name)
    if svc == 'switch': return gen_switch(fmt=fmt, vendor_name=vendor_name, product_name=product_name)
    if svc == 'firewall': return gen_firewall(fmt=fmt, vendor_name=vendor_name, product_name=product_name)
    return gen_event_log(fmt=fmt, vendor_name=vendor_name, product_name=product_name) # Fallback

# --- STORY GENERATORS ---
def rogue_insider_story(fmt, vendor_name, product_name):
    insider = {'username': 'insider_joe', 'department': 'Finance'}
    story_logs = []
    # 5 Router Logs: Show a user making unauthorized configuration changes.
    for i in range(5):
        story_logs.append(gen_router(user_info=insider, message=f"%SYS-5-CONFIG_I: Configured from console by {insider['username']} on vty{i}", fmt=fmt, vendor_name=vendor_name, product_name=product_name))
    # 2 Switch Logs: A port goes down and then up, suggesting a rogue device was connected.
    story_logs.append(gen_switch(state='down', fmt=fmt, vendor_name=vendor_name, product_name=product_name))
    story_logs.append(gen_switch(state='up', fmt=fmt, vendor_name=vendor_name, product_name=product_name))
    # 5 Firewall Logs: A known malicious outbound connection indicates data is leaving the network.
    for _ in range(5):
        story_logs.append(gen_firewall(src_ip="192.168.1.101", dst_ip=random.choice(KNOWN_BAD_IPS), is_blocked=True, fmt=fmt, vendor_name=vendor_name, product_name=product_name))
    # 5 FTP Logs: A RETR action confirms files were downloaded from a server.
    for _ in range(5):
        story_logs.append(gen_ftp(user_info=insider, action="RETR", filename=f"confidential_{random.randint(1,100)}.docx", is_exfil=True, fmt=fmt, vendor_name=vendor_name, product_name=product_name))
    return story_logs

def web_server_breach_story(fmt, vendor_name, product_name):
    attacker_ip = fake.ipv4_public()
    web_server_ip = "10.1.2.30"
    internal_server_ip = "10.1.2.55"
    story_logs = []
    # HTTP Logs: Multiple 404 errors are logged during the reconnaissance phase
    for path in ["/admin", "/backup", "/config.php.bak"]:
        story_logs.append(gen_http(src_ip=attacker_ip, path=path, status=404, fmt=fmt, vendor_name=vendor_name, product_name=product_name))
    # A successful POST request to an unusual path, indicating a web shell has been uploaded.
    story_logs.append(gen_http(src_ip=attacker_ip, path="/uploads/shell.php", status=200, fmt=fmt, vendor_name=vendor_name, product_name=product_name))
    # Firewall Log: A new inbound connection from the web server's IP to another internal machine is logged
    story_logs.append(gen_firewall(src_ip=web_server_ip, dst_ip=internal_server_ip, action="ALLOWED", fmt=fmt, vendor_name=vendor_name, product_name=product_name))
    return story_logs

def brute_force_data_theft_story(fmt, vendor_name, product_name):
    attacker_ip = fake.ipv4_public()
    compromised_user = {'username': 'data_user', 'department': 'Sales'}
    story_logs = []
    # FTP Logs: A high volume of failed LOGIN attempts from a single IP
    for _ in range(10): # High volume
        story_logs.append(gen_ftp(user_info=compromised_user, src_ip=attacker_ip, action="LOGIN", status="fail", fmt=fmt, vendor_name=vendor_name, product_name=product_name))
    # Followed by one successful LOGIN event.
    story_logs.append(gen_ftp(user_info=compromised_user, src_ip=attacker_ip, action="LOGIN", status="success", fmt=fmt, vendor_name=vendor_name, product_name=product_name))
    # A RETR action confirms data theft.
    story_logs.append(gen_ftp(user_info=compromised_user, src_ip=attacker_ip, action="RETR", filename="customer_list.csv", is_exfil=True, fmt=fmt, vendor_name=vendor_name, product_name=product_name))
    # Firewall Log: An outbound connection to a suspicious external IP is logged
    story_logs.append(gen_firewall(src_ip=attacker_ip, dst_ip=random.choice(KNOWN_BAD_IPS), action="ALLOWED", fmt=fmt, vendor_name=vendor_name, product_name=product_name))
    # Switch Log: A switch port goes down
    story_logs.append(gen_switch(state='down', fmt=fmt, vendor_name=vendor_name, product_name=product_name))
    return story_logs

# --- SESSION MANAGEMENT ---
def generate_logs_session(config):
    """Main thread function to start either a random or story session."""
    send_mode = config.get('send_mode', 'random')
    
    # Initialize common variables
    dest_ip = config.get('dest_ip', '127.0.0.1')
    dest_port = int(config.get('dest_port', 514))
    fmt = config.get('log_format', 'cef')
    if send_mode == 'story':
        fmt = 'cef'
    save_file = config.get('save_file', False)
    vendor_name = config.get('vendor') or DEFAULT_VENDOR
    product_name = config.get('product_name')
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fhandle = None
    csv_writer = None

    if save_file:
        os.makedirs(LOG_DIR, exist_ok=True)
        filename = f"syslog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}.csv"
        file_path = os.path.join(LOG_DIR, filename)
        fhandle = open(file_path, 'w', newline='', encoding='utf-8')
        # Define comprehensive fieldnames
        fieldnames = ['timestamp', 'vendor', 'product', 'severity', 'event_id', 'name', 'username', 'department', 'src_ip', 'dst_ip', 'request', 'status', 'action', 'message', 'filename', 'log_line']
        csv_writer = csv.DictWriter(fhandle, fieldnames=fieldnames, extrasaction='ignore')
        csv_writer.writeheader()

    try:
        if send_mode == 'random':
            run_randomization_session(config, sock, csv_writer)
        elif send_mode == 'story':
            run_story_session(config, sock, csv_writer)
    except Exception as e:
        print(f"Error in generator thread: {e}")
        with session_lock:
            error_msg = json.dumps({"status": f"Error: {e}", "type": "danger"})
            session_state['logs_queue'].append(f'data: {error_msg}\n\n')
    finally:
        sock.close()
        if fhandle:
            fhandle.close()
            with session_lock:
                saved_msg = json.dumps({"status": "Logs saved to CSV file.", "type": "info"})
                session_state['logs_queue'].append(f'data: {saved_msg}\n\n')
        with session_lock:
            session_state['is_running'] = False
            session_state['is_paused'] = False
            session_state['thread'] = None
            stopped_msg = json.dumps({
                "status": "Session stopped.", "type": "danger",
                "is_running": False, "is_paused": False
            })
            session_state['logs_queue'].append(f'data: {stopped_msg}\n\n')

def run_randomization_session(config, sock, csv_writer):
    duration_minutes = int(config.get('duration_minutes', 1))
    messages_per_second = int(config.get('messages_per_second', 10))
    selected_sources = config.get('sources', [])
    custom_username = config.get('custom_username', '')
    custom_department = config.get('custom_department', '')
    vendor_name = config.get('vendor') or DEFAULT_VENDOR
    product_name = config.get('product_name')
    fmt = config.get('log_format', 'cef')
    dest_ip = config.get('dest_ip', '127.0.0.1')
    dest_port = int(config.get('dest_port', 514))

    if not selected_sources:
        with session_lock:
            error_msg = json.dumps({"status": "Error: No sources selected in Randomization mode.", "type": "danger"})
            session_state['logs_queue'].append(f'data: {error_msg}\n\n')
        return

    end_time = time.time() + (duration_minutes * 60)
    sleep_interval = 1.0 / messages_per_second

    while time.time() < end_time and not session_state['stop_event'].is_set():
        if session_state['pause_event'].is_set():
            time.sleep(0.5)
            continue

        svc = random.choice(selected_sources)
        log_dict = {}
        if svc == 'http': log_dict = gen_http(custom_username=custom_username, custom_department=custom_department, fmt=fmt, vendor_name=vendor_name, product_name=product_name)
        elif svc == 'ftp': log_dict = gen_ftp(custom_username=custom_username, custom_department=custom_department, fmt=fmt, vendor_name=vendor_name, product_name=product_name)
        elif svc == 'router': log_dict = gen_router(custom_username=custom_username, custom_department=custom_department, fmt=fmt, vendor_name=vendor_name, product_name=product_name)
        elif svc == 'switch': log_dict = gen_switch(state=random.choice(['up', 'down']), fmt=fmt, vendor_name=vendor_name, product_name=product_name)
        elif svc == 'firewall': log_dict = gen_firewall(fmt=fmt, vendor_name=vendor_name, product_name=product_name)
        
        if log_dict:
            log_line = log_dict['log_line']
            sock.sendto(log_line.encode('utf-8'), (dest_ip, dest_port))
            if csv_writer:
                csv_writer.writerow(log_dict)
            with session_lock:
                log_json = json.dumps({"log": log_line})
                session_state['logs_queue'].append(f'data: {log_json}\n\n')
        
        time.sleep(sleep_interval)

def run_story_session(config, sock, csv_writer):
    story_type = config.get('story_type', 'rogue_insider_story')
    add_noise = config.get('add_noise', False)
    vendor_name = config.get('vendor') or DEFAULT_VENDOR
    product_name = config.get('product_name')
    fmt = 'cef' # Story mode always uses CEF
    dest_ip = config.get('dest_ip', '127.0.0.1')
    dest_port = int(config.get('dest_port', 514))
    
    story_map = {
        "rogue_insider_story": rogue_insider_story,
        "web_server_breach_story": web_server_breach_story,
        "brute_force_data_theft_story": brute_force_data_theft_story
    }
    story_function = story_map.get(story_type)
    if not story_function: return

    story_logs = story_function(fmt, vendor_name, product_name)
    all_logs_to_send = story_logs
    if add_noise:
        num_noise_logs = 83
        noise_logs = [gen_noise_log(fmt, SOURCES, vendor_name, product_name) for _ in range(num_noise_logs)]
        all_logs_to_send.extend(noise_logs)
        random.shuffle(all_logs_to_send)
    
    for log_entry in all_logs_to_send:
        if session_state['stop_event'].is_set(): break
        while session_state['pause_event'].is_set():
            time.sleep(0.5)
            if session_state['stop_event'].is_set(): break
        if session_state['stop_event'].is_set(): break

        log_line = log_entry['log_line']
        sock.sendto(log_line.encode('utf-8'), (dest_ip, dest_port))
        if csv_writer:
            csv_writer.writerow(log_entry)
        with session_lock:
            log_json = json.dumps({"log": log_line})
            session_state['logs_queue'].append(f'data: {log_json}\n\n')
        time.sleep(0.5) # Fixed delay for story events

    with session_lock:
        final_msg = json.dumps({
            "status": f"Story '{story_type}' has completed. Total events: {len(all_logs_to_send)}",
            "type": "success", "is_running": False, "is_paused": False
        })
        session_state['logs_queue'].append(f'data: {final_msg}\n\n')

# --- FLASK ROUTES ---
@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/start', methods=['POST'])
def start_generation():
    with session_lock:
        if session_state['thread'] and session_state['thread'].is_alive():
            return jsonify({'success': False, 'message': 'A session is already running.'})
        
        config = request.json
        if config.get('send_mode') == 'story':
            config['log_format'] = 'cef'

        session_state['stop_event'].clear()
        session_state['pause_event'].clear()
        session_state['logs_queue'].clear()
        session_state['is_running'] = True
        session_state['is_paused'] = False
        
        session_state['thread'] = threading.Thread(target=generate_logs_session, args=(config,))
        session_state['thread'].daemon = True
        session_state['thread'].start()
        
        return jsonify({'success': True, 'message': 'Log generation started.'})

@app.route('/pause', methods=['POST'])
def pause_generation():
    with session_lock:
        if not session_state['is_running']:
            return jsonify({'success': False, 'message': 'No session is running.'})
        
        if session_state['is_paused']:
            session_state['pause_event'].clear()
            session_state['is_paused'] = False
            message = 'Session resumed.'
        else:
            session_state['pause_event'].set()
            session_state['is_paused'] = True
            message = 'Session paused.'
            
        return jsonify({
            'success': True, 'message': message,
            'is_running': session_state['is_running'],
            'is_paused': session_state['is_paused']
        })

@app.route('/stop', methods=['POST'])
def stop_generation():
    with session_lock:
        if not session_state['is_running']:
            return jsonify({'success': False, 'message': 'No session is running.'})
        
        session_state['stop_event'].set()
        session_state['pause_event'].clear() # Ensure it unblocks if paused
        
    # Wait for the thread to finish
    if session_state['thread']:
        session_state['thread'].join(timeout=2)
        
    with session_lock:
        session_state['is_running'] = False
        session_state['is_paused'] = False
        session_state['thread'] = None

    return jsonify({'success': True, 'message': 'Log generation stopped.'})

@app.route('/status')
def status():
    with session_lock:
        message = "Session is running." if session_state['is_running'] else "No active session."
        if session_state['is_running'] and session_state['is_paused']:
            message = "Session is paused."
        return jsonify({
            'is_running': session_state['is_running'],
            'is_paused': session_state['is_paused'],
            'message': message
        })

@app.route('/stream')
def stream():
    def event_stream():
        last_sent_index = 0
        while True:
            with session_lock:
                if not session_state['is_running'] and last_sent_index >= len(session_state['logs_queue']):
                    break # End stream if session is over and all logs sent
                
                queue_len = len(session_state['logs_queue'])
                if last_sent_index < queue_len:
                    for i in range(last_sent_index, queue_len):
                        yield session_state['logs_queue'][i]
                    last_sent_index = queue_len
            time.sleep(0.1)
    return Response(event_stream(), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(debug=True, threaded=True, host='0.0.0.0', port=5001)


