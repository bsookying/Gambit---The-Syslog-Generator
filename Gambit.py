import csv
from flask import Flask, render_template_string, request, Response, jsonify
from faker import Faker
import socket
import os
import time
from datetime import datetime
import random
import threading

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

# The updated HTML template is embedded here as a string
HTML = '''
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Gambit</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background-color: #121212;
      color: #e0e0e0;
    }
    .container {
      max-width: 900px;
    }
    .rounded {
      border-color: #444 !important;
      background-color: #1e1e1e;
    }
    .form-label, h5 {
      color: #e0e0e0;
    }
    .form-control, .form-select {
      background-color: #2e2e2e;
      color: #e0e0e0;
      border-color: #444;
    }
    .form-control:focus, .form-select:focus {
      background-color: #2e2e2e;
      color: #e0e0e0;
      border-color: #555;
      box-shadow: 0 0 0 0.25rem rgba(0, 255, 0, 0.25);
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
    #log_display {
      height: 400px;
      overflow-y: scroll;
      background-color: #1a1a1a;
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
  </style>
</head>
<body class="p-4">
  <div class="container text-center">
    <img src="https://storage.googleapis.com/gcs-p-gemini-generative-content/v5/gambit.jpg" alt="Gambit" class="img-fluid mb-4" style="max-width: 250px;">
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
              <label for="dest_ip" class="form-label">Cortex Broker IP</label>
              <input type="text" class="form-control" id="dest_ip" name="dest_ip" required placeholder="127.0.0.1" value="">
              <small class="form-text text-muted">Enter Destination Broker IP</small>
            </div>
            <div class="row">
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
          <div class="mb-4 p-3 border rounded">
            <h5 class="mb-3">Customize Logs</h5>
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
            <div class="mb-3" id="story-options-group" style="display: none;">
              <label for="story_type" class="form-label">Select a Story</label>
              <select class="form-select" id="story_type" name="story_type">
                <option value="rogue_insider">Rogue Insider</option>
                <option value="web_server_breach">Web Server Breach</option>
                <option value="brute_force_data_theft">Brute-Force & Data Theft</option>
              </select>
            </div>
            <div class="mb-3 form-check" id="noise-toggle-group" style="display: none;">
                <input class="form-check-input" type="checkbox" id="add_noise" name="add_noise" checked>
                <label class="form-check-label" for="add_noise">Add Noise</label>
            </div>
            <div id="session-controls-group">
              <h5 class="mb-3">Session & Control</h5>
              <div class="mb-3">
                <label for="duration_minutes" class="form-label">Session Duration (minutes)</label>
                <input type="number" class="form-control" id="duration_minutes" name="duration_minutes" required value="1">
              </div>
              <div class="mb-3" id="random-controls" style="display: block;">
                <label for="messages_per_second" class="form-label">Messages per Second</label>
                <input type="number" class="form-control" id="messages_per_second" name="messages_per_second" required value="10">
              </div>
              <div class="alert alert-info mt-2" id="story-note" style="display: none;">
                Note: All story and noise messages (100 total by default) will be sent at random intervals over the specified session duration.
              </div>
            </div>
            <div class="d-flex gap-2 mb-3">
              <button type="button" class="btn btn-success" id="start-btn">Start</button>
              <button type="button" class="btn btn-warning" id="pause-btn">Pause</button>
              <button type="button" class="btn btn-danger" id="stop-btn">Stop</button>
            </div>
          </div>
          <div class="form-check mb-3">
            <input class="form-check-input" type="checkbox" id="save_file" name="save_file">
            <label class="form-check-label" for="save_file">Save generated logs to CSV file</label>
          </div>
        </div>
      </div>
    </form>
    <div id="status-alert" class="alert mt-3 d-none"></div>
    <div class="mt-4">
      <h3>Live Log Display</h3>
      <div id="log_display"></div>
    </div>
  </div>

  <script>
    const form = document.getElementById('generator-form');
    const startBtn = document.getElementById('start-btn');
    const pauseBtn = document.getElementById('pause-btn');
    const stopBtn = document.getElementById('stop-btn');
    const statusAlert = document.getElementById('status-alert');
    const logDisplay = document.getElementById('log_display');
    const storyModeRadio = document.getElementById('mode_story');
    const randomModeRadio = document.getElementById('mode_random');
    const storyOptionsGroup = document.getElementById('story-options-group');
    const sessionControlsGroup = document.getElementById('session-controls-group');
    const randomControlsGroup = document.getElementById('random-controls');
    const noiseToggleGroup = document.getElementById('noise-toggle-group');
    const addNoiseCheckbox = document.getElementById('add_noise');
    const logSourcesCheckboxes = document.querySelectorAll('input[name="sources"]');
    const storyNote = document.getElementById('story-note');
    const vendorInput = document.getElementById('vendor');

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

    function startStreaming() {
      if (eventSource) {
        eventSource.close();
      }
      eventSource = new EventSource(window.location.origin + '/stream');
      eventSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        if (data.status) {
          showStatus(data.status, data.type);
          setButtonsState(data.is_running, data.is_paused);
        } else if (data.log) {
          const logElement = document.createElement('div');
          logElement.className = 'log-line';
          logElement.textContent = data.log;
          logDisplay.appendChild(logElement);
          logDisplay.scrollTop = logDisplay.scrollHeight;
        }
      };
      eventSource.onerror = function(err) {
        console.error("EventSource failed:", err);
        eventSource.close();
      };
    }

    // Function to handle UI changes based on send mode
    function updateUIMode(sendMode) {
      if (sendMode === 'story') {
        storyOptionsGroup.style.display = 'block';
        randomControlsGroup.style.display = 'none';
        noiseToggleGroup.style.display = 'block';
        storyNote.style.display = 'block';
        logSourcesCheckboxes.forEach(checkbox => {
          checkbox.disabled = true;
          checkbox.checked = false;
        });
      } else { // 'random' mode
        storyOptionsGroup.style.display = 'none';
        randomControlsGroup.style.display = 'block';
        noiseToggleGroup.style.display = 'none';
        storyNote.style.display = 'none';
        logSourcesCheckboxes.forEach(checkbox => {
          checkbox.disabled = false;
        });
      }
    }

    storyModeRadio.addEventListener('change', (e) => updateUIMode(e.target.value));
    randomModeRadio.addEventListener('change', (e) => updateUIMode(e.target.value));
    
    startBtn.addEventListener('click', () => {
      const formData = new FormData(form);
      const data = Object.fromEntries(formData.entries());
      
      const sendMode = formData.get('send_mode');
      if (sendMode === 'random') {
        data.sources = formData.getAll('sources');
        if (data.sources.length === 0) {
          showStatus('Please select at least one log source for Randomization mode.', 'danger');
          return;
        }
        data.duration_minutes = parseInt(data.duration_minutes);
        data.messages_per_second = parseInt(data.messages_per_second);
      } else if (sendMode === 'story') {
        data.story_type = formData.get('story_type');
        data.add_noise = formData.get('add_noise') === 'on';
        data.noise_count = data.add_noise ? 83 : 0;
        data.duration_minutes = parseInt(data.duration_minutes);
        data.sources = ['router', 'switch', 'firewall', 'ftp', 'http'];
      }
      
      data.save_file = formData.get('save_file') === 'on';
      data.dest_port = 514;
      
      fetch(window.location.origin + '/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      }).then(response => response.json()).then(result => {
        if (result.success) {
          showStatus(result.message, 'success');
          setButtonsState(true, false);
          startStreaming();
        } else {
          showStatus(result.message, 'danger');
        }
      });
    });

    pauseBtn.addEventListener('click', () => {
      fetch(window.location.origin + '/pause', { method: 'POST' })
        .then(response => response.json())
        .then(result => {
          showStatus(result.message, 'warning');
          setButtonsState(result.is_running, result.is_paused);
        });
    });

    stopBtn.addEventListener('click', () => {
      fetch(window.location.origin + '/stop', { method: 'POST' })
        .then(response => response.json())
        .then(result => {
          showStatus(result.message, 'danger');
          setButtonsState(false, false);
          if (eventSource) {
            eventSource.close();
            eventSource = null;
          }
        });
    });

    // Initial state check and UI update
    fetch(window.location.origin + '/status').then(response => response.json()).then(status => {
      setButtonsState(status.is_running, status.is_paused);
      if (status.is_running) {
        showStatus(status.message, 'info');
        startStreaming();
      }
      updateUIMode(form.elements.send_mode.value);
    });

  </script>
</body>
</html>
'''

SOURCES = ["http", "ftp", "router", "switch", "firewall"]

# Message generators per source
def gen_http():
    ip = fake.ipv4_private()
    method = random.choice(["GET", "POST", "PUT", "DELETE"])
    resource = fake.uri_path()
    status = random.choice([200, 301, 401, 404, 500])
    size = random.randint(100, 5000)
    return {'msg': f'"{method} {resource} HTTP/1.1" {status} {size}', 'src_ip': ip, 'dst_ip': '-'}

def gen_ftp():
    user = fake.user_name()
    ip = fake.ipv4_private()
    action = random.choice(["LOGIN", "RETR", "STOR", "QUIT"])
    return {'msg': f'{action} user={user} from={ip}', 'src_ip': ip, 'user': user}

def gen_router():
    user = fake.user_name()
    ip = fake.ipv4_private()
    return {'msg': f'%SYS-5-CONFIG_I: Configured from console by {user} on vty0 ({ip})', 'src_ip': ip, 'user': user}

def gen_switch(state):
    port = random.randint(1, 48)
    return {'msg': f'%LINK-3-UPDOWN: Interface FastEthernet{port}/1, changed state to {state}', 'port': port, 'state': state}

def gen_firewall():
    direction = random.choice(["inbound", "outbound"])
    src_ip = fake.ipv4_private()
    dst_ip = fake.ipv4_private()
    sport = random.randint(1024, 65535)
    dport = random.randint(1, 1024)
    return {'msg': f'Built {direction} UDP connection src={src_ip} dst={dst_ip} sport={sport} dport={dport}', 'src_ip': src_ip, 'dst_ip': dst_ip, 'sport': sport, 'dport': dport}

# NEW: Log generators for specific story scenarios
def gen_brute_force_log():
    ip = fake.ipv4_public()
    user = fake.user_name()
    status = random.choice([401, 403])
    return {'msg': f'Failed login attempt for user={user} from {ip}. Status Code: {status}', 'src_ip': ip, 'user': user, 'status': status}

def gen_web_breach_log():
    ip = fake.ipv4_public()
    method = random.choice(["GET", "POST"])
    status = random.choice([200, 404])
    resource = random.choice([
        '/admin/login.php',
        '/etc/passwd',
        '/var/www/html/database.sql',
        '/index.html'
    ])
    return {'msg': f'"{method} {resource} HTTP/1.1" {status}', 'src_ip': ip, 'dst_ip': '-', 'resource': resource, 'status': status}

# Formatter including vendor & product
def format_log(fmt, message_dict, svc, vendor_name=DEFAULT_VENDOR, product_name=None):
    now = datetime.now()
    # Use product_name if provided, otherwise create a default one
    product = product_name if product_name else f"{vendor_name}{svc.upper()}"
    
    log_line = ""
    sev = random.randint(0, 10)

    if fmt == 'cef':
        sip = message_dict.get('src_ip', fake.ipv4_private())
        dip = message_dict.get('dst_ip', fake.ipv4_private())
        log_line = f'CEF:0|{vendor_name}|{product}|1.0|100|Event|{sev}|src={sip} dst={dip} msg="{message_dict["msg"]}"'
    elif fmt == 'leef':
        sip = message_dict.get('src_ip', fake.ipv4_private())
        dip = message_dict.get('dst_ip', fake.ipv4_private())
        log_line = f'LEEF:2.0|{vendor_name}|{product}|1.0|100\tsev={sev}\tsrc={sip}\tdst={dip}\tmsg="{message_dict["msg"]}"'
    
    message_dict.update({
        'log_line': log_line,
        'timestamp': now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
        'vendor': vendor_name,
        'product': product,
        'severity': sev,
        'svc': svc,
    })
    return message_dict

def gen_noise_log(fmt, sources, vendor_name, product_name):
    """Generates a random log line for noise."""
    svc = random.choice(sources)
    msg_gen_func = globals().get(f'gen_{svc}', lambda: {'msg': f'Event from {svc}'})
    # FIX: Add a random state for the switch generator
    if svc == 'switch':
        msg_dict = gen_switch(random.choice(['up', 'down']))
    else:
        msg_dict = msg_gen_func()
    return format_log(fmt, msg_dict, svc, vendor_name, product_name)

# Log generation thread function
def generate_logs_session(config):
    with session_lock:
        session_state['is_running'] = True
        session_state['is_paused'] = False
        session_state['stop_event'].clear()
        session_state['pause_event'].clear()
        session_state['start_time'] = time.time()
        session_state['logs_queue'].clear()

    dest_ip = config.get('dest_ip', '127.0.0.1')
    dest_port = config.get('dest_port', 514)
    fmt = config['log_format']
    save_file = config['save_file']
    send_mode = config['send_mode']
    vendor_name = config.get('vendor') if config.get('vendor') and config.get('vendor') != 'Gambit (default)' else DEFAULT_VENDOR
    product_name = config.get('product_name')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fhandle = None
    csv_writer = None
    if save_file:
        os.makedirs(LOG_DIR, exist_ok=True)
        filename = f"syslog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}.csv"
        file_path = os.path.join(LOG_DIR, filename)
        fhandle = open(file_path, 'w', newline='')
        fieldnames = ['timestamp', 'vendor', 'product', 'severity', 'svc', 'src_ip', 'dst_ip', 'user', 'msg', 'log_line']
        csv_writer = csv.DictWriter(fhandle, fieldnames=fieldnames, extrasaction='ignore')
        csv_writer.writeheader()

    try:
        if send_mode == 'random':
            duration_minutes = int(config.get('duration_minutes', 1))
            messages_per_second = int(config.get('messages_per_second', 10))
            selected_sources = config['sources']
            if not selected_sources:
                with session_lock:
                    session_state['logs_queue'].append("Error: No sources selected in Randomization mode.")
                return

            end_time = session_state['start_time'] + (duration_minutes * 60)
            while time.time() < end_time and not session_state['stop_event'].is_set():
                if not session_state['pause_event'].is_set():
                    for _ in range(messages_per_second):
                        if session_state['stop_event'].is_set(): break
                        svc = random.choice(selected_sources)
                        
                        # FIX: Check if the selected service is 'switch' and provide a 'state' argument
                        if svc == 'switch':
                            msg_dict = gen_switch(random.choice(['up', 'down']))
                        else:
                            msg_gen_func = globals().get(f'gen_{svc}', lambda: {'msg': f'Event from {svc}'})
                            msg_dict = msg_gen_func()
                            
                        log_dict = format_log(fmt, msg_dict, svc, vendor_name, product_name)
                        log_line = log_dict['log_line']
                        
                        sock.sendto(log_line.encode(), (dest_ip, dest_port))
                        if csv_writer:
                            csv_writer.writerow(log_dict)
                        with session_lock:
                            session_state['logs_queue'].append(log_line)
                    time.sleep(1) # Wait for 1 second to control messages per second
                else:
                    session_state['pause_event'].wait(1)
        
        elif send_mode == 'story':
            story_type = config['story_type']
            duration_minutes = int(config.get('duration_minutes', 1))
            add_noise = config.get('add_noise', False)
            
            story_events = []
            
            # --- START FIX: Adding logic for missing story types ---
            if story_type == 'rogue_insider':
                story_steps = [
                    {'source': 'router', 'count': 5},
                    {'source': 'switch', 'state': 'down', 'count': 1},
                    {'source': 'switch', 'state': 'up', 'count': 1},
                    {'source': 'firewall', 'count': 5},
                    {'source': 'ftp', 'count': 5},
                ]
                for step in story_steps:
                    for _ in range(step.get('count', 1)):
                        svc = step['source']
                        if svc == 'switch':
                            msg_dict = gen_switch(step.get('state'))
                        else:
                            msg_gen_func = globals().get(f'gen_{svc}', lambda: {'msg': f'Event from {svc}'})
                            msg_dict = msg_gen_func()
                        story_events.append(format_log(fmt, msg_dict, svc, vendor_name, product_name))

            elif story_type == 'web_server_breach':
                story_steps = [
                    {'source': 'http', 'count': 10, 'log_func': lambda: gen_web_breach_log()}, # 10 failed/suspicious HTTP requests
                    {'source': 'ftp', 'count': 1, 'log_func': gen_ftp}, # Successful FTP login
                    {'source': 'http', 'count': 1, 'log_func': lambda: gen_web_breach_log()}, # Successful web request
                ]
                for step in story_steps:
                    for _ in range(step.get('count', 1)):
                        svc = step['source']
                        msg_dict = step['log_func']()
                        story_events.append(format_log(fmt, msg_dict, svc, vendor_name, product_name))

            elif story_type == 'brute_force_data_theft':
                story_steps = [
                    {'source': 'http', 'count': 20, 'log_func': gen_brute_force_log}, # 20 brute-force login attempts
                    {'source': 'http', 'count': 1, 'log_func': lambda: {'msg': '"POST /login HTTP/1.1" 200 1024', 'src_ip': fake.ipv4_public(), 'dst_ip': '-'}}, # Successful login
                    {'source': 'ftp', 'count': 1, 'log_func': lambda: {'msg': 'RETR large_database.zip from_internal_ip', 'src_ip': fake.ipv4_private()}} # Data exfiltration via FTP
                ]
                for step in story_steps:
                    for _ in range(step.get('count', 1)):
                        svc = step['source']
                        msg_dict = step['log_func']()
                        story_events.append(format_log(fmt, msg_dict, svc, vendor_name, product_name))
            # --- END FIX ---
            
            all_logs_to_send = []
            if add_noise:
                # Noise count for stories is set to 83, so the total will be ~100
                noise_logs = [gen_noise_log(fmt, SOURCES, vendor_name, product_name) for _ in range(100 - len(story_events))]
                all_logs_to_send = story_events + noise_logs
            else:
                all_logs_to_send = story_events

            random.shuffle(all_logs_to_send)
            
            total_logs = len(all_logs_to_send)
            duration_seconds = duration_minutes * 60
            sleep_time = duration_seconds / total_logs if total_logs > 0 else 0

            for log_dict in all_logs_to_send:
                if session_state['stop_event'].is_set(): break
                if not session_state['pause_event'].is_set():
                    log_line = log_dict['log_line']
                    sock.sendto(log_line.encode(), (dest_ip, dest_port))
                    if csv_writer: csv_writer.writerow(log_dict)
                    with session_lock: session_state['logs_queue'].append(log_line)
                    time.sleep(sleep_time)
                else:
                    session_state['pause_event'].wait(1)

            with session_lock:
                final_msg = f"Story '{story_type}' has completed its log sequence. Total events sent: {len(all_logs_to_send)}"
                session_state['logs_queue'].append(final_msg)
            session_state['stop_event'].set()

    except Exception as e:
        print(f"Error in generator thread: {e}")
        with session_lock:
            session_state['logs_queue'].append(f"Error: {e}")
    finally:
        sock.close()
        if fhandle:
            fhandle.close()
            with session_lock:
                session_state['logs_queue'].append(f"Logs saved to CSV file: {file_path}")
        with session_lock:
            session_state['is_running'] = False
            session_state['is_paused'] = False
            session_state['thread'] = None
            session_state['logs_queue'].append("Session stopped.")

@app.route('/', methods=['GET'])
def index():
    return render_template_string(HTML, sources=SOURCES)

@app.route('/start', methods=['POST'])
def start_session():
    with session_lock:
        if session_state['is_running']:
            return jsonify({'success': False, 'message': 'A session is already running.'})
        
        config = request.json
        if not config.get('log_format'):
              return jsonify({'success': False, 'message': 'No log format selected.'})
        
        if config.get('send_mode') == 'random':
            if not config.get('sources'):
                return jsonify({'success': False, 'message': 'No sources selected for Randomization mode.'})
        
        session_state['thread'] = threading.Thread(target=generate_logs_session, args=(config,))
        session_state['thread'].daemon = True
        session_state['thread'].start()
        
        return jsonify({'success': True, 'message': 'Log generation session started.'})

@app.route('/pause', methods=['POST'])
def pause_session():
    with session_lock:
        if not session_state['is_running']:
            return jsonify({'success': False, 'message': 'No session is running.'})
        
        if session_state['is_paused']:
            session_state['pause_event'].clear()
            session_state['is_paused'] = False
            return jsonify({'success': True, 'message': 'Session resumed.', 'is_running': True, 'is_paused': False})
        else:
            session_state['pause_event'].set()
            session_state['is_paused'] = True
            return jsonify({'success': True, 'message': 'Session paused.', 'is_running': True, 'is_paused': True})

@app.route('/stop', methods=['POST'])
def stop_session():
    with session_lock:
        if not session_state['is_running']:
            return jsonify({'success': False, 'message': 'No session is running.'})
        
        session_state['stop_event'].set()
        return jsonify({'success': True, 'message': 'Stopping session...'})

@app.route('/status', methods=['GET'])
def get_status():
    with session_lock:
        if session_state['is_running']:
            status_msg = "Session running."
            if session_state['is_paused']:
                status_msg = "Session paused."
            return jsonify({'is_running': session_state['is_running'], 'is_paused': session_state['is_paused'], 'message': status_msg})
        else:
            return jsonify({'is_running': False, 'is_paused': False, 'message': 'No session is running.'})

@app.route('/stream')
def stream_logs():
    def event_stream():
        last_index = 0
        while True:
            time.sleep(0.5)
            with session_lock:
                if session_state['logs_queue'] and session_state['logs_queue'][-1].startswith("Story") and "completed" in session_state['logs_queue'][-1]:
                    yield f'data: {{"status": "{session_state["logs_queue"][-1]}", "type": "success", "is_running": false, "is_paused": false}}\n\n'
                    session_state['logs_queue'].clear()
                    break
                if session_state['logs_queue'] and session_state['logs_queue'][-1] == "Session stopped.":
                    yield f'data: {{"status": "Session stopped.", "type": "danger", "is_running": false, "is_paused": false}}\n\n'
                    session_state['logs_queue'].clear()
                    break
                
                if session_state['logs_queue'] and session_state['logs_queue'][-1].startswith("Error:"):
                    error_msg = session_state['logs_queue'][-1]
                    yield f'data: {{"status": "{error_msg}", "type": "danger", "is_running": false, "is_paused": false}}\n\n'
                    session_state['logs_queue'].clear()
                    break

                if len(session_state['logs_queue']) > last_index:
                    for i in range(last_index, len(session_state['logs_queue'])):
                        log = session_state['logs_queue'][i]
                        log = log.replace('"', '\\"') 
                        yield f'data: {{"log": "{log}"}}\n\n'
                    last_index = len(session_state['logs_queue'])
    
    return Response(event_stream(), mimetype="text/event-stream")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)


