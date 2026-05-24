import sys
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

from flask import Flask, render_template, request, jsonify, Response
import threading
import time
import json
import queue
from backend.orchestrator import SwarmOrchestrator
from backend.core.config import MissionProfile, Config

app = Flask(__name__, static_folder="static", template_folder="static")

# Global State
orchestrator = None
log_queue = queue.Queue()
mission_active = False

def log_callback(message):
    global mission_active
    timestamp = time.strftime("%H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    log_queue.put(log_entry)
    
    # Reset mission_active when mission completes
    if "Mission Complete" in message:
        mission_active = False

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/api/start', methods=['POST'])
def start_mission():
    global orchestrator, mission_active
    
    # Check if there's actually a running mission
    if mission_active and orchestrator and orchestrator.is_running:
        return jsonify({"status": "error", "message": "Mission already in progress"}), 400
    
    # Reset state for new mission
    mission_active = False
        
    data = request.json
    target_url = data.get('target', Config.DEFAULT_TARGET_URL)
    modules = data.get('modules', [])
    headers = data.get('headers', {})
    headers_b = data.get('headers_b', {})
    
    if not modules:
        return jsonify({"status": "error", "message": "No modules selected"}), 400

    profile = MissionProfile(target_url, modules, headers=headers, headers_b=headers_b)
    orchestrator = SwarmOrchestrator(profile, log_callback=log_callback)
    
    mission_active = True
    orchestrator.start()
    
    return jsonify({"status": "success", "message": "Swarm launched"})

@app.route('/api/stop', methods=['POST'])
def stop_mission():
    global orchestrator, mission_active
    if orchestrator and mission_active:
        orchestrator.stop()
        mission_active = False
        log_callback("Mission aborted by user.")
        return jsonify({"status": "success", "message": "Swarm stopped"})
    return jsonify({"status": "error", "message": "No active mission"}), 400

@app.route('/api/status')
def get_status():
    """Get current mission status."""
    global orchestrator, mission_active
    if orchestrator:
        return jsonify({
            "active": mission_active and orchestrator.is_running,
            "findings": len(orchestrator.findings) if orchestrator else 0,
            "report_dir": orchestrator.report_dir if orchestrator else None
        })
    return jsonify({"active": False, "findings": 0, "report_dir": None})

@app.route('/api/stream')
def stream_logs():
    def generate():
        while True:
            try:
                message = log_queue.get(timeout=1.0) 
                yield f"data: {message}\n\n"
            except queue.Empty:
                yield ": keep-alive\n\n"
    
    return Response(generate(), mimetype='text/event-stream')

# ===== Source Code Scanner =====
from backend.agents.code_scanner_agent import CodeScannerAgent

code_scanner = None
code_log_queue = queue.Queue()
code_scan_active = False

def code_log_callback(message):
    global code_scan_active
    timestamp = time.strftime("%H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    code_log_queue.put(log_entry)
    if "Scan Complete" in message:
        code_scan_active = False

@app.route('/api/code-scan', methods=['POST'])
def start_code_scan():
    global code_scanner, code_scan_active
    
    if code_scan_active and code_scanner and code_scanner.is_running:
        return jsonify({"status": "error", "message": "Code scan already in progress"}), 400
    
    data = request.json
    repo_url = data.get('repo_url', '').strip()
    
    if not repo_url:
        return jsonify({"status": "error", "message": "Repository URL is required"}), 400
    
    code_scanner = CodeScannerAgent(log_callback=code_log_callback)
    code_scan_active = True
    
    def run_scan():
        code_scanner.scan_repo(repo_url)
    
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    
    return jsonify({"status": "success", "message": "Code scan started"})

@app.route('/api/code-stop', methods=['POST'])
def stop_code_scan():
    global code_scanner, code_scan_active
    if code_scanner and code_scan_active:
        code_scanner.stop()
        code_scan_active = False
        code_log_callback("Code scan aborted by user.")
        return jsonify({"status": "success", "message": "Code scan stopped"})
    return jsonify({"status": "error", "message": "No active code scan"}), 400

@app.route('/api/code-stream')
def stream_code_logs():
    def generate():
        while True:
            try:
                message = code_log_queue.get(timeout=1.0)
                yield f"data: {message}\n\n"
            except queue.Empty:
                yield ": keep-alive\n\n"
    
    return Response(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(debug=True, port=5001, threaded=True)
