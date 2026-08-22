#!/usr/bin/env python3
"""
Security Web Dashboard
Visual interface for all your security tools
"""

from flask import Flask, render_template, request, jsonify
import subprocess
import json
import os
from datetime import datetime

app = Flask(__name__)

# Store recent alerts
alerts = []

def add_alert(title, message, alert_type="info"):
    """Add alert to the list"""
    alert = {
        'title': title,
        'message': message,
        'type': alert_type,  # 'danger', 'warning', 'success', 'info'
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    alerts.insert(0, alert)
    # Keep only last 100 alerts
    if len(alerts) > 100:
        alerts.pop()
    return alert

@app.route('/')
def index():
    """Dashboard home page"""
    return render_template('dashboard.html', alerts=alerts)

@app.route('/api/scan', methods=['POST'])
def run_scan():
    """Run port scanner"""
    data = request.json
    target = data.get('target', '127.0.0.1')
    ports = data.get('ports', '20-25')
    
    try:
        result = subprocess.run(
            ['sudo', 'python3', 'port_scanner.py', target, '-p', ports],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout if result.stdout else result.stderr
        add_alert(f"Scan Complete", f"Scanned {target}:{ports}", "success")
        return jsonify({'output': output, 'status': 'success'})
    except subprocess.TimeoutExpired:
        add_alert("Scan Timeout", f"Scan of {target} timed out", "warning")
        return jsonify({'output': '⚠️ Scan timed out', 'status': 'timeout'})
    except Exception as e:
        add_alert("Scan Error", str(e), "danger")
        return jsonify({'output': f'❌ Error: {e}', 'status': 'error'})

@app.route('/api/logs', methods=['POST'])
def run_log_analyzer():
    """Run log analyzer"""
    data = request.json
    threshold = data.get('threshold', 5)
    
    try:
        result = subprocess.run(
            ['sudo', 'python3', 'log_analyzer.py', '/var/log/auth.log', '-t', str(threshold)],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout if result.stdout else result.stderr
        
        # Check if suspicious activity was found
        if "ALERT" in output:
            add_alert("Suspicious Activity Detected!", "Check log analysis results", "danger")
        else:
            add_alert("Log Analysis Complete", "No suspicious activity found", "success")
        
        return jsonify({'output': output, 'status': 'success'})
    except Exception as e:
        add_alert("Log Analysis Error", str(e), "danger")
        return jsonify({'output': f'❌ Error: {e}', 'status': 'error'})

@app.route('/api/integrity', methods=['POST'])
def run_integrity():
    """Run integrity checker"""
    data = request.json
    directory = data.get('directory', '/home/rania/Documents')
    baseline = data.get('baseline', 'baseline.json')
    
    try:
        result = subprocess.run(
            ['python3', 'ficheck.py', directory, '-b', baseline],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout if result.stdout else result.stderr
        
        # Check if changes were detected
        if "ALERT" in output or "NEW" in output or "MODIFIED" in output:
            add_alert("File Changes Detected!", f"Changes found in {directory}", "warning")
        elif "No changes detected" in output:
            add_alert("Integrity Check Complete", "No file changes detected", "success")
        
        return jsonify({'output': output, 'status': 'success'})
    except Exception as e:
        add_alert("Integrity Check Error", str(e), "danger")
        return jsonify({'output': f'❌ Error: {e}', 'status': 'error'})

# ===== NEW: Auto-Remediation =====
@app.route('/api/remediate', methods=['POST'])
def run_remediation():
    """Run auto-remediation"""
    try:
        result = subprocess.run(
            ['sudo', 'python3', 'remediation.py'],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout if result.stdout else result.stderr
        add_alert("Remediation Complete", "Suspicious IPs blocked", "success")
        return jsonify({'output': output, 'status': 'success'})
    except Exception as e:
        add_alert("Remediation Error", str(e), "danger")
        return jsonify({'output': f'❌ Error: {e}', 'status': 'error'})

# ===== NEW: CVE Lookup =====
@app.route('/api/cve', methods=['POST'])
def run_cve_check():
    """Run CVE vulnerability check"""
    try:
        result = subprocess.run(
            ['python3', 'cve_lookup.py'],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout if result.stdout else result.stderr
        add_alert("CVE Check Complete", "Vulnerability check finished", "info")
        return jsonify({'output': output, 'status': 'success'})
    except Exception as e:
        add_alert("CVE Check Error", str(e), "danger")
        return jsonify({'output': f'❌ Error: {e}', 'status': 'error'})

# ===== NEW: List Blocked IPs =====
@app.route('/api/blocked')
def get_blocked():
    """Get list of blocked IPs"""
    try:
        result = subprocess.run(
            ['sudo', 'python3', 'remediation.py', '--list'],
            capture_output=True, text=True
        )
        return jsonify({'output': result.stdout})
    except Exception as e:
        return jsonify({'output': f'❌ Error: {e}'})

@app.route('/api/alerts')
def get_alerts():
    """Return recent alerts"""
    return jsonify({'alerts': alerts})

@app.route('/api/clear_alerts', methods=['POST'])
def clear_alerts():
    """Clear all alerts"""
    global alerts
    alerts = []
    return jsonify({'status': 'cleared'})

if __name__ == '__main__':
    # Create templates folder
    os.makedirs('templates', exist_ok=True)
    app.run(host='0.0.0.0', port=5001, debug=True)
