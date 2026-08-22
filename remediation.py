#!/usr/bin/env python3
"""
Automated Threat Remediation
Blocks IPs that exceed failure thresholds using iptables
"""

import subprocess
import re
from collections import Counter
import os
from datetime import datetime

# ===== CONFIGURATION =====
THRESHOLD = 5
BLOCKLIST_FILE = "blocked_ips.txt"
LOG_FILE = "/var/log/auth.log"
# =========================

def get_failed_ips(log_file=LOG_FILE):
    """Extract IPs with failed SSH attempts"""
    pattern = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
    ips = []
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    ips.append(match.group(1))
    except FileNotFoundError:
        print(f"❌ Log file {log_file} not found!")
        return Counter()
    except PermissionError:
        print("❌ Permission denied! Run with sudo.")
        return Counter()
    
    return Counter(ips)

def load_blocked_ips():
    """Load previously blocked IPs"""
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, 'r') as f:
            return set(f.read().strip().split('\n') if f.read() else [])
    return set()

def save_blocked_ip(ip):
    """Save blocked IP to file"""
    with open(BLOCKLIST_FILE, 'a') as f:
        f.write(f"{ip}\n")

def block_ip(ip):
    """Block IP using iptables"""
    # Check if already blocked
    result = subprocess.run(
        ['sudo', 'iptables', '-L', 'INPUT', '-n'],
        capture_output=True, text=True
    )
    if f"DROP       {ip}" in result.stdout:
        print(f"⏭️  {ip} already blocked")
        return True
    
    try:
        subprocess.run(
            ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
            check=True,
            capture_output=True
        )
        save_blocked_ip(ip)
        print(f"✅ Blocked {ip} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to block {ip}: {e.stderr.decode()}")
        return False

def unblock_ip(ip):
    """Remove IP from iptables"""
    try:
        subprocess.run(
            ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
            check=True,
            capture_output=True
        )
        print(f"✅ Unblocked {ip}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to unblock {ip}: {e.stderr.decode()}")
        return False

def list_blocked():
    """List all blocked IPs"""
    blocked = load_blocked_ips()
    if blocked:
        print("\n📋 Blocked IPs:")
        for ip in sorted(blocked):
            print(f"  • {ip}")
        print(f"\nTotal: {len(blocked)} IPs")
    else:
        print("✅ No IPs are currently blocked")
    return blocked

def show_iptables_rules():
    """Show current iptables rules"""
    result = subprocess.run(
        ['sudo', 'iptables', '-L', 'INPUT', '-n', '--line-numbers'],
        capture_output=True, text=True
    )
    print("\n📋 Current iptables rules:")
    print(result.stdout)

def main():
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--list":
            list_blocked()
            return
        elif sys.argv[1] == "--rules":
            show_iptables_rules()
            return
        elif sys.argv[1] == "--unblock" and len(sys.argv) > 2:
            unblock_ip(sys.argv[2])
            return
        elif sys.argv[1] == "--help":
            print("""
Usage: sudo python3 remediation.py [OPTIONS]

Options:
  --list          List all blocked IPs
  --rules         Show iptables rules
  --unblock IP    Unblock an IP address
  --help          Show this help message

Without options, scans logs and blocks suspicious IPs.
            """)
            return
    
    print("🛡️  Automated Threat Remediation")
    print("=" * 40)
    
    counter = get_failed_ips()
    blocked = load_blocked_ips()
    
    suspicious = {}
    for ip, count in counter.items():
        if count >= THRESHOLD and ip not in blocked and ip != "127.0.0.1":
            suspicious[ip] = count
    
    if suspicious:
        print(f"\n⚠️  Found {len(suspicious)} suspicious IPs:")
        for ip, count in sorted(suspicious.items(), key=lambda x: x[1], reverse=True):
            print(f"  • {ip} - {count} attempts")
            block_ip(ip)
    else:
        print("\n✅ No new suspicious IPs found")
    
    print(f"\n📊 Summary:")
    print(f"  • Total failed attempts: {sum(counter.values())}")
    print(f"  • Unique IPs: {len(counter)}")
    print(f"  • Blocked IPs: {len(blocked)}")
    print(f"  • Newly blocked: {len(suspicious)}")

if __name__ == "__main__":
    main()
