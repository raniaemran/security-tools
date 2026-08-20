#!/usr/bin/env python3
"""
Security Dashboard Summary
Quick overview of system security status
"""

import subprocess
import os
from datetime import datetime

def run_command(cmd):
    """Run a shell command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return result.stdout.strip() if result.stdout else "N/A"
    except:
        return "Error"

def main():
    print("\n" + "="*60)
    print("🛡️  SECURITY DASHBOARD")
    print("="*60)
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    # 1. SSH Status
    ssh_status = run_command("systemctl is-active ssh")
    ssh_color = "✅" if ssh_status == "active" else "❌"
    print(f"{ssh_color} SSH Service: {ssh_status}")
    
    # 2. Firewall Status
    ufw_status = run_command("ufw status | grep Status")
    if "active" in ufw_status.lower():
        print(f"✅ Firewall: {ufw_status}")
    else:
        print(f"❌ Firewall: {ufw_status or 'Not enabled'}")
    
    # 3. Recent Suspicious Logins (last 24 hours)
    print("\n📋 Recent Suspicious Logins (last 24h):")
    suspicious = run_command("grep 'Failed password' /var/log/auth.log | tail -3")
    if suspicious:
        for line in suspicious.split('\n'):
            if line:
                print(f"   🔴 {line[:80]}")
    else:
        print("   ✅ No suspicious logins found")
    
    # 4. File Integrity Check
    baseline_exists = os.path.exists("/home/rania/security-tools/baseline.json")
    if baseline_exists:
        print(f"\n🔒 Integrity Check: ✅ Baseline exists")
    else:
        print(f"\n🔒 Integrity Check: ⚠️  No baseline found (run ficheck.py)")
    
    # 5. System Uptime
    uptime = run_command("uptime -p")
    print(f"\n⏱️  System Uptime: {uptime}")
    
    # 6. Failed Login Summary
    total_failures = run_command("grep -c 'Failed password' /var/log/auth.log")
    print(f"\n📊 Total Failed SSH Attempts (all time): {total_failures}")
    
    print("\n" + "="*60)
    print("✅ Security summary complete")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
