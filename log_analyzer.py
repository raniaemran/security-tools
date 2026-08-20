#!/usr/bin/env python3
"""
Automated Log Analysis Script
Detects suspicious activities in system logs
Sends email and Telegram alerts
"""

import re
import sys
import argparse
from collections import Counter
from datetime import datetime

# Import alert modules
try:
    from email_alerts import send_alert
except ImportError:
    def send_alert(subject, body):
        print(f"📧 [ALERT] {subject}")
        return False

try:
    from telegram_alerts import send_telegram
except ImportError:
    def send_telegram(msg):
        print(f"📲 [Telegram] {msg}")

def parse_auth_log(log_file):
    """Parse auth.log for failed SSH attempts"""
    ip_pattern = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
    user_pattern = re.compile(r"Failed password for (?:invalid user )?([a-zA-Z0-9_]+) from")
    failed_ips = []
    failed_users = []
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                ip_match = ip_pattern.search(line)
                if ip_match:
                    failed_ips.append(ip_match.group(1))
                    user_match = user_pattern.search(line)
                    if user_match:
                        failed_users.append(user_match.group(1))
    except FileNotFoundError:
        print(f"❌ Log file {log_file} not found!")
        sys.exit(1)
    except PermissionError:
        print(f"❌ Permission denied! Try running with sudo.")
        sys.exit(1)
    
    return failed_ips, failed_users

def analyze_failures(ips, users, threshold):
    """Analyze and flag suspicious activities"""
    ip_counts = Counter(ips)
    user_counts = Counter(users)
    
    print(f"\n📊 Analysis Results\n{'='*50}")
    
    # Flag IPs with excessive failures
    suspicious_ips = {ip: count for ip, count in ip_counts.items() 
                     if count >= threshold}
    
    if suspicious_ips:
        print(f"\n⚠️  ALERT: Suspicious activity detected!\n")
        print("IP Address          Failed Attempts")
        print("-" * 40)
        for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip:20s} {count}")
        
        # ===== EMAIL ALERT =====
        alert_body = "🚨 SSH Brute-Force Attack Detected!\n\n"
        alert_body += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        alert_body += "Suspicious IPs (failed attempts):\n"
        alert_body += "-" * 40 + "\n"
        for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
            alert_body += f"{ip:20s} {count} attempts\n"
        
        alert_body += f"\nTotal failed attempts: {len(ips)}"
        alert_body += f"\nUnique IPs: {len(ip_counts)}"
        alert_body += f"\nThreshold: {threshold} attempts"
        
        send_alert("SSH Brute-Force Detected", alert_body)
        
        # ===== TELEGRAM ALERT =====
        telegram_msg = f"""
🚨 <b>SSH BRUTE-FORCE DETECTED</b>

<b>Suspicious IPs:</b>
{chr(10).join([f"  • <code>{ip}</code> - {count} attempts" for ip, count in list(suspicious_ips.items())[:5]])}

<b>Total attempts:</b> {len(ips)}
<b>Unique IPs:</b> {len(ip_counts)}
<b>Users targeted:</b> {', '.join([user for user, _ in user_counts.most_common(3)])}

🛡️ <i>Take action immediately!</i>
"""
        send_telegram(telegram_msg)
        
    else:
        print("\n✅ No suspicious IPs detected")
    
    # Show most targeted users
    print("\n📋 Most Targeted Users")
    print("-" * 40)
    for user, count in user_counts.most_common(5):
        print(f"{user:20s} {count}")
    
    # Summary
    print(f"\n📈 Summary")
    print("-" * 40)
    print(f"Total failed attempts: {len(ips)}")
    print(f"Unique IPs: {len(ip_counts)}")
    print(f"Unique users targeted: {len(user_counts)}")
    print(f"Alert threshold: {threshold} attempts")

def main():
    parser = argparse.ArgumentParser(description="Analyze system logs for suspicious activity")
    parser.add_argument("log_file", help="Path to log file (e.g., /var/log/auth.log)")
    parser.add_argument("-t", "--threshold", type=int, default=5,
                       help="Failed attempts threshold (default: 5)")
    args = parser.parse_args()
    
    print(f"🔍 Analyzing {args.log_file}...")
    ips, users = parse_auth_log(args.log_file)
    analyze_failures(ips, users, args.threshold)

if __name__ == "__main__":
    main()
