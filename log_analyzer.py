#!/usr/bin/env python3
"""
Automated Log Analysis Script
Detects suspicious activities in system logs with desktop alerts
"""

import re
import sys
import argparse
import subprocess
from collections import Counter
from datetime import datetime

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

def send_alert(ip, count, user):
    """Send desktop notification about suspicious activity"""
    try:
        # Desktop notification (works on Ubuntu/GNOME)
        subprocess.run([
            'notify-send',
            '🚨 Security Alert!',
            f'IP {ip} had {count} failed SSH attempts targeting user {user}'
        ], timeout=2, stderr=subprocess.DEVNULL)
    except:
        pass  # Silently fail if notification isn't available

def analyze_failures(ips, users, threshold):
    """Analyze and flag suspicious activities"""
    ip_counts = Counter(ips)
    user_counts = Counter(users)
    
    print(f"\n📊 Analysis Results")
    print("=" * 50)
    
    # Flag IPs with excessive failures
    suspicious_ips = {ip: count for ip, count in ip_counts.items() 
                     if count >= threshold}
    
    if suspicious_ips:
        print(f"\n⚠️  ALERT: Suspicious activity detected!\n")
        print("IP Address          Failed Attempts")
        print("-" * 40)
        top_user = user_counts.most_common(1)[0][0] if user_counts else "unknown"
        for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip:20s} {count}")
            # Send desktop alert for each suspicious IP
            send_alert(ip, count, top_user)
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
    
    if suspicious_ips:
        print(f"\n🚨 Desktop alerts sent for {len(suspicious_ips)} suspicious IPs!")

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
