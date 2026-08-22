#!/usr/bin/env python3
"""
Enhanced Log Analyzer with Email Alerts
Detects suspicious activities and sends email notifications
"""

import re
import sys
import smtplib
import argparse
from collections import Counter
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Email configuration (UPDATE THESE!)
SMTP_SERVER = "smtp.gmail.com"  # For Gmail
SMTP_PORT = 587
EMAIL_SENDER = "your-email@gmail.com"
EMAIL_PASSWORD = "your-app-password"  # Use App Password, NOT your regular password!
EMAIL_RECIPIENT = "your-email@gmail.com"

def send_alert(ip_counts, user_counts, threshold):
    """Send email alert about suspicious activity"""
    if not ip_counts:
        return
    
    subject = f"🚨 SECURITY ALERT: Suspicious SSH Activity Detected!"
    
    # Build email body
    body = f"""
    Security Alert Report
    {'='*50}
    
    Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    Threshold: {threshold} failed attempts
    
    Suspicious IP Addresses:
    {'-'*40}
    """
    
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        body += f"  {ip:20s} {count} attempts\n"
    
    body += f"\nMost Targeted Users:\n{'-'*40}\n"
    for user, count in user_counts.most_common(5):
        body += f"  {user:20s} {count} attempts\n"
    
    body += f"\nTotal Failed Attempts: {sum(ip_counts.values())}"
    body += f"\nUnique IPs: {len(ip_counts)}"
    
    # Create email
    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECIPIENT
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    # Send email
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"📧 Alert email sent to {EMAIL_RECIPIENT}")
        return True
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False

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

def main():
    parser = argparse.ArgumentParser(description="Enhanced log analyzer with email alerts")
    parser.add_argument("log_file", help="Path to log file")
    parser.add_argument("-t", "--threshold", type=int, default=5,
                       help="Failed attempts threshold (default: 5)")
    parser.add_argument("-e", "--email", action="store_true",
                       help="Send email alerts")
    args = parser.parse_args()
    
    print(f"🔍 Analyzing {args.log_file}...")
    ips, users = parse_auth_log(args.log_file)
    
    ip_counts = Counter(ips)
    user_counts = Counter(users)
    
    suspicious_ips = {ip: count for ip, count in ip_counts.items() 
                     if count >= args.threshold}
    
    # Print results
    print(f"\n📊 Analysis Results\n{'='*50}")
    
    if suspicious_ips:
        print(f"\n⚠️  ALERT: {len(suspicious_ips)} suspicious IPs detected!\n")
        for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"  {ip:20s} {count} attempts")
        
        # Send email if requested
        if args.email:
            send_alert(suspicious_ips, user_counts, args.threshold)
    else:
        print("\n✅ No suspicious activity detected")
    
    print(f"\n📈 Summary")
    print(f"Total failed attempts: {len(ips)}")
    print(f"Unique IPs: {len(ip_counts)}")
    print(f"Alert threshold: {args.threshold} attempts")

if __name__ == "__main__":
    main()
