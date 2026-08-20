#!/usr/bin/env python3
"""
Email alert module for security tools
Uses Gmail SMTP with App Password
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket

# ===== CONFIGURATION - EDIT THESE =====
SENDER_EMAIL = "raniaemran252@gmail.com"
APP_PASSWORD = "eeuy whnf gzjf sfdm"   # Your 16-char app password
RECIPIENT_EMAIL = "raniaemran252@gmail.com"
# ======================================

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

def send_alert(subject, body):
    """Send an email alert"""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECIPIENT_EMAIL
        msg['Subject'] = f"[Security Alert] {subject}"

        # Attach body
        msg.attach(MIMEText(body, 'plain'))

        # Connect and send
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD.replace(" ", ""))  # Remove spaces
        server.send_message(msg)
        server.quit()

        print(f"✅ Alert email sent: {subject}")
        return True
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False

# Test function
# Test function
if __name__ == "__main__":
    send_alert("Test Alert", "This is a test from your security tools.")
