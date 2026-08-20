#!/usr/bin/env python3
"""
File Integrity Checker
Monitors directory for file changes using SHA-256 hashes
Sends email alerts when changes are detected
"""

import os
import sys
import json
import hashlib
import argparse
from datetime import datetime

try:
    from email_alerts import send_alert
except ImportError:
    print("⚠️  email_alerts.py not found. Email alerts disabled.")
    def send_alert(subject, body):
        print(f"📧 [ALERT] {subject}")
        return False

def sha256_file(filepath):
    """Calculate SHA-256 hash of a file"""
    sha = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha.update(chunk)
        return sha.hexdigest()
    except (IOError, OSError, PermissionError):
        return None

def build_hash_dict(directory, exclude=None):
    """Walk directory and build hash dictionary"""
    if exclude is None:
        exclude = []
    
    hash_dict = {}
    for dirpath, dirnames, filenames in os.walk(directory):
        # Exclude directories
        dirnames[:] = [d for d in dirnames if d not in exclude]
        
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(full_path, directory)
            file_hash = sha256_file(full_path)
            if file_hash:
                hash_dict[rel_path] = file_hash
    
    return hash_dict

def save_baseline(baseline_file, hash_dict):
    """Save hash dictionary to JSON file"""
    with open(baseline_file, 'w') as f:
        json.dump(hash_dict, f, indent=2)
    print(f"💾 Baseline saved to {baseline_file}")

def check_integrity(baseline_file, directory, exclude=None):
    """Compare current state with baseline"""
    if exclude is None:
        exclude = []
    
    try:
        with open(baseline_file, 'r') as f:
            baseline = json.load(f)
        print(f"📂 Loaded baseline with {len(baseline)} files")
    except FileNotFoundError:
        print("🔨 No baseline found. Creating one...")
        hash_dict = build_hash_dict(directory, exclude)
        save_baseline(baseline_file, hash_dict)
        print("✅ Baseline created. Run again to check integrity.")
        return
    
    current = build_hash_dict(directory, exclude)
    
    print(f"\n🔍 Checking integrity...\n")
    changes_found = False
    changed_files = {"new": [], "modified": [], "deleted": []}
    
    # Check for new and modified files
    for rel_path, cur_hash in current.items():
        if rel_path not in baseline:
            print(f"🆕 NEW: {rel_path}")
            changed_files["new"].append(rel_path)
            changes_found = True
        elif baseline[rel_path] != cur_hash:
            print(f"🔄 MODIFIED: {rel_path}")
            changed_files["modified"].append(rel_path)
            changes_found = True
    
    # Check for deleted files
    for rel_path in baseline:
        if rel_path not in current:
            print(f"🗑️  DELETED: {rel_path}")
            changed_files["deleted"].append(rel_path)
            changes_found = True
    
    if not changes_found:
        print("✅ No changes detected - system is clean!")
    else:
        # Count total changes
        total_changes = len(changed_files["new"]) + len(changed_files["modified"]) + len(changed_files["deleted"])
        print(f"\n⚠️  ALERT: {total_changes} changes detected!")
        
        # ===== EMAIL ALERT =====
        alert_body = "🚨 File Integrity Alert!\n\n"
        alert_body += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        alert_body += f"Directory: {directory}\n\n"
        
        if changed_files["new"]:
            alert_body += "🆕 New Files:\n"
            for f in changed_files["new"][:10]:
                alert_body += f"  - {f}\n"
            if len(changed_files["new"]) > 10:
                alert_body += f"  ... and {len(changed_files['new']) - 10} more\n"
        
        if changed_files["modified"]:
            alert_body += "\n🔄 Modified Files:\n"
            for f in changed_files["modified"][:10]:
                alert_body += f"  - {f}\n"
            if len(changed_files["modified"]) > 10:
                alert_body += f"  ... and {len(changed_files['modified']) - 10} more\n"
        
        if changed_files["deleted"]:
            alert_body += "\n🗑️  Deleted Files:\n"
            for f in changed_files["deleted"][:10]:
                alert_body += f"  - {f}\n"
            if len(changed_files["deleted"]) > 10:
                alert_body += f"  ... and {len(changed_files['deleted']) - 10} more\n"
        
        send_alert("File Integrity Alert", alert_body)
        print("📧 Email alert sent!")

def main():
    parser = argparse.ArgumentParser(description="Monitor file integrity using SHA-256")
    parser.add_argument("directory", help="Directory to monitor")
    parser.add_argument("-b", "--baseline", default="baseline.json",
                       help="Baseline file path (default: baseline.json)")
    parser.add_argument("-e", "--exclude", nargs="+", default=[],
                       help="Directories to exclude (e.g., .git __pycache__)")
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"❌ Directory {args.directory} not found!")
        sys.exit(1)
    
    print(f"🔒 File Integrity Checker")
    print(f"📁 Directory: {args.directory}")
    print(f"📄 Baseline: {args.baseline}")
    print(f"🚫 Excluding: {', '.join(args.exclude) if args.exclude else 'None'}\n")
    
    check_integrity(args.baseline, args.directory, args.exclude)

if __name__ == "__main__":
    main()
