#!/usr/bin/env python3
"""
Lightweight TCP Port Scanner
Educational purposes only - use on authorized systems!
"""

import socket
import sys
import threading
from datetime import datetime
import argparse

def grab_banner(ip, port):
    """Attempt to grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        # Send generic probe
        if port in [80, 443, 8080]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        else:
            sock.send(b"\n")
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner if banner else "No banner"
    except:
        return "No banner"

def identify_service(port):
    """Map port to common service"""
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    return services.get(port, "Unknown")

def is_vulnerable(port, banner):
    """Flag potentially vulnerable services"""
    risky_ports = [21, 23, 25, 80, 443, 3306, 3389, 5432]
    if port in risky_ports:
        return True
    # Check for outdated versions in banner
    if banner and any(x in banner.lower() for x in ["2.0", "1.0", "old", "outdated"]):
        return True
    return False

def scan_port(ip, port, results):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            banner = grab_banner(ip, port)
            service = identify_service(port)
            vulnerable = is_vulnerable(port, banner)
            results.append({
                'port': port,
                'service': service,
                'banner': banner,
                'vulnerable': vulnerable
            })
        sock.close()
    except:
        pass

def main():
    parser = argparse.ArgumentParser(description="Lightweight TCP port scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", 
                       help="Port range (e.g., 1-1000, 80,443)")
    parser.add_argument("-t", "--threads", type=int, default=50,
                       help="Number of threads (default: 50)")
    args = parser.parse_args()
    
    # Parse port range
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = range(start, end + 1)
    else:
        ports = [int(p) for p in args.ports.split(',')]
    
    print(f"\n🔍 Scanning {args.target}...")
    print(f"📡 Ports: {args.ports}")
    print(f"⏱️  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    results = []
    threads = []
    
    # Start scanning
    for port in ports:
        t = threading.Thread(target=scan_port, args=(args.target, port, results))
        threads.append(t)
        t.start()
        # Limit concurrent threads
        if len(threads) >= args.threads:
            for t in threads:
                t.join()
            threads = []
    
    # Wait for remaining threads
    for t in threads:
        t.join()
    
    # Display results
    open_ports = [r for r in results if r]
    if open_ports:
        print(f"✅ Found {len(open_ports)} open ports:\n")
        for r in open_ports:
            vuln = "⚠️  VULNERABLE" if r['vulnerable'] else "✅ Safe"
            print(f"  Port {r['port']:5d} [{r['service']:12s}] {r['banner'][:40]:40s} {vuln}")
    else:
        print("❌ No open ports found in range")
    
    print(f"\n⏱️  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
