#!/usr/bin/env python3
"""
CVE Vulnerability Lookup
Check services for known vulnerabilities using NVD API
"""

import requests
import json
from datetime import datetime
import time

class CVEChecker:
    def __init__(self):
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = {}
        self.cache_file = "cve_cache.json"
        self.load_cache()
    
    def load_cache(self):
        """Load cached CVE results"""
        try:
            with open(self.cache_file, 'r') as f:
                self.cache = json.load(f)
            print(f"📂 Loaded {len(self.cache)} cached CVE results")
        except FileNotFoundError:
            self.cache = {}
    
    def save_cache(self):
        """Save CVE results to cache"""
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)
    
    def check_service(self, service, version=None):
        """Check if a service has known CVEs"""
        cache_key = f"{service}:{version}" if version else service
        
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            params = {
                'keywordSearch': service if not version else f"{service} {version}",
                'resultsPerPage': 5
            }
            print(f"🔍 Checking {service} {version if version else ''}...")
            response = requests.get(self.api_url, params=params, timeout=10)
            data = response.json()
            
            total = data.get('totalResults', 0)
            vulnerabilities = data.get('vulnerabilities', [])
            
            result = {
                'service': service,
                'version': version,
                'total_cves': total,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'recent': [],
                'timestamp': datetime.now().isoformat()
            }
            
            # Parse CVEs
            for cve_data in vulnerabilities[:5]:
                cve = cve_data['cve']
                cve_id = cve.get('id', 'Unknown')
                
                # Get severity
                metrics = cve.get('metrics', {})
                cvss_v31 = metrics.get('cvssMetricV31', [{}])[0]
                cvss_v30 = metrics.get('cvssMetricV30', [{}])[0]
                cvss_v2 = metrics.get('cvssMetricV2', [{}])[0]
                
                score = 0
                severity = 'UNKNOWN'
                
                if cvss_v31:
                    score = cvss_v31.get('cvssData', {}).get('baseScore', 0)
                    severity = cvss_v31.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
                elif cvss_v30:
                    score = cvss_v30.get('cvssData', {}).get('baseScore', 0)
                    severity = cvss_v30.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
                elif cvss_v2:
                    score = cvss_v2.get('cvssData', {}).get('baseScore', 0)
                    severity = 'HIGH' if score >= 7 else 'MEDIUM' if score >= 4 else 'LOW'
                
                # Count by severity
                if score >= 9.0:
                    result['critical'] += 1
                elif score >= 7.0:
                    result['high'] += 1
                elif score >= 4.0:
                    result['medium'] += 1
                elif score > 0:
                    result['low'] += 1
                
                # Get description
                descriptions = cve.get('descriptions', [])
                description = ''
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                result['recent'].append({
                    'id': cve_id,
                    'score': score,
                    'severity': severity,
                    'description': description[:200]
                })
            
            self.cache[cache_key] = result
            self.save_cache()
            
            # Rate limit
            time.sleep(1)
            return result
            
        except requests.exceptions.Timeout:
            print("⏱️  Timeout waiting for NVD API")
            return None
        except requests.exceptions.RequestException as e:
            print(f"⚠️ CVE lookup failed: {e}")
            return None
        except json.JSONDecodeError:
            print("⚠️ Invalid response from NVD API")
            return None
    
    def check_ports(self, port_data):
        """Check ports from scanner results"""
        service_map = {
            22: ('OpenSSH', None),
            80: ('Apache', None),
            443: ('Apache', None),
            3306: ('MySQL', None),
            5432: ('PostgreSQL', None),
            3389: ('RDP', None),
            21: ('FTP', None),
            25: ('SMTP', None),
            8080: ('Apache', None)
        }
        
        results = {}
        for port in port_data:
            if port in service_map:
                service, version = service_map[port]
                result = self.check_service(service, version)
                if result:
                    results[port] = result
        
        return results

if __name__ == "__main__":
    # Test the CVE checker
    checker = CVEChecker()
    
    print("\n🔍 Testing CVE Lookup:")
    tests = [
        ('OpenSSH', '10.2'),
        ('Apache', '2.4.41'),
        ('MySQL', '8.0.23'),
    ]
    
    for service, version in tests:
        result = checker.check_service(service, version)
        if result:
            print(f"\n📦 {service} {version}:")
            print(f"   Total CVEs: {result['total_cves']}")
            print(f"   🔴 Critical: {result['critical']}")
            print(f"   🟠 High: {result['high']}")
            print(f"   🟡 Medium: {result['medium']}")
            print(f"   🟢 Low: {result['low']}")
            
            if result['recent']:
                print(f"   Recent CVEs:")
                for cve in result['recent'][:3]:
                    print(f"      - {cve['id']} (Score: {cve['score']} | {cve['severity']})")
