#!/usr/bin/env python3
"""
Anomalyze - Advanced Web Path and Response Analyzer
A comprehensive security tool for discovering sensitive data and vulnerabilities
"""

import requests
import argparse
from colorama import Fore, Style, init
import csv
import json
import concurrent.futures
import re
import time
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from prettytable import PrettyTable
from bs4 import BeautifulSoup

# Initialize colorama
init()

def print_banner():
    banner_lines = [
        "                                                              ,,                            ",
        "      db                                                    `7MM                            ",
        "     ;MM:                                                     MM                            ",
        "    ,V^MM.    `7MMpMMMb.  ,pW\"Wq.`7MMpMMMb.pMMMb.   ,6\"Yb.    MM `7M'   `MF'M\"\"\"\"MMV .gP\"Ya  ",
        "   ,M  `MM      MM    MM 6W'   `Wb MM    MM    MM  8)   MM    MM   VA   ,V  '  AMV ,M'   Yb ",
        "   AbmmmqMA     MM    MM 8M     M8 MM    MM    MM   ,pm9MM    MM    VA ,V     AMV  8M\"\"\"\"\"\" ",
        "  A'     VML    MM    MM YA.   ,A9 MM    MM    MM  8M   MM    MM     VVV     AMV  ,YM.    , ",
        ".AMA.   .AMMA..JMML  JMML.`Ybmd9'.JMML  JMML  JMML.`Moo9^Yo..JMML.   ,V     AMMmmmM `Mbmmd' ",
        "                                                                    ,V                      ",
        "                                                                 OOb\"                       "
    ]
    
    print(f"{Fore.CYAN}")
    for line in banner_lines:
        print(line)
    print(f"{Style.RESET_ALL}")
    
    print(f"{Fore.YELLOW}Anomalyze - Advanced Server Response Analyzer{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Detect anomalous server behaviors and potential vulnerabilities")
    print("through customized HTTP request testing and response analysis")
    print(f"{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}Created by: {Fore.RED}xtawb Ghorbandy")
    print(f"{Fore.MAGENTA}->Contact : {Fore.RED}https://linktr.ee/xtawb")
    print(f"{Fore.MAGENTA}->GitHub  : {Fore.RED}https://github.com/xtawb{Style.RESET_ALL}")
    print()

# Color and icon definitions
SEVERITY_COLORS = {
    'Critical': Fore.RED + Style.BRIGHT,
    'High': Fore.RED,
    'Medium': Fore.YELLOW,
    'Low': Fore.GREEN,
    'Info': Fore.BLUE
}

SEVERITY_ICONS = {
    'Critical': '🔴',
    'High': '🔴',
    'Medium': '🟡',
    'Low': '🔵',
    'Info': 'ℹ️'
}

# Default paths for scanning
DEFAULT_PATHS = [
    '/', '/admin', '/wp-admin', '/config',
    '/login', '/dashboard', '/api',
    '/test', '/backup', '/.env',
    '/phpmyadmin', '/.git', '/wp-login.php',
    '/administrator', '/mysql', '/dbadmin',
    '/private', '/secure', '/internal'
]

# Sensitive data patterns with severity classification
SENSITIVE_PATTERNS = {
    'Critical': [
        (r'\b(password|passwd|pwd|credential)\b', '🔒 Sensitive Credential'),
        (r'\b(api[_-]?key|token|secret|auth)\b', '🔑 API Key'),
        (r'\bSQL syntax error|unclosed quotation\b', '⚠️ SQL Error'),
        (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '💳 Credit Card'),
        (r'\b(ssh-rsa|BEGIN RSA PRIVATE KEY)\b', '🔑 SSH Key')
    ],
    'High': [
        (r'\b(admin|root|superuser|sysadmin)\b', '👑 Admin Account'),
        (r'\b(login|signin|authentication)\b', '🔐 Auth Endpoint'),
        (r'\b(ssn|social security number)\b', '📛 PII Data'),
        (r'\b(aws_access_key_id|aws_secret_access_key)\b', '☁️ AWS Credentials')
    ],
    'Medium': [
        (r'\b(config|settings|env|configuration)\b', '⚙️ Config File'),
        (r'\b(backup|archive|dump|sql)\b', '💾 Backup File'),
        (r'\b(internal|confidential|restricted)\b', '📄 Internal Doc')
    ],
    'Low': [
        (r'\b(server|version|os|platform)\b', '🖥️ Server Info'),
        (r'\b(php|asp|jsp|nodejs)\b', '💻 Tech Stack'),
        (r'\b(jquery|bootstrap|react)\b', '📚 Client Library')
    ]
}

class ResponseAnalyzer:
    def __init__(self):
        self.compiled_patterns = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile all regex patterns for performance"""
        for severity, patterns in SENSITIVE_PATTERNS.items():
            self.compiled_patterns[severity] = [
                (re.compile(pattern, re.IGNORECASE), desc)
                for pattern, desc in patterns
            ]
    
    def analyze_content(self, text, headers):
        """Analyze text content and headers for sensitive patterns"""
        findings = defaultdict(list)
        
        # Check headers
        for header, value in headers.items():
            for severity in self.compiled_patterns:
                for pattern, desc in self.compiled_patterns[severity]:
                    if pattern.search(f"{header}: {value}"):
                        findings[severity].append({
                            'type': desc,
                            'match': value,
                            'location': 'header'
                        })
        
        # Check body content
        for severity in self.compiled_patterns:
            for pattern, desc in self.compiled_patterns[severity]:
                for match in pattern.finditer(text):
                    findings[severity].append({
                        'type': desc,
                        'match': match.group(),
                        'location': 'body'
                    })
        
        return findings
    
    def extract_links(self, text, base_url):
        """Extract links from HTML and JSON responses"""
        links = set()
        
        # Try to parse as HTML first
        try:
            soup = BeautifulSoup(text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith(('http://', 'https://')):
                    parsed = urlparse(href)
                    if parsed.netloc == urlparse(base_url).netloc:
                        links.add(parsed.path)
                elif href.startswith('/'):
                    links.add(href)
                elif not href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                    links.add('/' + href)
        except:
            pass
        
        # Try to parse as JSON
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                for value in data.values():
                    if isinstance(value, str) and value.startswith('/'):
                        links.add(value)
        except:
            pass
        
        return links

class Anomalyze:
    def __init__(self, args):
        self.base_url = args.url.rstrip('/')
        self.method = args.method.upper()
        self.headers = self.parse_headers(args.header)
        self.params = self.parse_params(args.params)
        self.data = args.data
        self.proxy = args.proxy
        self.threads = args.threads
        self.discovered_paths = set()  #####load_paths#####
        self.paths = self.load_paths(args)
        self.session = self.create_session()
        self.analyzer = ResponseAnalyzer()
        self.results = []
        self.verbose = args.verbose
        self.output_format = args.output

    def parse_headers(self, headers):
        """Parse custom headers from command line"""
        parsed = {}
        if headers:
            for h in headers:
                if ':' in h:
                    key, val = h.split(':', 1)
                    parsed[key.strip()] = val.strip()
        return parsed

    def parse_params(self, params):
        """Parse query parameters from command line"""
        parsed = []
        if params:
            for p in params:
                if '=' in p:
                    key, val = p.split('=', 1)
                    parsed.append((key.strip(), val.strip()))
        return parsed

    def create_session(self):
        """Create requests session with proxy if specified"""
        session = requests.Session()
        if self.proxy:
            session.proxies = {'http': self.proxy, 'https': self.proxy}
        return session

    def load_paths(self, args):
        """Load paths from various sources"""
        paths = []
        
        # If no paths specified, use default paths
        if not args.path and not args.paths_file and not args.default_paths:
            args.default_paths = True
        
        if args.path:
            if isinstance(args.path, list):
                paths.extend(args.path)
            else:
                paths.append(args.path)
        
        if args.paths_file:
            try:
                with open(args.paths_file, 'r') as f:
                    paths.extend(line.strip() for line in f if line.strip())
            except FileNotFoundError:
                print(f"{Fore.RED}Error: Paths file not found: {args.paths_file}{Style.RESET_ALL}")
        
        if args.default_paths:
            paths.extend(DEFAULT_PATHS)
        
        # Normalize and deduplicate paths
        normalized_paths = []
        for path in paths:
            path = path.strip()
            if not path.startswith('/'):
                path = '/' + path
            normalized_paths.append(path)
            self.discovered_paths.add(path)  # Track all initial paths
        
        return list(set(normalized_paths))

    def send_request(self, url):
        """Send HTTP request and return response"""
        try:
            start = time.time()
            resp = self.session.request(
                self.method,
                url,
                headers=self.headers,
                params=self.params,
                data=self.data,
                timeout=15,
                allow_redirects=False
            )
            duration = time.time() - start
            return resp, duration
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Request Error: {e}{Style.RESET_ALL}")
            return None, 0

    def process_response(self, resp, duration, url):
        """Analyze server response for vulnerabilities"""
        analysis = {
            'url': url,
            'status': resp.status_code,
            'size': len(resp.content),
            'time': f"{duration:.2f}s",
            'findings': [],
            'severity': 'Info'
        }
        
        # Analyze content for sensitive data
        findings = self.analyzer.analyze_content(resp.text, resp.headers)
        
        # Extract new paths from response
        if resp.status_code == 200:
            new_paths = self.analyzer.extract_links(resp.text, self.base_url)
            for path in new_paths:
                if path not in self.discovered_paths:
                    self.discovered_paths.add(path)
                    self.paths.append(path)  # Add to paths to scan
        
        # Determine maximum severity
        max_severity = 'Info'
        severity_order = ['Info', 'Low', 'Medium', 'High', 'Critical']
        
        for severity in findings:
            if severity_order.index(severity) > severity_order.index(max_severity):
                max_severity = severity
            analysis['findings'].extend(findings[severity])
        
        analysis['severity'] = max_severity
        return analysis

    def run_scan(self):
        """Execute the scanning process"""
        if not self.paths:
            print(f"{Fore.YELLOW}No paths to scan.{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}Starting scan with {len(self.paths)} initial paths and {self.threads} threads...{Style.RESET_ALL}")
        
        # We'll scan in batches as we discover new paths
        total_scanned = 0
        while self.paths:
            current_batch = self.paths[:100]  # Scan up to 100 paths at a time
            self.paths = self.paths[100:]  # Remaining paths for next batch
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {
                    executor.submit(self.send_request, urljoin(self.base_url + '/', path.lstrip('/'))): path
                    for path in current_batch
                }
                
                for future in concurrent.futures.as_completed(future_to_url):
                    path = future_to_url[future]
                    try:
                        resp, duration = future.result()
                        if resp:
                            result = self.process_response(resp, duration, urljoin(self.base_url + '/', path.lstrip('/')))
                            self.results.append(result)
                            self.print_result(result)
                            total_scanned += 1
                    except Exception as e:
                        if self.verbose:
                            print(f"{Fore.RED}Error processing {path}: {e}{Style.RESET_ALL}")
            
            print(f"\n{Fore.CYAN}Scanned {total_scanned} paths. Discovered {len(self.paths)} new paths to scan.{Style.RESET_ALL}")
            
            # Limit total scans to prevent infinite loops
            if total_scanned > 1000:
                print(f"{Fore.YELLOW}Scan limit reached (1000 paths). Stopping.{Style.RESET_ALL}")
                break

        self.save_results()

    def print_result(self, result):
        """Display scan results in a formatted table"""
        color = SEVERITY_COLORS.get(result['severity'], Fore.WHITE)
        icon = SEVERITY_ICONS.get(result['severity'], '')
        
        # Main result table
        main_table = PrettyTable()
        main_table.field_names = [f"{icon} {color}{result['severity']}{Style.RESET_ALL}", "Value"]
        main_table.align = "l"
        main_table.add_row(["URL", result['url']])
        main_table.add_row(["Status", result['status']])
        main_table.add_row(["Size", f"{result['size']} bytes"])
        main_table.add_row(["Time", f"{result['time']}"])
        
        print(main_table)
        
        # Findings table if any
        if result['findings']:
            findings_table = PrettyTable()
            findings_table.field_names = ["Type", "Match", "Location"]
            findings_table.align = "l"
            
            for finding in result['findings']:
                findings_table.add_row([
                    finding['type'],
                    finding['match'][:50] + ('...' if len(finding['match']) > 50 else ''),
                    finding['location']
                ])
            
            print(f"\n{Fore.YELLOW}Sensitive Data Found:{Style.RESET_ALL}")
            print(findings_table)
        
        print("\n" + "="*80 + "\n")

    def save_results(self):
        """Save scan results to file"""
        if not self.results:
            print(f"{Fore.YELLOW}No results to save.{Style.RESET_ALL}")
            return
        
        timestamp = int(time.time())
        
        if self.output_format == 'json' or self.output_format == 'both':
            json_file = f'anomalyze_report_{timestamp}.json'
            with open(json_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"{Fore.GREEN}JSON report saved to: {json_file}{Style.RESET_ALL}")
        
        if self.output_format == 'csv' or self.output_format == 'both':
            csv_file = f'anomalyze_report_{timestamp}.csv'
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Status', 'Size', 'Time', 'Severity', 'Finding Type', 'Match', 'Location'])
                for result in self.results:
                    if result['findings']:
                        for finding in result['findings']:
                            writer.writerow([
                                result['url'],
                                result['status'],
                                result['size'],
                                result['time'],
                                result['severity'],
                                finding['type'],
                                finding['match'],
                                finding['location']
                            ])
                    else:
                        writer.writerow([
                            result['url'],
                            result['status'],
                            result['size'],
                            result['time'],
                            result['severity'],
                            '',
                            '',
                            ''
                        ])
            print(f"{Fore.GREEN}CSV report saved to: {csv_file}{Style.RESET_ALL}")

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Anomalyze - Advanced Web Path and Response Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  -> Basic scan ---> : anomalyze.py -u http://example.com\n'
               '  -> Custom paths -> : anomalyze.py -u http://example.com -p /admin -p /login\n'
               '  -> From file ----> : anomalyze.py -u http://example.com --paths-file paths.txt\n'
               '  -> Full scan ----> : anomalyze.py -u http://example.com --default-paths -t 20 --output both'
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', required=True, help='Target base URL')
    
    # Path configuration
    path_group = parser.add_argument_group('Path Configuration')
    path_group.add_argument('-p', '--path', action='append', help='Individual path to test')
    path_group.add_argument('--paths-file', help='File containing list of paths to test')
    path_group.add_argument('--default-paths', action='store_true', 
                          help='Use default list of common paths (enabled by default if no paths specified)')
    
    # Request configuration
    req_group = parser.add_argument_group('Request Configuration')
    req_group.add_argument('-m', '--method', default='GET', 
                         help='HTTP method (GET, POST, etc)')
    req_group.add_argument('-H', '--header', action='append', 
                         help='Custom headers (Header:Value)')
    req_group.add_argument('-d', '--data', 
                         help='Request body data')
    req_group.add_argument('--params', action='append', 
                         help='Query parameters (param=value)')
    
    # Performance options
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument('-t', '--threads', type=int, default=10,
                          help='Number of concurrent threads (default: 10)')
    perf_group.add_argument('-x', '--proxy',
                          help='Proxy server (e.g., http://localhost:8080)')
    
    # Output options
    out_group = parser.add_argument_group('Output Options')
    out_group.add_argument('-o', '--output', choices=['json', 'csv', 'both'], default='json',
                         help='Output format (default: json)')
    out_group.add_argument('-v', '--verbose', action='store_true',
                         help='Verbose output including errors')
    
    args = parser.parse_args()
    
    analyzer = Anomalyze(args)
    analyzer.run_scan()

if __name__ == '__main__':
    main()
