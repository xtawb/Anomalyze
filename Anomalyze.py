#!/usr/bin/env python3
"""
Anomalyze - Advanced Web Path and Response Analyzer
A comprehensive security tool for discovering sensitive data and vulnerabilities
"""

import sys

# Make sure emoji/unicode output never crashes the scan on consoles that
# default to a legacy codepage (common on Windows cmd.exe / redirected output).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8')
    except Exception:
        pass

import os
import random
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
import urllib3

__version__ = '1.1.0'

# Initialize colorama
init()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PATTERNS_FILE = os.path.join(SCRIPT_DIR, 'patterns.json')

DEFAULT_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
]


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

    print(f"{Fore.YELLOW}Anomalyze v{__version__} - Advanced Server Response Analyzer{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Detect anomalous server behaviors and potential vulnerabilities")
    print("through customized HTTP request testing and response analysis")
    print(f"{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}Created by: {Fore.RED}xtawb")
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
    'High': '🟠',
    'Medium': '🟡',
    'Low': '🔵',
    'Info': 'ℹ️'
}

SEVERITY_ORDER = ['Info', 'Low', 'Medium', 'High', 'Critical']

# Default paths for scanning
DEFAULT_PATHS = [
    '/', '/admin', '/wp-admin', '/config',
    '/login', '/dashboard', '/api',
    '/test', '/backup', '/.env',
    '/phpmyadmin', '/.git', '/wp-login.php',
    '/administrator', '/mysql', '/dbadmin',
    '/private', '/secure', '/internal'
]

# Sensitive data patterns with severity classification (fallback if patterns.json is unavailable)
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


def load_patterns(patterns_file):
    """Load sensitive-data patterns from a JSON file, falling back to the built-in set."""
    path = patterns_file or DEFAULT_PATTERNS_FILE
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        patterns = {}
        for severity, entries in data.items():
            patterns[severity] = [(item[0], item[1]) for item in entries]
        if patterns:
            return patterns
    except FileNotFoundError:
        if patterns_file:
            print(f"{Fore.RED}Error: Patterns file not found: {patterns_file}. Using built-in patterns.{Style.RESET_ALL}")
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
        print(f"{Fore.RED}Error: Invalid patterns file ({e}). Using built-in patterns.{Style.RESET_ALL}")
    return SENSITIVE_PATTERNS


class ResponseAnalyzer:
    def __init__(self, patterns=None, min_severity='Info'):
        self.patterns = patterns or SENSITIVE_PATTERNS
        self.min_severity_index = SEVERITY_ORDER.index(min_severity)
        self.compiled_patterns = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile all regex patterns for performance"""
        for severity, patterns in self.patterns.items():
            self.compiled_patterns[severity] = [
                (re.compile(pattern, re.IGNORECASE), desc)
                for pattern, desc in patterns
            ]

    def analyze_content(self, text, headers):
        """Analyze text content and headers for sensitive patterns"""
        findings = defaultdict(list)

        # Check header values (matching header *names* like "Server" or
        # "Authorization" against the patterns would trigger on nearly every
        # response and drown real findings in noise).
        for header, value in headers.items():
            for severity, patterns in self.compiled_patterns.items():
                if SEVERITY_ORDER.index(severity) < self.min_severity_index:
                    continue
                for pattern, desc in patterns:
                    match = pattern.search(value)
                    if match:
                        findings[severity].append({
                            'type': desc,
                            'match': match.group(),
                            'location': f'header:{header}'
                        })

        # Check body content
        for severity, patterns in self.compiled_patterns.items():
            if SEVERITY_ORDER.index(severity) < self.min_severity_index:
                continue
            for pattern, desc in patterns:
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
            for link in soup.find_all(['a', 'script', 'link'], href=True):
                href = link.get('href')
                self._add_link(links, href, base_url)
            for tag in soup.find_all('script', src=True):
                self._add_link(links, tag.get('src'), base_url)
        except Exception:
            pass

        # Try to parse as JSON
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                for value in data.values():
                    if isinstance(value, str) and value.startswith('/'):
                        links.add(value)
        except Exception:
            pass

        return links

    @staticmethod
    def _add_link(links, href, base_url):
        if not href:
            return
        if href.startswith(('http://', 'https://')):
            parsed = urlparse(href)
            if parsed.netloc == urlparse(base_url).netloc and parsed.path:
                links.add(parsed.path)
        elif href.startswith('//'):
            return  # protocol-relative URL to another host, skip
        elif href.startswith('/'):
            links.add(href)
        elif not href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
            links.add('/' + href)


class Anomalyze:
    def __init__(self, args):
        self.base_url = self.normalize_base_url(args.url)
        self.method = args.method.upper()
        self.headers = self.build_headers(args)
        self.params = self.parse_params(args.params)
        self.data = args.data
        self.proxy = args.proxy
        self.proxy_list = self.load_line_file(args.proxy_list)
        self.threads = max(1, args.threads)
        self.timeout = args.timeout
        self.delay = args.delay
        self.insecure = args.insecure
        self.deep_scan = args.deep_scan
        self.max_depth = args.max_depth
        self.discovered_paths = set()
        self.paths = self.load_paths(args)
        self.session = self.create_session()
        patterns = load_patterns(args.patterns_file)
        self.analyzer = ResponseAnalyzer(patterns, args.min_severity)
        self.results = []
        self.verbose = args.verbose
        self.output_format = args.output

        if self.insecure:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @staticmethod
    def normalize_base_url(url):
        """Ensure the target URL has a scheme so requests doesn't reject it."""
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
            print(f"{Fore.YELLOW}No scheme in URL, defaulting to http:// -> http://{url}{Style.RESET_ALL}")
            url = 'http://' + url
        return url.rstrip('/')

    def build_headers(self, args):
        """Merge headers from --header-file, -H, --user-agent and --cookie."""
        headers = {}

        if args.header_file:
            try:
                with open(args.header_file, 'r', encoding='utf-8') as f:
                    file_headers = json.load(f)
                if isinstance(file_headers, dict):
                    headers.update({str(k): str(v) for k, v in file_headers.items()})
            except FileNotFoundError:
                print(f"{Fore.RED}Error: Header file not found: {args.header_file}{Style.RESET_ALL}")
            except json.JSONDecodeError as e:
                print(f"{Fore.RED}Error: Invalid header file ({e}){Style.RESET_ALL}")

        headers.update(self.parse_headers(args.header))

        if args.content_type:
            headers['Content-Type'] = args.content_type

        self.user_agents = self.load_line_file(args.user_agent_file)
        if not self.user_agents:
            headers['User-Agent'] = args.user_agent or random.choice(DEFAULT_USER_AGENTS)

        if args.cookie:
            headers['Cookie'] = args.cookie

        return headers

    @staticmethod
    def parse_headers(headers):
        """Parse custom headers from command line"""
        parsed = {}
        if headers:
            for h in headers:
                if ':' in h:
                    key, val = h.split(':', 1)
                    parsed[key.strip()] = val.strip()
        return parsed

    @staticmethod
    def parse_params(params):
        """Parse query parameters from command line"""
        parsed = []
        if params:
            for p in params:
                if '=' in p:
                    key, val = p.split('=', 1)
                    parsed.append((key.strip(), val.strip()))
        return parsed

    @staticmethod
    def load_line_file(file_path):
        """Load a list of non-empty, non-comment lines from a file."""
        if not file_path:
            return []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File not found: {file_path}{Style.RESET_ALL}")
            return []

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
            paths.extend(args.path)

        if args.paths_file:
            lines = self.load_line_file(args.paths_file)
            if not lines and not os.path.exists(args.paths_file):
                pass  # error already printed by load_line_file
            paths.extend(lines)

        if args.default_paths:
            paths.extend(DEFAULT_PATHS)

        # Normalize and deduplicate paths while preserving order
        normalized_paths = []
        seen = set()
        for path in paths:
            path = path.strip()
            if not path:
                continue
            if not path.startswith('/'):
                path = '/' + path
            self.discovered_paths.add(path)  # Track all initial paths
            if path not in seen:
                seen.add(path)
                normalized_paths.append((path, 0))

        return normalized_paths

    def send_request(self, url):
        """Send HTTP request and return response"""
        headers = dict(self.headers)
        if self.user_agents:
            headers['User-Agent'] = random.choice(self.user_agents)

        proxies = None
        if self.proxy_list:
            chosen = random.choice(self.proxy_list)
            proxies = {'http': chosen, 'https': chosen}

        if self.delay:
            time.sleep(self.delay / 1000.0)

        try:
            start = time.time()
            resp = self.session.request(
                self.method,
                url,
                headers=headers,
                params=self.params,
                data=self.data,
                timeout=self.timeout,
                allow_redirects=False,
                verify=not self.insecure,
                proxies=proxies
            )
            duration = time.time() - start
            return resp, duration
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"{Fore.RED}Request Error: {e}{Style.RESET_ALL}")
            return None, 0

    def process_response(self, resp, duration, url, depth):
        """Analyze server response for vulnerabilities"""
        analysis = {
            'url': url,
            'status': resp.status_code,
            'size': len(resp.content),
            'time': f"{duration:.2f}s",
            'findings': [],
            'severity': 'Info'
        }

        content_type = resp.headers.get('Content-Type', '')
        is_text = content_type == '' or any(
            t in content_type for t in ('text', 'json', 'xml', 'javascript', 'html')
        )

        # Skip pattern analysis on large/binary bodies to avoid wasted CPU/memory
        if is_text and len(resp.content) <= 5 * 1024 * 1024:
            findings = self.analyzer.analyze_content(resp.text, resp.headers)
        else:
            findings = {}

        # Extract new paths from response (only when deep scanning is enabled)
        if self.deep_scan and resp.status_code == 200 and depth < self.max_depth and is_text:
            new_paths = self.analyzer.extract_links(resp.text, self.base_url)
            for path in new_paths:
                if path not in self.discovered_paths:
                    self.discovered_paths.add(path)
                    self.paths.append((path, depth + 1))

        # Determine maximum severity
        max_severity = 'Info'
        for severity in findings:
            if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(max_severity):
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

        total_scanned = 0
        try:
            while self.paths:
                current_batch = self.paths[:100]  # Scan up to 100 paths at a time
                self.paths = self.paths[100:]  # Remaining paths for next batch

                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                    future_to_path = {
                        executor.submit(
                            self.send_request,
                            urljoin(self.base_url + '/', path.lstrip('/'))
                        ): (path, depth)
                        for path, depth in current_batch
                    }

                    for future in concurrent.futures.as_completed(future_to_path):
                        path, depth = future_to_path[future]
                        try:
                            resp, duration = future.result()
                            if resp is not None:
                                url = urljoin(self.base_url + '/', path.lstrip('/'))
                                result = self.process_response(resp, duration, url, depth)
                                self.results.append(result)
                                self.print_result(result)
                                total_scanned += 1
                        except Exception as e:
                            if self.verbose:
                                print(f"{Fore.RED}Error processing {path}: {e}{Style.RESET_ALL}")

                print(f"\n{Fore.CYAN}Scanned {total_scanned} paths. {len(self.paths)} new paths queued.{Style.RESET_ALL}")

                # Limit total scans to prevent runaway crawls
                if total_scanned > 1000:
                    print(f"{Fore.YELLOW}Scan limit reached (1000 paths). Stopping.{Style.RESET_ALL}")
                    break
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Scan interrupted by user. Saving partial results...{Style.RESET_ALL}")

        self.save_results()

    def print_result(self, result):
        """Display scan results in a formatted table"""
        color = SEVERITY_COLORS.get(result['severity'], Fore.WHITE)
        icon = SEVERITY_ICONS.get(result['severity'], '')

        print(f"{color}{icon} {result['severity']}{Style.RESET_ALL}")

        main_table = PrettyTable()
        main_table.field_names = ["Field", "Value"]
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
                match_text = finding['match']
                findings_table.add_row([
                    finding['type'],
                    match_text[:50] + ('...' if len(match_text) > 50 else ''),
                    finding['location']
                ])

            print(f"\n{Fore.YELLOW}Sensitive Data Found:{Style.RESET_ALL}")
            print(findings_table)

        print("\n" + "=" * 80 + "\n")

    def save_results(self):
        """Save scan results to file"""
        if not self.results:
            print(f"{Fore.YELLOW}No results to save.{Style.RESET_ALL}")
            return

        timestamp = int(time.time())

        if self.output_format in ('json', 'both'):
            json_file = f'anomalyze_report_{timestamp}.json'
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2)
            print(f"{Fore.GREEN}JSON report saved to: {json_file}{Style.RESET_ALL}")

        if self.output_format in ('csv', 'both'):
            csv_file = f'anomalyze_report_{timestamp}.csv'
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Status', 'Size', 'Time', 'Severity', 'Finding Type', 'Match', 'Location'])
                for result in self.results:
                    if result['findings']:
                        for finding in result['findings']:
                            writer.writerow([
                                result['url'], result['status'], result['size'], result['time'],
                                result['severity'], finding['type'], finding['match'], finding['location']
                            ])
                    else:
                        writer.writerow([
                            result['url'], result['status'], result['size'], result['time'],
                            result['severity'], '', '', ''
                        ])
            print(f"{Fore.GREEN}CSV report saved to: {csv_file}{Style.RESET_ALL}")


def positive_int(value):
    ivalue = int(value)
    if ivalue < 1:
        raise argparse.ArgumentTypeError(f"{value} must be a positive integer")
    return ivalue


def delay_ms(value):
    """Accept a plain millisecond integer or a random(min-max) expression."""
    match = re.match(r'^random\((\d+)-(\d+)\)$', value.strip())
    if match:
        low, high = int(match.group(1)), int(match.group(2))
        return random.randint(min(low, high), max(low, high))
    try:
        return int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{value} must be an integer (ms) or random(min-max), e.g. random(500-3000)"
        )


def build_parser():
    parser = argparse.ArgumentParser(
        description='Anomalyze - Advanced Web Path and Response Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  -> Basic scan ---> : anomalyze.py -u http://example.com\n'
               '  -> Custom paths -> : anomalyze.py -u http://example.com -p /admin -p /login\n'
               '  -> From file ----> : anomalyze.py -u http://example.com --paths-file paths.txt\n'
               '  -> Full scan ----> : anomalyze.py -u http://example.com --default-paths -t 20 --output both\n'
               '  -> Deep crawl ---> : anomalyze.py -u http://example.com --deep-scan --max-depth 3'
    )

    parser.add_argument('-u', '--url', required=True, help='Target base URL')
    parser.add_argument('--version', action='version', version=f'Anomalyze {__version__}')

    path_group = parser.add_argument_group('Path Configuration')
    path_group.add_argument('-p', '--path', action='append', help='Individual path to test')
    path_group.add_argument('--paths-file', help='File containing list of paths to test')
    path_group.add_argument('--default-paths', action='store_true',
                             help='Use default list of common paths (enabled by default if no paths specified)')
    path_group.add_argument('--deep-scan', action='store_true',
                             help='Follow links discovered in responses to find new paths')
    path_group.add_argument('--max-depth', type=int, default=2,
                             help='Maximum recursion depth for --deep-scan (default: 2)')

    req_group = parser.add_argument_group('Request Configuration')
    req_group.add_argument('-m', '--method', default='GET', help='HTTP method (GET, POST, etc)')
    req_group.add_argument('-H', '--header', action='append', help='Custom headers (Header:Value)')
    req_group.add_argument('--header-file', help='JSON file of additional headers to send')
    req_group.add_argument('-d', '--data', help='Request body data')
    req_group.add_argument('--params', action='append', help='Query parameters (param=value)')
    req_group.add_argument('--cookie', help='Raw Cookie header value')
    req_group.add_argument('--content-type', help='Shorthand for -H "Content-Type: <value>"')
    req_group.add_argument('--user-agent', help='Custom User-Agent string (default: random)')
    req_group.add_argument('--user-agent-file', help='File of User-Agent strings to rotate per request')

    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument('-t', '--threads', type=positive_int, default=10,
                             help='Number of concurrent threads (default: 10)')
    perf_group.add_argument('-x', '--proxy', help='Proxy server (e.g., http://localhost:8080)')
    perf_group.add_argument('--proxy-list', help='File of proxies to rotate per request')
    perf_group.add_argument('--timeout', type=positive_int, default=15, help='Request timeout in seconds (default: 15)')
    perf_group.add_argument('--delay', type=delay_ms, default=0,
                             help='Delay between requests in ms, or random(min-max), e.g. random(500-3000)')
    perf_group.add_argument('-k', '--insecure', action='store_true', help='Skip TLS certificate verification')

    out_group = parser.add_argument_group('Output Options')
    out_group.add_argument('-o', '--output', choices=['json', 'csv', 'both'], default='json',
                            help='Output format (default: json)')
    out_group.add_argument('--min-severity', choices=SEVERITY_ORDER, default='Info',
                            help='Only report findings at or above this severity (default: Info)')
    out_group.add_argument('--patterns-file',
                            help=f'JSON file of custom detection patterns (default: {os.path.basename(DEFAULT_PATTERNS_FILE)} next to the script)')
    out_group.add_argument('-v', '--verbose', action='store_true', help='Verbose output including errors')

    return parser


def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    try:
        analyzer = Anomalyze(args)
        analyzer.run_scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted.{Style.RESET_ALL}")
        sys.exit(130)


if __name__ == '__main__':
    main()
