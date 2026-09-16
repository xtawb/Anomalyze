# Anomalyze Practical Examples 🚀

## Table of Contents
1. [Basic Scanning](#basic-scanning)
2. [Recursive Discovery](#recursive-discovery)
3. [Authentication Testing](#authentication-testing)
4. [API Security](#api-security)
5. [Stealth Scanning](#stealth-scanning)
6. [Custom Wordlists and Patterns](#custom-wordlists-and-patterns)
7. [CI Pipeline Usage](#ci-pipeline-usage)

---

## Basic Scanning

### Standard Web Application Scan
```bash
python Anomalyze.py -u https://example.com --default-paths -t 20
```
**What it does**:
- Checks the built-in list of common paths (admin panels, config files, VCS
  metadata, etc.)
- Uses 20 threads for faster scanning
- Prints color-coded results to the console and saves a JSON report

### Both JSON and CSV Output
```bash
python Anomalyze.py -u https://example.com --default-paths -o both
```

---

## Recursive Discovery

```bash
python Anomalyze.py -u https://example.com --deep-scan --max-depth 3
```
Follows links discovered in HTML (`<a>`, `<script src>`, `<link href>`) and
JSON responses, up to 3 hops from the initial path list, staying on the
scanned host.

---

## Authentication Testing

### Admin Panel Discovery with Spoofed Headers
```bash
python Anomalyze.py -u https://example.com -p /admin -p /wp-admin \
  -H "X-Forwarded-For: 127.0.0.1"
```

### Authenticated Scan with a Session Cookie
```bash
python Anomalyze.py -u https://example.com \
  --cookie "session=abc123" --deep-scan
```

### Bearer Token Auth
```bash
python Anomalyze.py -u https://example.com \
  -H "Authorization: Bearer token123" --deep-scan
```

---

## API Security

### REST API Scanning
```bash
python Anomalyze.py -u https://api.example.com/v1 \
  -H "Accept: application/json" \
  -p /users -p /products -p /admin
```

### POST Requests with a JSON Body
```bash
python Anomalyze.py -u https://api.example.com/v1 -m POST \
  --data '{"query":"test"}' --content-type "application/json"
```

---

## Stealth Scanning

### Slow, Low-Noise Scan
```bash
python Anomalyze.py -u https://example.com \
  -t 1 --delay "random(2000-5000)"
```
Single-threaded with a random 2-5 second delay between requests.

### Self-Signed Certificates in a Lab Environment
```bash
python Anomalyze.py -u https://internal-lab.local --insecure
```

---

## Custom Wordlists and Patterns

### Paths From a File
```bash
python Anomalyze.py -u https://example.com --paths-file wordlists/common.txt
```

### Custom Sensitive-Data Patterns
```bash
python Anomalyze.py -u https://example.com \
  --patterns-file bounty_patterns.json --min-severity High
```

---

## CI Pipeline Usage

### GitHub Actions
```yaml
- name: Run Anomalyze Scan
  run: |
    pip install -r requirements.txt
    python Anomalyze.py -u "$TARGET_URL" --default-paths -o json
- name: Upload report
  uses: actions/upload-artifact@v4
  with:
    name: anomalyze-report
    path: anomalyze_report_*.json
```

### Piping JSON to jq
```bash
python Anomalyze.py -u https://example.com --default-paths -o json
jq '.[] | select(.severity == "Critical")' anomalyze_report_*.json
```

> **Note**: Always obtain proper authorization before scanning a target you
> don't own or control.
