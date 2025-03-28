<!-- markdownextradata disabled -->
# Anomalyze Practical Examples 🚀

## Table of Contents
1. [Basic Scanning](#basic-scanning)
2. [Authentication Testing](#authentication-testing)
3. [API Security](#api-security)
4. [Stealth Operations](#stealth-operations)
5. [Bug Bounty Hunting](#bug-bounty-hunting)
6. [CI/CD Integration](#cicd-integration)
7. [Advanced Analysis](#advanced-analysis)

---

## Basic Scanning

### Standard Web Application Scan
```bash
python Anomalyze.py -u https://example.com --default-paths -t 20
```
**What it does**:
- Checks 500+ common paths
- Uses 20 threads for fast scanning
- Outputs to console in color-coded format

### Full Recursive Crawl
```bash
python Anomalyze.py -u https://example.com --deep-scan --max-depth 3
```
**Features**:
- Follows links up to 3 levels deep
- Automatically discovers new paths
- Saves discovered paths to `discovered_paths.txt`

---

## Authentication Testing

### Admin Panel Discovery
```bash
python Anomalyze.py -u https://example.com -p /admin -p /wp-admin \
  -H "X-Forwarded-For: 127.0.0.1"
```

### Brute Force Protection Testing
```bash
python Anomalyze.py -u https://example.com/login \
  --data "username=admin&password=test" \
  --retry-codes 401:3,302:1
```
**Behavior**:
- Retries 3 times on 401 responses
- Retries once on 302 redirects

---

## API Security

### REST API Scanning
```bash
python Anomalyze.py -u https://api.example.com/v1 \
  -H "Accept: application/json" \
  --api-paths /users,/products,/admin
```

### GraphQL Endpoint Testing
```bash
python Anomalyze.py -u https://api.example.com/graphql \
  --graphql --query-file queries.gql \
  --detect-introspection
```

---

## Stealth Operations

### Slow Rate Scanning
```bash
python Anomalyze.py -u https://example.com \
  --delay random(2000-5000) \
  --throttle 5:30s
```
**Stealth Features**:
- Random delays between 2-5 seconds
- Pauses for 30s after every 5 requests

### Proxy Chain Rotation
```bash
python Anomalyze.py -u https://example.com \
  --proxy-rotation 10:3 \
  --proxy-list proxies.txt
```

---

## Bug Bounty Hunting

### Sensitive Data Discovery
```bash
python Anomalyze.py -u https://example.com \
  --sensitive-data-scan \
  --custom-patterns bounty_patterns.json
```

### Subdomain Enumeration Combo
```bash
subfinder -d example.com | python Anomalyze.py --stdin-mode \
  --quick-scan -o findings.json
```

---

## CI/CD Integration

### Jenkins Pipeline Integration
```groovy
stage('Security Scan') {
    steps {
        sh 'python Anomalyze.py -u ${WEBSITE_URL} -o json > scan.json'
        archiveArtifacts 'scan.json'
    }
}
```

### GitHub Actions Workflow
```yaml
- name: Run Anomalyze Scan
  run: |
    python Anomalyze.py -u "https://example.com" \
      --output-format sarif \
      --output-file scan.sarif
```

---

## Advanced Analysis

### Compare Two Scans
```bash
python utils/scan_diff.py old_scan.json new_scan.json
```

### Visualize Results
```bash
python Anomalyze.py -u https://example.com -o json \
  | python utils/visualizer.py --html report.html
```

---

## Pro Tips 💡

1. **Combine with Nuclei**:
   ```bash
   python Anomalyze.py -u https://example.com --discovered-urls \
     | nuclei -t ~/nuclei-templates/
   ```

2. **Monitor for Changes**:
   ```bash
   watch -n 3600 "python Anomalyze.py -u https://example.com \
     --compare-with baseline.json"
   ```

3. **Target Specific Tech**:
   ```bash
   python Anomalyze.py -u https://example.com \
     --tech-detect wordpress --wp-scan-mode
   ```

> **Note**: Always obtain proper authorization before scanning.  
> **Tip**: Use `--dry-run` to test configurations without sending actual requests.
