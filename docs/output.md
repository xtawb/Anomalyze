# Anomalyze Output System 📊

## Table of Contents
1. [Output Formats](#output-formats)
2. [Console Output](#console-output)
3. [File Output](#file-output)
4. [Severity Classification](#severity-classification)
5. [Customizing Output](#customizing-output)
6. [Output Examples](#output-examples)
7. [Integrating with Other Tools](#integrating-with-other-tools)

---

## Output Formats

Anomalyze supports multiple output formats:

| Format | Command Option | Best For |
|--------|----------------|----------|
| **Console (Color)** | Default | Real-time monitoring |
| **JSON** | `-o json` | Tool integration |
| **CSV** | `-o csv` | Spreadsheet analysis |
| **SARIF** | `-o sarif` | GitHub Code Scanning |
| **HTML** | `-o html` | Visual reports |

---

## Console Output

### Standard View
```plaintext
[+] https://example.com/admin
   Status: 403 | Size: 1.2KB | Time: 0.23s
   🔴 CRITICAL: Admin portal accessible (403 may indicate protection)

[+] https://example.com/.git/config
   Status: 200 | Size: 0.3KB | Time: 0.15s
   🟠 HIGH: Git config exposed (contains repository details)
```

### Verbose Mode (`-v`)
```plaintext
[DEBUG] Request to /admin
   Headers: {'User-Agent': 'Anomalyze/1.0'}
   Response Time: 230ms
   Cookies: session=abc123
```

---

## File Output

### JSON Output Example
```json
{
  "scan_metadata": {
    "target": "https://example.com",
    "timestamp": "2024-03-15T14:30:00Z",
    "duration": "00:02:45"
  },
  "results": [
    {
      "url": "https://example.com/admin",
      "status": 403,
      "size": 1254,
      "response_time": 0.23,
      "findings": [
        {
          "type": "Admin Portal Access",
          "severity": "High",
          "match": "Admin Dashboard",
          "location": "title_tag"
        }
      ]
    }
  ]
}
```

### CSV Output Structure
```csv
URL,Status,Size,Time,Severity,Type,Match,Location
https://example.com/admin,403,1254,0.23,High,Admin Portal,Admin Dashboard,title
https://example.com/.env,200,342,0.12,Critical,Env File,DB_PASSWORD=secret,body
```

---

## Severity Classification

| Level | Color | Icon | Criteria |
|-------|-------|------|----------|
| **Critical** | 🔴 Red | 🚨 | Direct security impacts (credentials, RCE) |
| **High** | 🟠 Orange | ⚠️ | Sensitive data exposure |
| **Medium** | 🟡 Yellow | 🔍 | Security misconfigurations |
| **Low** | 🔵 Blue | ℹ️ | Informational findings |
| **Info** | ⬜ White | 📝 | General observations |

---

## Customizing Output

### Filtering Results
```bash
# Only show Critical findings
python Anomalyze.py -u https://example.com --min-severity Critical

# Exclude info-level results
python Anomalyze.py -u https://example.com --exclude-info
```

### Output Templates
Create `custom_template.json`:
```json
{
  "template": "{url} | {status} | {severity}",
  "color_rules": {
    "200": "green",
    "403": "yellow",
    "500": "red"
  }
}
```
Usage:
```bash
python Anomalyze.py -u https://example.com --template custom_template.json
```

---

## Output Examples

### SARIF Output (for GitHub)
```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Anomalyze",
          "version": "1.0.0"
        }
      },
      "results": [
        {
          "ruleId": "ANOM-1001",
          "level": "error",
          "message": {
            "text": "Exposed admin portal"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "https://example.com/admin"
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

### HTML Report Sample
```html
<div class="finding critical">
  <h3>https://example.com/.env</h3>
  <div class="details">
    <span class="severity">CRITICAL</span>
    <span class="type">Environment File Exposure</span>
    <pre>DB_PASSWORD=secret123</pre>
  </div>
</div>
```

---

## Integrating with Other Tools

### 1. Import to Splunk
```bash
python Anomalyze.py -u https://example.com -o json | curl -d @- https://splunk:8088/services/collector
```

### 2. JIRA Integration
```bash
python Anomalyze.py -u https://example.com -o json | python utils/jira_integration.py --project SEC
```

### 3. Elasticsearch Indexing
```bash
python Anomalyze.py -u https://example.com -o json | /usr/share/logstash/bin/logstash -f anom.conf
```

---

## Pro Tips 🛠️

1. **Continuous Monitoring**:
   ```bash
   watch -n 3600 "python Anomalyze.py -u https://example.com -o json --compare previous_scan.json"
   ```

2. **Dashboard Integration**:
   ```bash
   python Anomalyze.py -u https://example.com -o json | python utils/grafana_push.py
   ```

3. **PDF Reports**:
   ```bash
   python Anomalyze.py -u https://example.com -o json | pandoc -o report.pdf
   ```

> **Note**: All output files are saved in `./anomalyze_reports/` by default  
> **Tip**: Use `--output-dir` to specify custom save locations
