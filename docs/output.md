# Anomalyze Output System 📊

## Table of Contents
1. [Output Formats](#output-formats)
2. [Console Output](#console-output)
3. [File Output](#file-output)
4. [Severity Classification](#severity-classification)
5. [Filtering Output](#filtering-output)
6. [Piping to Other Tools](#piping-to-other-tools)

---

## Output Formats

| Format | Command Option | Best For |
|--------|----------------|----------|
| **Console (color)** | Default | Real-time monitoring |
| **JSON** | `-o json` (default) | Tool integration, scripting |
| **CSV** | `-o csv` | Spreadsheet analysis |
| **Both** | `-o both` | Save JSON and CSV together |

Report files are written to the current directory as
`anomalyze_report_<unix-timestamp>.json` and/or `.csv`.

---

## Console Output

Each scanned URL prints a severity line, a result table, and (if anything was
found) a findings table:

```text
🔴 Critical
+--------+------------------------------+
| Field  | Value                        |
+--------+------------------------------+
| URL    | https://example.com/.env     |
| Status | 200                          |
| Size   | 342 bytes                    |
| Time   | 0.12s                        |
+--------+------------------------------+

Sensitive Data Found:
+--------------------------+-------------------+----------+
| Type                     | Match             | Location |
+--------------------------+-------------------+----------+
| 🔒 Sensitive Credential  | password          | body     |
+--------------------------+-------------------+----------+
```

Run with `-v/--verbose` to also see request-level errors (timeouts,
connection failures) as they occur.

---

## File Output

### JSON Report Structure
```json
[
  {
    "url": "https://example.com/admin",
    "status": 200,
    "size": 1024,
    "time": "0.45s",
    "severity": "Critical",
    "findings": [
      {
        "type": "🔑 API Key",
        "match": "api_key",
        "location": "body"
      }
    ]
  }
]
```

- `location` is `"body"` for content matches, or `"header:<Header-Name>"`
  when the match came from a response header (e.g. `"header:X-Powered-By"`).
- `match` is the literal substring the pattern matched, truncated to 50
  characters in the console table but stored in full in the JSON/CSV report.

### CSV Report Structure
```csv
URL,Status,Size,Time,Severity,Finding Type,Match,Location
https://example.com/admin,200,1024,0.45s,Critical,🔑 API Key,api_key,body
```
Rows with no findings still appear, with the finding columns left blank, so
every scanned URL is represented in the report.

---

## Severity Classification

| Level | Color | Icon | Criteria |
|-------|-------|------|----------|
| **Critical** | Red (bright) | 🔴 | Credentials, secrets, SQL errors, credit cards, private keys |
| **High** | Red | 🟠 | Admin/auth endpoints, PII, cloud credentials |
| **Medium** | Yellow | 🟡 | Config/backup files, internal documents |
| **Low** | Green | 🔵 | Server/tech-stack disclosure |
| **Info** | Blue | ℹ️ | No sensitive pattern matched |

Severities and patterns are defined in `patterns.json`; see
[Custom Detection Patterns](advanced_options.md#custom-detection-patterns)
to extend or replace them.

---

## Filtering Output

```bash
# Only report Critical and High findings
python Anomalyze.py -u https://example.com --min-severity High
```

---

## Piping to Other Tools

Since JSON output is just a file, it composes with standard tooling instead
of needing a dedicated integration flag:

```bash
# Extract Critical findings with jq
jq '.[] | select(.severity == "Critical")' anomalyze_report_*.json

# Feed discovered 200-status paths into another scanner
jq -r '.[] | select(.status == 200) | .url' anomalyze_report_*.json
```
