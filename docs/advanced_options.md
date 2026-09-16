# Advanced Usage Guide for Anomalyze 🛠️

*Unlocking Anomalyze's Full Potential*

## Table of Contents
1. [Full Option Reference](#full-option-reference)
2. [Deep / Recursive Scanning](#deep-recursive-scanning)
3. [Custom Request Manipulation](#custom-request-manipulation)
4. [Session Management](#session-management)
5. [Rate Limiting and Stealth](#rate-limiting-and-stealth)
6. [User-Agent and Proxy Rotation](#user-agent-and-proxy-rotation)
7. [Custom Detection Patterns](#custom-detection-patterns)
8. [Filtering Output](#filtering-output)
9. [Debugging & Troubleshooting](#debugging-and-troubleshooting)

---

## Full Option Reference

| Option               | Description                                        | Default |
|----------------------|-----------------------------------------------------|---------|
| `-u, --url`          | Target base URL                                     | *required* |
| `-p, --path`         | Add an individual path to test (repeatable)          | None    |
| `--paths-file`       | File containing paths to test, one per line          | None    |
| `--default-paths`    | Use the built-in list of common paths                | Used automatically if no paths are given |
| `--deep-scan`        | Follow links found in responses to discover new paths | False   |
| `--max-depth`        | Maximum recursion depth for `--deep-scan`             | 2       |
| `-m, --method`       | HTTP method                                           | GET     |
| `-H, --header`       | Add a custom header (`Header: Value`, repeatable)     | None    |
| `--header-file`      | JSON file of `{"Header": "Value"}` pairs to send      | None    |
| `-d, --data`         | Request body data                                     | None    |
| `--params`           | Add a query parameter (`key=value`, repeatable)       | None    |
| `--cookie`           | Raw `Cookie` header value                             | None    |
| `--content-type`     | Shorthand for `-H "Content-Type: <value>"`            | None    |
| `--user-agent`       | Custom User-Agent string                              | Random built-in browser UA |
| `--user-agent-file`  | File of User-Agent strings, rotated per request       | None    |
| `-t, --threads`      | Number of concurrent threads                          | 10      |
| `-x, --proxy`        | Single proxy server (`http://host:port`)              | None    |
| `--proxy-list`       | File of proxies, rotated per request                  | None    |
| `--timeout`          | Request timeout in seconds                            | 15      |
| `--delay`            | Delay between requests in ms, or `random(min-max)`    | 0       |
| `-k, --insecure`     | Skip TLS certificate verification                     | False   |
| `-o, --output`       | `json`, `csv`, or `both`                              | json    |
| `--min-severity`     | Only report findings at or above this severity        | Info    |
| `--patterns-file`    | Custom JSON detection-pattern file                     | `patterns.json` next to the script |
| `-v, --verbose`      | Print request errors and extra detail                 | False   |
| `--version`          | Print the tool version and exit                       | -       |

---

## Deep / Recursive Scanning

```bash
python Anomalyze.py -u https://target.com --deep-scan --max-depth 3
```
- Extracts links from `<a>`, `<script src>` and `<link href>` tags plus string
  values in JSON bodies.
- Only follows links whose host matches the scanned target.
- `--max-depth` caps how many hops from the original path list a discovered
  path can be before it's no longer followed further (depth 0 = paths you
  supplied or the default list).

---

## Custom Request Manipulation

### Header Injection
```bash
python Anomalyze.py -u https://target.com \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Original-URL: /admin" \
  --header-file custom_headers.json
```

`custom_headers.json`:
```json
{
  "Cache-Control": "no-cache",
  "X-Custom-Version": "1.2.0"
}
```
`-H` values override anything set by `--header-file` for the same header name.

### Request Body and Content Type
```bash
python Anomalyze.py -u https://api.target.com -m PUT \
  --data '{"status":"modified"}' \
  --content-type "application/json"
```

### Parameter Repetition
```bash
python Anomalyze.py -u https://target.com \
  --params "id=1" --params "id=2" --params "id=3"
```

---

## Session Management 🔐

### Cookies
```bash
python Anomalyze.py -u https://target.com --cookie "session=abc123"
```

### Bearer Tokens
```bash
python Anomalyze.py -u https://api.target.com \
  -H "Authorization: Bearer xyz789"
```

---

## Rate Limiting and Stealth ⏱️

```bash
# Fixed 500ms delay between every request
python Anomalyze.py -u https://target.com --delay 500

# Random delay between 500ms and 3s per request
python Anomalyze.py -u https://target.com --delay "random(500-3000)"
```
Combine with `-t 1` for fully sequential, low-noise scanning.

---

## User-Agent and Proxy Rotation

```bash
python Anomalyze.py -u https://target.com \
  --user-agent-file agents.txt \
  --proxy-list proxies.txt
```

`agents.txt` (one User-Agent per line):
```text
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36
Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
```

`proxies.txt` (one proxy URL per line):
```text
http://proxy1:8080
http://proxy2:8080
```
Without `--user-agent-file`, Anomalyze picks one random built-in browser
User-Agent for the whole run. Without `--proxy-list`, use `-x/--proxy` for a
single proxy for every request.

---

## Custom Detection Patterns

Anomalyze loads its sensitive-data patterns from `patterns.json` next to the
script. You can point it at your own file instead:

```bash
python Anomalyze.py -u https://target.com --patterns-file bounty_patterns.json
```

The file must follow the same shape as the bundled `patterns.json`:
```json
{
  "Critical": [
    ["\\bproprietary[_-]?key\\b", "🔑 Proprietary Key"]
  ]
}
```
Each entry is `[regex, description]`. Severities are `Critical`, `High`,
`Medium`, and `Low`; any severities you omit simply won't be checked.

---

## Filtering Output

```bash
# Only report Critical and High findings
python Anomalyze.py -u https://target.com --min-severity High
```

---

## Debugging and Troubleshooting

```bash
python Anomalyze.py -u https://target.com -v
```
`-v/--verbose` prints request-level errors (timeouts, connection failures,
TLS errors) as they happen instead of failing silently.

> **⚠️ Important**: Always obtain proper authorization before scanning a
> target you don't own or control.
> **📚 Documentation**: [anomalyze.readthedocs.io](https://anomalyze.readthedocs.io)
