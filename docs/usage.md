# Basic Usage

```bash
python3 Anomalyze.py -u https://target.site
```

With no path options given, Anomalyze scans the built-in default path list
automatically.

## Common Options

| Option               | Description                                  | Default |
|-----------------------|----------------------------------------------|---------|
| `-u, --url`           | Base URL to scan                             | *required* |
| `-p, --path`          | Add custom path(s) to scan                   | None    |
| `--paths-file`        | File containing paths to test                | None    |
| `--default-paths`     | Enable built-in path dictionary              | Used automatically if no paths given |
| `--deep-scan`         | Follow links found in responses              | False   |
| `--max-depth`         | Maximum recursion depth                      | 2       |
| `-m, --method`        | HTTP method to use                           | GET     |
| `-H, --header`        | Add custom headers                           | None    |
| `-d, --data`          | Request body data                            | None    |
| `--params`            | Add query parameters                         | None    |
| `--cookie`            | Set the Cookie header                        | None    |
| `--user-agent`        | Custom User-Agent string                     | Random  |
| `-t, --threads`       | Number of concurrent threads                 | 10      |
| `-x, --proxy`         | Proxy server to use                          | None    |
| `--timeout`           | Request timeout in seconds                   | 15      |
| `--delay`             | Delay between requests (ms), or `random(min-max)` | 0  |
| `-o, --output`        | Output format: `json`, `csv`, or `both`      | json    |

See [Advanced Options](advanced_options.md) for the full reference, including
`--header-file`, `--proxy-list`, `--user-agent-file`, `--min-severity`,
`--patterns-file`, and `-k/--insecure`.

## Practical Examples

### Example 1: Basic Vulnerability Scan
```bash
python3 Anomalyze.py -u https://example.com --default-paths -t 20 -o both
```

### Example 2: Authenticated Scan
```bash
python3 Anomalyze.py -u https://example.com -H "Authorization: Bearer token123" --deep-scan
```

### Example 3: API Testing
```bash
python3 Anomalyze.py -u https://api.example.com/v1 -m POST --data '{"query":"test"}' --content-type "application/json"
```

More scenarios are in [Practical Examples](examples.md).

## Output Formats

### Console Output
Color-coded results with severity indicators:
- 🔴 Critical
- 🟠 High
- 🟡 Medium
- 🔵 Low
- ℹ️ Info

### JSON Report
```json
{
  "url": "https://example.com/admin",
  "status": 200,
  "findings": [
    {
      "type": "🔑 API Key",
      "match": "api_key",
      "location": "body"
    }
  ]
}
```

### CSV Report
```
URL,Status,Size,Time,Severity,Finding Type,Match,Location
https://example.com/admin,200,1024,0.45s,Critical,🔑 API Key,api_key,body
```

Full schema details are in [Output Formats](output.md).
