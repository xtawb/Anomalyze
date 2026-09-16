<p align="center">
  <img src="https://i.ibb.co/xS2vdM5q/2-logo.png" alt="Anomalyze Logo" width="150">
</p>

<h2 align="center">ＡＮＯＭＡＬＹＺＥ</h2>

<p align="center">
  <b>Detect anomalous server behaviors and potential vulnerabilities through customized HTTP request testing and response analysis.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/Version-1.1.0-red" alt="Version">
  <img src="https://img.shields.io/github/issues-closed/xtawb/Anomalyze">
</p>

### Anomalyze 🔍

## Overview

Anomalyze is a security analysis tool for penetration testers, security
researchers, and web developers, built for **authorized** testing of web
applications you own or have explicit permission to assess. It performs
comprehensive scanning of web applications to identify:

- Sensitive data exposure
- Hidden API endpoints
- Authentication vulnerabilities
- Information disclosure issues
- Server misconfigurations

The tool combines traditional directory brute-forcing with intelligent
response analysis, making it significantly more effective than conventional
scanners.

## Key Features

### 1. Comprehensive Path Discovery
- Built-in dictionary of common paths, or bring your own via `--paths-file`
- Custom path input support (`-p/--path`, repeatable)
- Recursive path discovery from HTML links, `<script>` tags, and JSON
  responses, opt-in via `--deep-scan` and bounded by `--max-depth`

### 2. Advanced Response Analysis
- **Content Inspection**: credit card patterns, API keys/tokens, credential
  patterns, PII
- **Header Analysis**: security header checks, server/tech-stack disclosure —
  matches header *values*, not header names, to avoid false positives
- **Custom Patterns**: rules live in `patterns.json`, overridable with
  `--patterns-file`

### 3. Performance Optimizations
- Multi-threaded architecture (`-t/--threads`)
- Persistent, connection-pooled `requests` session
- Configurable delay/backoff via `--delay` (fixed ms or `random(min-max)`)
- Content-type/size guards skip binary or oversized responses

### 4. Reporting Capabilities
- JSON and CSV output, color-coded console output
- Severity classification (Critical, High, Medium, Low, Info) with
  `--min-severity` filtering

## Where to Go Next

- [Installation](installation.md) — get Anomalyze running
- [Basic Usage](usage.md) — the essential command-line options
- [Advanced Options](advanced_options.md) — the full flag reference
- [Examples](examples.md) — real-world usage patterns
- [Output Formats](output.md) — JSON/CSV schema and severity levels
- [Architecture](architecture.md) — how the tool works internally

## Support and Contact

- GitHub Issues: [github.com/xtawb/Anomalyze/issues](https://github.com/xtawb/Anomalyze/issues)
- Contact: [linktr.ee/xtawb](https://linktr.ee/xtawb)

## Frequently Asked Questions

**Q: How is this different from dirbuster/gobuster?**
A: Anomalyze goes beyond simple directory brute-forcing by analyzing
responses for sensitive data and, with `--deep-scan`, automatically
discovering new paths from links in the response.

**Q: Is this tool safe to run on production systems?**
A: Always get proper authorization before scanning any system. Use
`-t/--threads`, `--delay`, and `--timeout` to control the load you put on a
target.

**Q: Can I extend the pattern matching?**
A: Yes — edit `patterns.json`, or point `--patterns-file` at your own JSON
file with the same structure. See
[Custom Detection Patterns](advanced_options.md#custom-detection-patterns).
