# Anomalyze Architecture Overview 🏗️

```mermaid
graph TD
    A[User] --> B[CLI Interface]
    B --> C[Core Engine]
    C --> D[Module Manager]
    D --> E[Scanning Modules]
    D --> F[Analysis Modules]
    C --> G[Output Handler]
    G --> H[Formatters]
    C --> I[Concurrency Manager]
```

## Table of Contents
1. [Core Components](#core-components)
2. [Data Flow](#data-flow)
3. [Module System](#module-system)
4. [Concurrency Model](#concurrency-model)
5. [Security Design](#security-design)
6. [Performance Considerations](#performance-considerations)
7. [Extension Points](#extension-points)

---

## Core Components

### 1. CLI Interface
- **Argument Parser**: Handles 50+ command-line options
- **Configuration Loader**: Merges CLI args with config files
- **Health Checker**: Validates dependencies and network

### 2. Core Engine
```python
class AnomalyzeEngine:
    def __init__(self):
        self.scanner = Scanner()
        self.analyzer = ResponseAnalyzer()
        self.reporter = ReportGenerator()
    
    def run_scan(self):
        while queue.has_tasks():
            url = queue.get()
            response = scanner.fetch(url)
            findings = analyzer.process(response)
            reporter.save(findings)
```

### 3. Module Manager
- **Dynamic Loading**: Hot-loads modules at runtime
- **Dependency Resolution**: Handles module requirements
- **Lifecycle Hooks**: Pre-scan, per-request, post-scan

---

## Data Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Engine
    participant Scanner
    participant Analyzer
    participant Reporter
    
    User->>CLI: python Anomalyze.py -u https://example.com
    CLI->>Engine: Initialize config
    Engine->>Scanner: Queue scan tasks
    Scanner->>Engine: HTTP responses
    Engine->>Analyzer: Pass responses
    Analyzer->>Engine: Findings list
    Engine->>Reporter: Generate output
    Reporter-->>User: Console/file reports
```

### Key Data Structures
1. **Scan Task Queue**: Priority queue for URLs
2. **Finding Object**:
   ```typescript
   interface Finding {
       type: string;
       severity: 'Critical'|'High'|'Medium'|'Low';
       match: string;
       location: 'header'|'body'|'url';
       context?: string;
   }
   ```
3. **Config Schema**: JSON schema for validation

---

## Module System

### Built-in Modules
| Module | Purpose | Hook Points |
|--------|---------|-------------|
| **PathFinder** | Directory brute-forcing | pre-scan, task-gen |
| **SensitiveData** | Pattern matching | response-analysis |
| **LinkExtractor** | Hyperlink discovery | post-response |
| **HeaderAnalyzer** | Security header checks | response-analysis |

### Custom Module Example
```python
from anomalye import Module

class CryptoScanner(Module):
    def setup(self):
        self.patterns = [
            r'-----BEGIN RSA PRIVATE KEY-----'
        ]
    
    def process_response(self, response):
        findings = []
        for pattern in self.patterns:
            if re.search(pattern, response.text):
                findings.append(Finding(
                    type="Crypto Key Exposure",
                    severity="Critical"
                ))
        return findings
```

---

## Concurrency Model

### Thread Pool Architecture
```mermaid
graph LR
    A[Main Thread] --> B[Task Scheduler]
    B --> C[Worker Thread 1]
    B --> D[Worker Thread 2]
    B --> E[...]
    C --> F[Network Stack]
    D --> F
```

- **Dynamic Thread Scaling**: Adjusts based on response times
- **Work Stealing**: Balances load between threads
- **Circuit Breaker**: Stops flood after 5 consecutive errors

### Rate Limiting
- **Adaptive Throttling**:
  ```python
  if response.status == 429:
      self.delay *= 1.5
  elif response.status == 200:
      self.delay = max(100, self.delay * 0.9)
  ```

---

## Security Design

### Protection Mechanisms
1. **Input Sanitization**:
   - URL canonicalization
   - Header injection prevention
2. **Safe Defaults**:
   - 10 req/sec limit
   - No automatic POST data
3. **Privacy Controls**:
   - Clears sensitive data from memory
   - Optional request anonymization

### Audit Trail
```json
{
  "audit_log": {
    "timestamp": "2024-03-15T12:00:00Z",
    "target": "https://example.com",
    "config_hash": "a1b2c3d4",
    "user": "security_team"
  }
}
```

---

## Performance Considerations

### Optimization Techniques
1. **Connection Pooling**: Reuses HTTP(S) connections
2. **Pattern Cache**: Compiled regex persistence
3. **Selective Parsing**:
   ```python
   if 'text/html' in content_type:
       parse_links(response)
   elif 'json' in content_type:
       parse_json(response)
   ```

### Resource Limits
| Resource | Default Limit | Configurable |
|----------|---------------|--------------|
| Threads | 10 | Yes (--threads) |
| Memory | 512MB | Yes (--max-memory) |
| Scan Depth | 2 | Yes (--max-depth) |

---

## Extension Points

### 1. Plugins System
```bash
python Anomalyze.py --load-plugin ./plugins/custom_scanner.py
```

### 2. Webhook Integration
```yaml
webhooks:
  - event: "critical_finding"
    url: "https://alerts.example.com"
    method: "POST"
```

### 3. API Mode
```python
from anomalye import AnomalyzeAPI

scanner = AnomalyzeAPI()
results = scanner.scan(
    targets=["https://example.com"],
    modules=["sql_injection", "xss"]
)
```

---

## Deployment Architecture

```mermaid
graph TB
    A[Anomalyze CLI] --> B[Local Machine]
    A --> C[CI/CD Pipeline]
    A --> D[Cloud Runner]
    D --> E[Distributed Workers]
    E --> F[Central Results DB]
```

> **Note**: All components are designed for containerization with Docker/K8s support
