#### Method 1: From Source
```bash
git clone https://github.com/xtawb/Anomalyze.git
cd Anomalyze
python -m venv venv
source venv/bin/activate  # Linux/MacOS
# venv\Scripts\activate  # Windows
pip3 install -r requirements.txt
```

### Verification
```bash
python3 Anomalyze.py --help
python3 Anomalyze.py --version
```

### Optional: Development Install
To also run the test suite, install the dev requirements instead:
```bash
pip3 install -r requirements-dev.txt
pytest tests/ -v
```

## Usage Documentation

### Basic Usage
```bash
python3 Anomalyze.py -u https://target.site
```

### Advanced Options

#### Scan Configuration
| Option               | Description                                  | Default |
|----------------------|----------------------------------------------|---------|
| `-u, --url`          | Base URL to scan                             | *required* |
| `-p, --path`         | Add custom path(s) to scan                   | None    |
| `--paths-file`       | File containing paths to test                | None    |
| `--default-paths`    | Enable built-in path dictionary              | Used automatically if no paths given |
| `--deep-scan`        | Follow links found in responses              | False   |
| `--max-depth`        | Maximum recursion depth                      | 2       |

#### Request Configuration
| Option               | Description                                  | Default |
|----------------------|----------------------------------------------|---------|
| `-m, --method`       | HTTP method to use                           | GET     |
| `-H, --header`       | Add custom headers                           | None    |
| `-d, --data`         | Request body data                            | None    |
| `--params`           | Add query parameters                         | None    |
| `--cookie`           | Set cookie values                            | None    |
| `--user-agent`       | Custom User-Agent string                     | Random  |

#### Performance Options
| Option               | Description                                  | Default |
|----------------------|----------------------------------------------|---------|
| `-t, --threads`      | Number of concurrent threads                 | 10      |
| `-x, --proxy`        | Proxy server to use                          | None    |
| `--timeout`          | Request timeout in seconds                   | 15      |
| `--delay`            | Delay between requests (ms), or `random(min-max)` | 0  |

The complete list, including `--header-file`, `--proxy-list`,
`--user-agent-file`, `--min-severity`, `--patterns-file`, and
`-k/--insecure`, is in [Advanced Options](advanced_options.md).
