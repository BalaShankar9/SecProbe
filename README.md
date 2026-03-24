# 🛡️ SecProbe — Security Testing Toolkit

A comprehensive, modular security testing tool built in Python for web application and network security assessments.

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)
![License MIT](https://img.shields.io/badge/License-MIT-green)

---

## ✨ Features

SecProbe includes **10 built-in scanner modules**:

| Scanner | Flag | Description |
|---------|------|-------------|
| **Port Scanner** | `ports` | TCP port scanning with service detection and banner grabbing |
| **SSL/TLS Scanner** | `ssl` | Certificate validation, protocol checks, cipher analysis |
| **Header Scanner** | `headers` | HTTP security header analysis (HSTS, CSP, X-Frame-Options, etc.) |
| **SQLi Scanner** | `sqli` | SQL injection testing (error-based, blind, time-based) |
| **XSS Scanner** | `xss` | Cross-Site Scripting detection (reflected, DOM-based) |
| **Directory Scanner** | `dirs` | Brute-force discovery of hidden directories and files |
| **DNS Scanner** | `dns` | Subdomain enumeration and DNS record analysis |
| **Cookie Scanner** | `cookies` | Cookie security flag analysis (Secure, HttpOnly, SameSite) |
| **CORS Scanner** | `cors` | Cross-Origin Resource Sharing misconfiguration testing |
| **Tech Scanner** | `tech` | Web technology fingerprinting and version detection |

### Report Formats
- **Console** — Color-coded terminal output with severity icons
- **HTML** — Beautiful dark-themed report with charts and details
- **JSON** — Machine-readable structured output

---

## 🚀 Installation

### Quick Start

```bash
# Clone / navigate to the project
cd STT

# Install dependencies
pip install -r requirements.txt

# Run directly
python -m secprobe example.com
```

### Install as CLI tool

```bash
pip install -e .
secprobe example.com
```

---

## 📖 Usage

### Basic Scan (all modules)

```bash
python -m secprobe example.com
```

### Select Specific Scanners

```bash
# Only HTTP headers and SSL
python -m secprobe example.com -s headers ssl

# Only port scanning with custom range
python -m secprobe example.com -s ports -p 1-65535 --threads 100

# Web vulnerability tests only
python -m secprobe example.com -s sqli xss cookies cors
```

### Generate Reports

```bash
# HTML report
python -m secprobe example.com -o html -f report.html

# JSON report
python -m secprobe example.com -o json -f results.json

# HTML report with all scanners
python -m secprobe example.com -s all -o html
```

### Advanced Options

```bash
# Rate-limited scanning (0.5s between requests)
python -m secprobe example.com -s sqli xss --rate-limit 0.5

# Custom user agent
python -m secprobe example.com --user-agent "MyBot/1.0"

# Custom wordlist for directory scanning
python -m secprobe example.com -s dirs --wordlist /path/to/wordlist.txt

# Disable color output (for piping)
python -m secprobe example.com --no-color

# Don't follow redirects
python -m secprobe example.com --no-redirect
```

---

## 🖥️ CLI Reference

```
usage: secprobe [-h] [-s SCANS [SCANS ...]] [-p PORTS] [-t THREADS]
                [--timeout TIMEOUT] [-o {console,json,html}] [-f FILE]
                [-v] [--no-color] [--rate-limit RATE_LIMIT]
                [--user-agent USER_AGENT] [--wordlist WORDLIST]
                [--no-redirect] [--version]
                target

Arguments:
  target                Target URL, hostname, or IP address

Options:
  -s, --scans           Scanner modules to run (default: all)
  -p, --ports           Port range (default: 1-1024)
  -t, --threads         Concurrent threads (default: 50)
  --timeout             Request timeout in seconds (default: 10)
  -o, --output          Report format: console, json, html
  -f, --file            Output file path
  -v, --verbose         Verbose output
  --no-color            Disable colors
  --rate-limit          Delay between requests (seconds)
  --user-agent          Custom User-Agent string
  --wordlist            Custom wordlist file for dir scanning
  --no-redirect         Don't follow HTTP redirects
  --version             Show version
```

---

## 📊 Severity Levels

| Level | Icon | Description |
|-------|------|-------------|
| **CRITICAL** | 🔴 | Exploitable vulnerability requiring immediate action |
| **HIGH** | 🟠 | Significant security issue that should be fixed soon |
| **MEDIUM** | 🟡 | Moderate risk that should be addressed |
| **LOW** | 🔵 | Minor issue or best practice recommendation |
| **INFO** | ℹ️ | Informational finding |

### Risk Scoring

SecProbe calculates a **risk score (0–100)** and assigns a **letter grade**:

| Score | Grade |
|-------|-------|
| 0 | A+ |
| 1–10 | A |
| 11–25 | B |
| 26–40 | C |
| 41–60 | D |
| 61–80 | E |
| 81–100 | F |

---

## 🏗️ Project Structure

```
STT/
├── secprobe/
│   ├── __init__.py          # Package metadata
│   ├── __main__.py          # Module entry point
│   ├── cli.py               # CLI argument parsing & orchestration
│   ├── config.py            # Configuration & constants
│   ├── models.py            # Data models (Finding, ScanResult)
│   ├── report.py            # Report generation (Console/HTML/JSON)
│   ├── utils.py             # Utilities & pretty printing
│   └── scanners/
│       ├── __init__.py      # Scanner registry
│       ├── base.py          # Base scanner class
│       ├── port_scanner.py  # Port scanning
│       ├── ssl_scanner.py   # SSL/TLS analysis
│       ├── header_scanner.py# HTTP header checks
│       ├── sqli_scanner.py  # SQL injection testing
│       ├── xss_scanner.py   # XSS detection
│       ├── directory_scanner.py  # Directory brute-force
│       ├── dns_scanner.py   # DNS enumeration
│       ├── cookie_scanner.py# Cookie analysis
│       ├── cors_scanner.py  # CORS testing
│       └── tech_scanner.py  # Technology detection
├── requirements.txt
├── setup.py
└── README.md
```

---

## ⚠️ Disclaimer

**This tool is intended for authorized security testing only.** Always obtain proper written permission before scanning any systems you do not own. Unauthorized scanning may violate laws and regulations. Use responsibly.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
