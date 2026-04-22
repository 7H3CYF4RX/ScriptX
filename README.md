# ScriptX - Advanced XSS Detection Tool

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

**ScriptX** is a comprehensive, Python-based XSS vulnerability scanner that leverages real browser engines (Firefox, Chrome, WebKit) to accurately detect Cross-Site Scripting vulnerabilities that traditional scanners miss.

## 🔥 Features

- **🌐 Multi-Browser Support** - Firefox, Chrome (Chromium), and WebKit
- **🔍 Deep Crawling** - Automatic site navigation with scope control
- **📝 Form Analysis** - GET/POST forms, hidden inputs, file uploads
- **🎯 Smart Detection** - Context-aware payload selection
- **🧬 DOM XSS** - Source-to-sink analysis with runtime monitoring
- **🛡️ WAF Bypass** - Encoding, case variation, polyglots
- **📸 Evidence Capture** - Screenshots and request/response logs
- **📊 Web Dashboard** - Real-time scanning interface
- **📄 Reports** - JSON and styled HTML reports

## 🚀 Quick Start

### Installation

```bash
# Clone or navigate to the directory
cd scriptx

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install
```

### Basic Usage

```bash
# Simple scan
python scriptx.py -u https://example.com

# Scan with Firefox in visible mode
python scriptx.py -u https://example.com -b firefox --headed

# Quick scan (no crawling)
python scriptx.py -u https://example.com --no-crawl

# Scan multiple URLs
python scriptx.py -l urls.txt

# Launch web dashboard
python scriptx.py -u https://example.com --dashboard
```

## 📖 Command Line Options

```
Usage: python scriptx.py [OPTIONS]

Target:
  -u, --url           Target URL to scan
  -l, --list          File containing URLs to scan

Browser:
  -b, --browser       Browser: firefox, chrome, webkit (default: chrome)
  --headless/--headed Run browser in headless mode (default: headless)

Crawling:
  --crawl/--no-crawl  Enable/disable crawling (default: enabled)
  --depth             Maximum crawl depth (default: 3)
  --scope             Crawl scope: domain, subdomain, all (default: domain)

Scanning:
  --mode              XSS mode: all, reflected, stored, dom (default: all)
  --payloads          Custom payload file
  --waf-bypass        Enable WAF bypass techniques (default: enabled)
  --delay             Delay between requests in ms (default: 100)

Output:
  -o, --output        Output format: json, html, all (default: json)
  --output-dir        Output directory (default: ./output)
  --screenshots       Capture vulnerability screenshots (default: enabled)
  -v, --verbose       Verbose output

Dashboard:
  --dashboard         Start web dashboard
  --port              Dashboard port (default: 8888)

Other:
  --proxy             Proxy server (e.g., http://127.0.0.1:8080)
  --cookies           Cookies file (JSON) or cookie string
  --user-agent        Custom User-Agent
  --timeout           Page timeout in ms (default: 30000)
```

## 📊 Example Usage

### Scan with All Options

```bash
python scriptx.py \
  -u https://testsite.com \
  -b firefox \
  --headed \
  --depth 3 \
  --mode all \
  --waf-bypass \
  -o html \
  --screenshots \
  -v
```

### Authenticated Scan with Cookies

```bash
# Save cookies to JSON file
echo '[{"name":"session","value":"abc123","domain":"example.com"}]' > cookies.json

# Scan with cookies
python scriptx.py -u https://example.com --cookies cookies.json
```

### Scan Through Proxy (Burp Suite)

```bash
python scriptx.py -u https://example.com --proxy http://127.0.0.1:8080
```

### Use Custom Payloads

```bash
python scriptx.py -u https://example.com --payloads custom_payloads.txt
```

## 🎯 Detection Capabilities

### Reflected XSS
- URL parameter injection
- Form input injection
- Context-aware payload selection
- Browser-verified execution (alert capture)

### Stored XSS
- Automatic storage form identification
- Payload tracking with unique markers
- Cross-page verification
- Multi-output page checking

### DOM-based XSS
- Static source-sink analysis
- Runtime sink monitoring
- Hash fragment injection
- Query parameter injection
- window.name / referrer injection

## 📁 Project Structure

```
scriptx/
├── scriptx.py              # Main CLI entry point
├── requirements.txt        # Dependencies
├── README.md               # This file
│
├── core/                   # Core modules
│   ├── browser.py          # Playwright browser controller
│   ├── scanner.py          # Main scanner orchestrator
│   └── config.py           # Configuration management
│
├── crawler/                # Crawling modules
│   ├── crawler.py          # Web crawler
│   ├── form_finder.py      # Form discovery
│   ├── link_extractor.py   # Link extraction
│   └── dom_analyzer.py     # DOM analysis
│
├── xss/                    # XSS detection modules
│   ├── detector.py         # XSS orchestrator
│   ├── reflected.py        # Reflected XSS
│   ├── stored.py           # Stored XSS
│   ├── dom_xss.py          # DOM XSS
│   └── payloads.py         # Payload engine
│
├── utils/                  # Utilities
│   ├── logger.py           # Rich logging
│   ├── reporter.py         # Report generation
│   └── helpers.py          # Helper functions
│
├── dashboard/              # Web dashboard
│   ├── app.py              # Flask app
│   └── templates/
│       └── index.html      # Dashboard UI
│
└── output/                 # Scan results
    ├── screenshots/
    ├── scriptx_results.json
    └── scriptx_report.html
```

## 🔧 Configuration

You can also use a configuration file:

```json
{
  "browser_type": "chromium",
  "headless": true,
  "crawl_enabled": true,
  "max_depth": 3,
  "scan_mode": "all",
  "waf_bypass": true,
  "request_delay": 100,
  "output_format": "json",
  "screenshots": true
}
```

Load with:
```python
from core.config import Config
config = Config.from_file('config.json')
```

## 🧪 Testing

Test against intentionally vulnerable applications:

- **DVWA** (Damn Vulnerable Web Application)
- **bWAPP**
- **XSS Game** (Google)
- **HackTheBox** machines

## 📝 Output Example

### JSON Report
```json
{
  "target": "https://example.com",
  "scan_time": 45.23,
  "xss": {
    "summary": {
      "total": 3,
      "reflected": 2,
      "stored": 1,
      "dom": 0
    },
    "vulnerabilities": {
      "reflected": [
        {
          "url": "https://example.com/search",
          "param": "q",
          "payload": "<script>alert(1)</script>",
          "method": "GET",
          "severity": "high"
        }
      ]
    }
  }
}
```

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper authorization before scanning any website. Unauthorized access to computer systems is illegal.

The developers are not responsible for any misuse of this tool.

## 📄 License

MIT License - See LICENSE for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests.

---

<p align="center">
  <b>ScriptX</b> - Advanced XSS Detection with Browser Control
</p>
