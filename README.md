# WEB3 — CSRF Attack/Replay Tool

CSRF token extraction, form replay, and auto-generation of CSRF payloads.

## Overview

This project implements a comprehensive CSRF testing tool that:
- Extracts CSRF tokens from forms and meta tags
- Analyzes token strength and identifies vulnerabilities
- Replays forms with custom data
- Auto-generates CSRF PoC HTML payloads
- Supports multiple bypass techniques (CORS, JSON content-type, Flash)

## Features

- **Token extraction**: Find hidden CSRF tokens in forms and meta tags
- **Token analysis**: Evaluate entropy, predictability, and strength
- **Form replay**: Replay captured forms with modified data
- **PoC generation**: Auto-generate HTML proof-of-concept files
- **Bypass techniques**: CORS misconfiguration, subdomain trust, content-type tricks

## Installation

```bash
pip install requests
```

## Usage

```bash
# Full analysis (analyze + forms + replay + generate)
python3 csrf_tool.py -u "http://target.com/form"

# Token analysis only
python3 csrf_tool.py -u "http://target.com/form" --action analyze

# Form extraction only
python3 csrf_tool.py -u "http://target.com/form" --action forms

# Replay form with custom data
python3 csrf_tool.py -u "http://target.com/form" --action replay --data "email=test@test.com"

# Generate PoC payloads
python3 csrf_tool.py -u "http://target.com/form" --action generate -o output/

# Generate bypass payloads
python3 csrf_tool.py -u "http://target.com/form" --action bypass

# Full scan with verbose output
python3 csrf_tool.py -u "http://target.com/form" --action all -v
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL |
| `-m, --method` | HTTP method: GET or POST |
| `-d, --data` | POST data (key=value&key2=value2) |
| `-c, --cookies` | Cookies (key=value;key2=value2) |
| `--header` | Custom header (repeatable) |
| `--timeout` | Request timeout in seconds |
| `--action` | Action: analyze, forms, replay, generate, bypass, all |
| `--replay-count` | Number of times to replay form |
| `-o, --output-dir` | Output directory for generated payloads |
| `-v, --verbose` | Verbose output |

## Example Output

```
  ╔══════════════════════════════════════════╗
  ║    WEB3 — CSRF Attack/Replay Tool        ║
  ║     Token Extraction & Payload Gen       ║
  ╚══════════════════════════════════════════╝

[*] Target: http://target.com/form

[*] Fetching page and extracting forms...
[*] Found 1 form(s)

  Form #1:
    Action: /form/submit
    Method: POST
    Fields: ['csrf_token', 'email', 'name', 'submit']
    CSRF Tokens: 1
      - csrf_token: a1b2c3d4e5f6g7h8i9j0... (strength: moderate)

[*] CSRF Token Analysis:

  Token: csrf_token
    Value: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6...
    Length: 32
    Entropy: 16
    Strength: moderate

[*] Replaying form #1...
  Status: 302
  Response: 0 bytes
  Redirected: True
  Redirect URL: http://target.com/success

[*] Generating CSRF payloads...
  Saved: output/csrf_poc.html
  Saved: output/csrf_bypass.html
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
