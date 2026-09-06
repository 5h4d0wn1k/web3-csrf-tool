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
# No third-party dependencies required - Python standard library only.
# The optional `requests` package transparently upgrades the HTTP stack:
pip install requests
```

## Usage

```bash
# Offline demo: full engine against the built-in vulnerable simulator (exit 0)
python3 csrf_tool.py --demo

# Offline demo: clean control simulator (must also exit 0, no findings)
python3 csrf_tool.py --demo --clean

# CSRF protection assessment (default action)
python3 csrf_tool.py -u "http://127.0.0.1:<port>/form"

# Token analysis only
python3 csrf_tool.py -u "http://127.0.0.1:<port>/form" --action analyze

# Form extraction only
python3 csrf_tool.py -u "http://127.0.0.1:<port>/form" --action forms

# Replay form with custom data
python3 csrf_tool.py -u "http://127.0.0.1:<port>/form" --action replay --data "email=admin@example.com"

# Generate PoC payloads
python3 csrf_tool.py -u "http://127.0.0.1:<port>/form" --action generate -o output/

# Generate bypass payloads
python3 csrf_tool.py -u "http://127.0.0.1:<port>/form" --action bypass

# Full assessment with verbose output
python3 csrf_tool.py -u "http://127.0.0.1:<port>/form" --action all -v
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
| `--action` | Action: analyze, forms, assess, replay, generate, bypass, all |
| `--replay-count` | Number of times to replay form |
| `-o, --output-dir` | Output directory for generated payloads |
| `-v, --verbose` | Verbose output |
| `--demo` | Run offline demo against the built-in simulator |
| `--clean` | With `--demo`: use the clean control simulator |

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

## Running the Demo and Tests

The tool ships with two built-in simulators (stdlib `http.server`):

- **Vulnerable** — a bank-transfer form whose POST handler **never validates the CSRF
  token**; a token-less replay is accepted with HTTP 200.
- **Clean** — the same form but the handler **rejects** any submission without a valid
  token (HTTP 403).

`--demo` runs the full detection engine (`extract_forms` → token analysis →
`assess_csrf_protection` → PoC generation) against these simulators over loopback,
using the exact same code path as a live target.

```bash
python3 -m unittest discover -s tests -v
```

## Live Lab Test Plan

Test only against targets in your own lab (e.g. a deliberately vulnerable app running
on 127.0.0.1 or 192.0.2.x RFC-5737 space):

1. Deploy a lab app with a POST form that lacks CSRF protection.
2. Confirm baseline: `python3 csrf_tool.py -u "http://127.0.0.1:<port>/form" --action forms -v`
3. Run assessment: `python3 csrf_tool.py -u "http://127.0.0.1:<port>/form" --action assess`
   and confirm the form is flagged as unprotected.
4. Repeat against the same app with server-side token validation and confirm it is
   reported as protected.
5. Document target, form action, token evidence, and replay status codes in your
   lab report.

## Metrics

- **Video metric**: 60-second screencast of `python3 csrf_tool.py --demo` reporting
  the unprotected form, plus `python3 -m unittest discover -s tests -v`, recorded on
  the lab-only loopback target.
- **Pass rate**: all unit tests green; demo exit 0 on both vulnerable and clean
  simulators.

## License

MIT
