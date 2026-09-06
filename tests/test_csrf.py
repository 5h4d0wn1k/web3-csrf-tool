#!/usr/bin/env python3
"""Tests for WEB3 — CSRF Attack/Replay Tool.

Exercises the real detection engine against a vulnerable simulator (accepts
token-less state-changing POSTs) and a clean control simulator (rejects any
POST without a valid CSRF token). The engine uses the exact same HTTP path as
a live target.
"""

import sys
import os
import threading
import time
import unittest
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from csrf_tool import (
    CSRFTool, ScanConfig, FormParser,
    VulnTransferApp, CleanTransferApp, demo,
)


class _Server:
    def __init__(self, handler_cls):
        from http.server import HTTPServer
        self.server = HTTPServer(("127.0.0.1", 0), handler_cls)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.2)

    def url(self, path="/form"):
        return "http://127.0.0.1:{}{}".format(self.port, path)

    def shutdown(self):
        self.server.shutdown()


class TestCSRFFormParsing(unittest.TestCase):
    def test_parser_extracts_form_and_token(self):
        html = (
            '<form action="/transfer" method="POST">'
            '<input type="hidden" name="csrf_token" value="abc123">'
            '<input type="text" name="amount" value="5">'
            "</form>"
        )
        parser = FormParser()
        parser.feed(html)
        self.assertEqual(len(parser.forms), 1)
        form = parser.forms[0]
        self.assertEqual(form.method, "POST")
        self.assertEqual(form.action, "/transfer")
        self.assertEqual(len(form.csrf_tokens), 1)
        self.assertEqual(form.csrf_tokens[0].name, "csrf_token")


class TestCSRFVulnDetection(unittest.TestCase):
    """Engine must confirm absence of CSRF protection on the vulnerable app."""

    @classmethod
    def setUpClass(cls):
        cls.server = _Server(VulnTransferApp)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_token_extraction(self):
        tool = CSRFTool(ScanConfig(url=self.server.url(), timeout=5))
        tokens = tool.extract_csrf_tokens()
        self.assertTrue(tokens, "Should extract token from vulnerable app form")

    def test_token_strength_analysis(self):
        tool = CSRFTool(ScanConfig(url=self.server.url(), timeout=5))
        tokens = tool.extract_csrf_tokens()
        self.assertTrue(tokens)
        analysis = tool.analyze_token(tokens[0])
        self.assertIn("strength", analysis)
        self.assertTrue(analysis["length"] > 0)

    def test_assess_finds_unprotected(self):
        tool = CSRFTool(ScanConfig(url=self.server.url(), timeout=5, verbose=False))
        findings = tool.assess_csrf_protection()
        self.assertTrue(findings, "Should find and assess at least one form")
        unprotected = [f for f in findings if not f.protected]
        self.assertTrue(unprotected, "Vulnerable app form should be flagged as unprotected")
        self.assertEqual(unprotected[0].status_without_token, 200)


class TestCSRFCleanNoFalsePositive(unittest.TestCase):
    """Engine must NOT flag the clean (token-validating) app."""

    @classmethod
    def setUpClass(cls):
        cls.server = _Server(CleanTransferApp)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_assess_no_false_positive(self):
        tool = CSRFTool(ScanConfig(url=self.server.url(), timeout=5, verbose=False))
        findings = tool.assess_csrf_protection()
        self.assertTrue(findings)
        unprotected = [f for f in findings if not f.protected]
        self.assertEqual(unprotected, [], "Clean app should be marked protected")
        self.assertEqual(findings[0].status_without_token, 403)


class TestCSRFPayloadGeneration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _Server(VulnTransferApp)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_poc_contains_target_and_token(self):
        tool = CSRFTool(ScanConfig(url=self.server.url(), timeout=5))
        tool.extract_forms()
        poc = tool.generate_csrf_payload(0)
        self.assertIn("form action", poc)
        self.assertIn("csrf_token", poc)


class TestCSRFDemo(unittest.TestCase):
    def test_demo_vulnerable_exits_zero(self):
        result = subprocess.run(
            [sys.executable, "-c",
             "from csrf_tool import demo; demo(vulnerable=True)"],
            capture_output=True, text=True, timeout=30,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        self.assertEqual(result.returncode, 0,
                         "Vuln demo should exit 0. stderr: " + result.stderr[:500])

    def test_demo_clean_exits_zero(self):
        result = subprocess.run(
            [sys.executable, "-c",
             "from csrf_tool import demo; demo(vulnerable=False)"],
            capture_output=True, text=True, timeout=30,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        self.assertEqual(result.returncode, 0,
                         "Clean demo should exit 0. stderr: " + result.stderr[:500])


if __name__ == "__main__":
    unittest.main()