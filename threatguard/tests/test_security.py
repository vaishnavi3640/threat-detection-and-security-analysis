"""
Tests for the security scanner module.

Uses mock HTTP responses to test detection logic without making real network calls.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from unittest.mock import patch, MagicMock
from modules.security_scanner import run_security_scan


def _make_response(
    status_code=200,
    headers=None,
    cookies=None,
    url="https://example.com",
    text="<html><body>Test</body></html>",
    ssl_error=False,
):
    """Factory for mock requests.Response objects."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers or {}
    mock_resp.cookies = cookies or MagicMock()
    mock_resp.cookies.__iter__ = MagicMock(return_value=iter([]))
    mock_resp.url = url
    mock_resp.text = text
    # Simulate raw headers
    mock_resp.raw = MagicMock()
    mock_resp.raw.headers = MagicMock()
    mock_resp.raw.headers.items = MagicMock(return_value=[])
    return mock_resp


class TestHTTPSDetection(unittest.TestCase):
    """Test case 1: HTTP-only website → no_https finding."""

    @patch("modules.security_scanner.requests.get")
    def test_http_site_flags_no_https(self, mock_get):
        mock_get.return_value = _make_response(url="http://example.com")
        findings = run_security_scan("http://example.com")
        names = [f["finding_name"] for f in findings]
        self.assertIn("HTTPS Not Used", names, "Expected 'HTTPS Not Used' finding for HTTP site.")

    @patch("modules.security_scanner.requests.get")
    def test_https_site_no_https_finding(self, mock_get):
        """Test case 2: HTTPS website → no no_https finding."""
        mock_get.return_value = _make_response(
            url="https://example.com",
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            }
        )
        findings = run_security_scan("https://example.com")
        names = [f["finding_name"] for f in findings]
        self.assertNotIn("HTTPS Not Used", names, "Should not flag HTTPS site as missing HTTPS.")


class TestSecurityHeaders(unittest.TestCase):
    """Test cases for security header detection."""

    @patch("modules.security_scanner.requests.get")
    def test_missing_hsts(self, mock_get):
        """Test case 3: Missing HSTS → no_hsts finding."""
        mock_get.return_value = _make_response(
            url="https://example.com",
            headers={}  # No HSTS
        )
        findings = run_security_scan("https://example.com")
        names = [f["finding_name"] for f in findings]
        self.assertIn("Missing HSTS Header", names)

    @patch("modules.security_scanner.requests.get")
    def test_missing_csp(self, mock_get):
        """Test case 4: Missing CSP → no_csp finding."""
        mock_get.return_value = _make_response(
            url="https://example.com",
            headers={"Strict-Transport-Security": "max-age=31536000"}
        )
        findings = run_security_scan("https://example.com")
        names = [f["finding_name"] for f in findings]
        self.assertIn("Missing Content-Security-Policy Header", names)

    @patch("modules.security_scanner.requests.get")
    def test_all_headers_present(self, mock_get):
        """Test case 5: All headers present → no missing-header findings."""
        mock_get.return_value = _make_response(
            url="https://example.com",
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            }
        )
        findings = run_security_scan("https://example.com")
        names = [f["finding_name"] for f in findings]
        self.assertNotIn("Missing HSTS Header", names)
        self.assertNotIn("Missing Content-Security-Policy Header", names)
        self.assertNotIn("Missing X-Content-Type-Options Header", names)


class TestCookieSecurity(unittest.TestCase):
    """Test cases for cookie security flags."""

    @patch("modules.security_scanner.requests.get")
    def test_cookie_missing_secure_flag(self, mock_get):
        """Test case 6: Cookie without Secure flag."""
        mock_resp = _make_response(url="https://example.com")
        # Mock raw headers with a cookie missing Secure
        mock_resp.raw.headers.items = MagicMock(return_value=[
            ("set-cookie", "sessionid=abc123; HttpOnly; SameSite=Lax")
        ])
        mock_get.return_value = mock_resp
        findings = run_security_scan("https://example.com")
        names = [f["finding_name"] for f in findings]
        self.assertIn("Cookies Missing Secure Flag", names)

    @patch("modules.security_scanner.requests.get")
    def test_cookie_missing_httponly_flag(self, mock_get):
        """Test case 7: Cookie without HttpOnly flag."""
        mock_resp = _make_response(url="https://example.com")
        mock_resp.raw.headers.items = MagicMock(return_value=[
            ("set-cookie", "sessionid=abc123; Secure; SameSite=Lax")
        ])
        mock_get.return_value = mock_resp
        findings = run_security_scan("https://example.com")
        names = [f["finding_name"] for f in findings]
        self.assertIn("Cookies Missing HttpOnly Flag", names)


class TestFindingStructure(unittest.TestCase):
    """Validate that findings have the required fields."""

    @patch("modules.security_scanner.requests.get")
    def test_finding_has_required_fields(self, mock_get):
        """All findings must have required fields."""
        mock_get.return_value = _make_response(url="https://example.com", headers={})
        findings = run_security_scan("https://example.com")
        required_fields = {"finding_name", "category", "severity", "confidence", "evidence", "impact", "recommendation"}
        for f in findings:
            for field in required_fields:
                self.assertIn(field, f, f"Finding missing field: {field}")

    @patch("modules.security_scanner.requests.get")
    def test_severity_values_valid(self, mock_get):
        """Severity must be one of the five defined levels."""
        mock_get.return_value = _make_response(url="https://example.com", headers={})
        valid_severities = {"Critical", "High", "Medium", "Low", "Informational"}
        findings = run_security_scan("https://example.com")
        for f in findings:
            self.assertIn(f["severity"], valid_severities,
                          f"Invalid severity '{f['severity']}' in finding '{f['finding_name']}'")


if __name__ == "__main__":
    unittest.main(verbosity=2)
