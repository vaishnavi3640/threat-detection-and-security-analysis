"""
Security scanner module for THREATGUARD.

Performs passive, read-only security checks:
  1. HTTPS availability
  2. HTTP security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options,
     Referrer-Policy, Permissions-Policy)
  3. Cookie security flags (Secure, HttpOnly, SameSite)
  4. HTTP → HTTPS redirect behaviour
  5. TLS certificate validity and expiry

All checks are non-intrusive and identical to what any browser would perform
when visiting the site.
"""
from __future__ import annotations

import ssl
import socket
import datetime
import requests
from urllib.parse import urlparse
from modules.risk_classifier import classify_finding, SECURITY_RULES

# Request timeout (seconds)
_TIMEOUT = 15
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; ThreatGuard/1.0; "
        "+https://github.com/threatguard/threatguard)"
    )
}


def run_security_scan(url: str) -> list[dict]:
    """
    Run all passive security checks on the given URL.

    Parameters
    ----------
    url : str  – fully-qualified URL (https://example.com)

    Returns
    -------
    list of finding dicts, each containing:
        finding_name, category, severity, confidence, evidence, impact, recommendation
    """
    findings: list[dict] = []

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    is_https = parsed.scheme == "https"

    # ── Fetch the page ────────────────────────────────────────────────────────
    try:
        response = requests.get(
            url,
            timeout=_TIMEOUT,
            headers=_HEADERS,
            allow_redirects=True,
            verify=True,
        )
        headers = response.headers
        cookies = response.cookies
        final_url = response.url
    except requests.exceptions.SSLError as exc:
        findings.append(_make_finding(
            "cert_self_signed",
            "TLS/SSL Certificate Error",
            f"SSL handshake failed: {str(exc)[:200]}",
        ))
        # Try again without verification to get headers
        try:
            response = requests.get(
                url, timeout=_TIMEOUT, headers=_HEADERS,
                allow_redirects=True, verify=False,
            )
            headers = response.headers
            cookies = response.cookies
            final_url = response.url
        except Exception:
            return findings
    except requests.exceptions.ConnectionError as exc:
        findings.append({
            "finding_name": "Connection Failed",
            "category": "security",
            "severity": "Informational",
            "confidence": "High",
            "evidence": f"Could not connect to {url}: {str(exc)[:200]}",
            "impact": "The website may be offline or blocking automated requests.",
            "recommendation": "Verify the URL is correct and the site is reachable.",
        })
        return findings
    except Exception as exc:
        findings.append({
            "finding_name": "Scan Error",
            "category": "security",
            "severity": "Informational",
            "confidence": "Low",
            "evidence": str(exc)[:200],
            "impact": "An unexpected error occurred during scanning.",
            "recommendation": "Retry the scan. If the issue persists, check the URL.",
        })
        return findings

    # ── 1. HTTPS availability ─────────────────────────────────────────────────
    if not is_https:
        findings.append(_make_finding(
            "no_https",
            "HTTPS Not Used",
            f"The URL uses HTTP (not HTTPS): {url}",
        ))

    # ── 2. HTTP → HTTPS redirect ──────────────────────────────────────────────
    if is_https:
        http_url = url.replace("https://", "http://", 1)
        try:
            http_resp = requests.get(
                http_url, timeout=_TIMEOUT, headers=_HEADERS,
                allow_redirects=False, verify=False,
            )
            location = http_resp.headers.get("Location", "")
            redirected_to_https = (
                http_resp.status_code in (301, 302, 307, 308) and
                location.startswith("https://")
            )
            if not redirected_to_https:
                findings.append(_make_finding(
                    "http_no_redirect",
                    "HTTP Not Redirected to HTTPS",
                    (
                        f"HTTP request returned status {http_resp.status_code} "
                        f"with Location: '{location}'. Expected a redirect to HTTPS."
                    ),
                ))
        except Exception:
            pass  # If we can't connect on HTTP, skip this check

    # ── 3. TLS certificate check ──────────────────────────────────────────────
    if is_https and hostname:
        cert_findings = _check_tls_certificate(hostname, parsed.port or 443)
        findings.extend(cert_findings)

    # ── 4. HTTP Security Headers ──────────────────────────────────────────────
    hdr = {k.lower(): v for k, v in headers.items()}

    if "strict-transport-security" not in hdr:
        findings.append(_make_finding(
            "no_hsts",
            "Missing HSTS Header",
            "Strict-Transport-Security header not present in response.",
        ))
    else:
        # Informational: found, show value
        findings.append({
            "finding_name": "HSTS Header Present",
            "category": "security",
            "severity": "Informational",
            "confidence": "High",
            "evidence": f"Strict-Transport-Security: {hdr['strict-transport-security']}",
            "impact": "HSTS is configured correctly.",
            "recommendation": "Ensure max-age is at least 31536000 (1 year) and includeSubDomains is set.",
        })

    if "content-security-policy" not in hdr:
        findings.append(_make_finding(
            "no_csp",
            "Missing Content-Security-Policy Header",
            "Content-Security-Policy header not present in response.",
        ))
    else:
        csp_val = hdr["content-security-policy"]
        # Check for unsafe-inline / unsafe-eval
        warnings = []
        if "'unsafe-inline'" in csp_val:
            warnings.append("'unsafe-inline' weakens XSS protection")
        if "'unsafe-eval'" in csp_val:
            warnings.append("'unsafe-eval' allows arbitrary code execution")
        note = "; ".join(warnings) if warnings else "CSP configured."
        findings.append({
            "finding_name": "Content-Security-Policy Present" + (" (Weak)" if warnings else ""),
            "category": "security",
            "severity": "Medium" if warnings else "Informational",
            "confidence": "High",
            "evidence": f"Content-Security-Policy: {csp_val[:300]}",
            "impact": note,
            "recommendation": "Remove 'unsafe-inline' and 'unsafe-eval' from CSP directives.",
        })

    if "x-content-type-options" not in hdr:
        findings.append(_make_finding(
            "no_x_content_type_options",
            "Missing X-Content-Type-Options Header",
            "X-Content-Type-Options header not present in response.",
        ))

    if "x-frame-options" not in hdr and "content-security-policy" not in hdr:
        findings.append(_make_finding(
            "no_x_frame_options",
            "Missing X-Frame-Options Header",
            "X-Frame-Options header not present in response.",
        ))

    if "referrer-policy" not in hdr:
        findings.append(_make_finding(
            "no_referrer_policy",
            "Missing Referrer-Policy Header",
            "Referrer-Policy header not present in response.",
        ))

    if "permissions-policy" not in hdr:
        findings.append(_make_finding(
            "permissions_policy_missing",
            "Missing Permissions-Policy Header",
            "Permissions-Policy header not present in response.",
        ))

    # ── 5. Cookie flags ───────────────────────────────────────────────────────
    cookie_findings = _check_cookies(response)
    findings.extend(cookie_findings)

    return findings


def _check_tls_certificate(hostname: str, port: int) -> list[dict]:
    """Check TLS certificate validity and expiry."""
    findings: list[dict] = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Expiry check
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (not_after - datetime.datetime.utcnow()).days
            if days_left < 0:
                findings.append(_make_finding(
                    "cert_expired",
                    "TLS Certificate Expired",
                    f"Certificate expired on {not_after_str} ({abs(days_left)} days ago).",
                ))
            elif days_left <= 30:
                findings.append(_make_finding(
                    "cert_expiring_soon",
                    "TLS Certificate Expiring Soon",
                    f"Certificate expires on {not_after_str} ({days_left} days remaining).",
                ))
            else:
                findings.append({
                    "finding_name": "TLS Certificate Valid",
                    "category": "security",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": f"Certificate valid until {not_after_str} ({days_left} days).",
                    "impact": "Certificate is valid and not expiring soon.",
                    "recommendation": "Set up auto-renewal to avoid future expiry.",
                })

        # Issuer check for self-signed
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer_org = issuer.get("organizationName", "")
        subject_org = subject.get("organizationName", "")
        if issuer_org and issuer_org == subject_org:
            findings.append(_make_finding(
                "cert_self_signed",
                "Possible Self-Signed Certificate",
                f"Issuer organisation '{issuer_org}' matches subject organisation.",
            ))

    except ssl.SSLCertVerificationError as exc:
        findings.append(_make_finding(
            "cert_self_signed",
            "TLS Certificate Verification Failed",
            f"SSL verification error: {str(exc)[:200]}",
        ))
    except Exception as exc:
        findings.append({
            "finding_name": "TLS Check Skipped",
            "category": "security",
            "severity": "Informational",
            "confidence": "Low",
            "evidence": f"Could not retrieve certificate: {str(exc)[:150]}",
            "impact": "TLS certificate details could not be verified.",
            "recommendation": "Ensure the site is reachable on port 443.",
        })

    return findings


def _check_cookies(response: requests.Response) -> list[dict]:
    """Check cookie security flags from Set-Cookie headers."""
    findings: list[dict] = []
    raw_cookies = response.headers.get_all("Set-Cookie") if hasattr(response.headers, "get_all") else []

    # Fallback: parse from raw headers
    if not raw_cookies:
        raw_cookies = [
            v for k, v in response.raw.headers.items()
            if k.lower() == "set-cookie"
        ]

    if not raw_cookies and not response.cookies:
        return findings  # No cookies set

    insecure = []
    no_httponly = []
    no_samesite = []

    for raw in raw_cookies:
        raw_lower = raw.lower()
        name = raw.split("=")[0].strip()
        if "secure" not in raw_lower:
            insecure.append(name)
        if "httponly" not in raw_lower:
            no_httponly.append(name)
        if "samesite" not in raw_lower:
            no_samesite.append(name)

    # Also check cookies from response.cookies (may differ)
    for cookie in response.cookies:
        name = cookie.name
        if not cookie.secure and name not in insecure:
            insecure.append(name)

    if insecure:
        rule = classify_finding("cookie_no_secure", "security")
        findings.append({
            "finding_name": "Cookies Missing Secure Flag",
            "category": "security",
            **rule,
            "evidence": f"Cookies without Secure flag: {', '.join(insecure[:10])}",
        })

    if no_httponly:
        rule = classify_finding("cookie_no_httponly", "security")
        findings.append({
            "finding_name": "Cookies Missing HttpOnly Flag",
            "category": "security",
            **rule,
            "evidence": f"Cookies without HttpOnly flag: {', '.join(no_httponly[:10])}",
        })

    if no_samesite:
        rule = classify_finding("cookie_no_samesite", "security")
        findings.append({
            "finding_name": "Cookies Missing SameSite Attribute",
            "category": "security",
            **rule,
            "evidence": f"Cookies without SameSite: {', '.join(no_samesite[:10])}",
        })

    return findings


def _make_finding(rule_key: str, finding_name: str, evidence: str) -> dict:
    """Create a finding dict from a rule key."""
    rule = classify_finding(rule_key, "security")
    return {
        "finding_name": finding_name,
        "category": "security",
        **rule,
        "evidence": evidence,
    }
