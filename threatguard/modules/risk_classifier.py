"""
Risk classifier – deterministic rule-based severity and confidence assignment.

Severity levels : Critical | High | Medium | Low | Informational
Confidence levels: High | Medium | Low

Rules are based on OWASP, Mozilla Observatory and industry guidelines.
The AI layer must NEVER override these values.
"""
from __future__ import annotations

# ── Severity penalty table (used by scoring_engine) ──────────────────────────
SEVERITY_PENALTIES: dict[str, float] = {
    "Critical": 25.0,
    "High": 15.0,
    "Medium": 8.0,
    "Low": 3.0,
    "Informational": 0.0,
}

# ── Static rule definitions ───────────────────────────────────────────────────
# Each rule maps a finding key → (severity, confidence, impact, recommendation)
SECURITY_RULES: dict[str, dict] = {
    "no_https": {
        "severity": "Critical",
        "confidence": "High",
        "impact": (
            "All data transmitted between the browser and server is unencrypted. "
            "Attackers on the same network can intercept credentials, session tokens "
            "and personal information (man-in-the-middle attack)."
        ),
        "recommendation": (
            "Obtain a free TLS certificate from Let's Encrypt and configure your "
            "web server to serve all content over HTTPS. Redirect all HTTP traffic "
            "to HTTPS with a 301 permanent redirect."
        ),
    },
    "no_hsts": {
        "severity": "High",
        "confidence": "High",
        "impact": (
            "Without HTTP Strict Transport Security, browsers may allow HTTP "
            "connections even after visiting the site over HTTPS. This enables "
            "SSL-stripping attacks."
        ),
        "recommendation": (
            "Add the response header: "
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
    },
    "no_csp": {
        "severity": "High",
        "confidence": "High",
        "impact": (
            "Without Content-Security-Policy, the site is vulnerable to Cross-Site "
            "Scripting (XSS) attacks. Malicious scripts can steal session cookies, "
            "redirect users or deface the page."
        ),
        "recommendation": (
            "Define a Content-Security-Policy header that whitelists trusted sources "
            "for scripts, styles and other resources. Start with: "
            "Content-Security-Policy: default-src 'self'"
        ),
    },
    "no_x_content_type_options": {
        "severity": "Medium",
        "confidence": "High",
        "impact": (
            "Browsers may MIME-sniff responses and execute non-script content as "
            "scripts, enabling content-injection attacks."
        ),
        "recommendation": (
            "Add the response header: X-Content-Type-Options: nosniff"
        ),
    },
    "no_x_frame_options": {
        "severity": "Medium",
        "confidence": "High",
        "impact": (
            "Without X-Frame-Options, the site can be embedded in an iframe on a "
            "malicious page, enabling clickjacking attacks that trick users into "
            "performing unintended actions."
        ),
        "recommendation": (
            "Add the response header: X-Frame-Options: DENY  "
            "(or SAMEORIGIN if you need to embed your own frames)."
        ),
    },
    "no_referrer_policy": {
        "severity": "Low",
        "confidence": "High",
        "impact": (
            "Without a Referrer-Policy header, the full URL (including path and "
            "query parameters) is sent as the Referer header to third-party sites, "
            "potentially leaking sensitive information."
        ),
        "recommendation": (
            "Add the response header: Referrer-Policy: strict-origin-when-cross-origin"
        ),
    },
    "cookie_no_secure": {
        "severity": "High",
        "confidence": "High",
        "impact": (
            "Cookies without the Secure flag can be transmitted over unencrypted "
            "HTTP connections, allowing interception of session tokens."
        ),
        "recommendation": (
            "Set the Secure attribute on all cookies: Set-Cookie: name=value; Secure"
        ),
    },
    "cookie_no_httponly": {
        "severity": "Medium",
        "confidence": "High",
        "impact": (
            "Cookies without the HttpOnly flag are accessible to JavaScript. If an "
            "XSS vulnerability exists, attackers can steal session cookies."
        ),
        "recommendation": (
            "Set the HttpOnly attribute on all session and authentication cookies: "
            "Set-Cookie: name=value; HttpOnly"
        ),
    },
    "cookie_no_samesite": {
        "severity": "Medium",
        "confidence": "Medium",
        "impact": (
            "Cookies without SameSite may be sent with cross-site requests, enabling "
            "Cross-Site Request Forgery (CSRF) attacks."
        ),
        "recommendation": (
            "Set SameSite=Lax or SameSite=Strict on cookies: "
            "Set-Cookie: name=value; SameSite=Lax"
        ),
    },
    "http_no_redirect": {
        "severity": "High",
        "confidence": "High",
        "impact": (
            "The site does not redirect HTTP requests to HTTPS. Users who visit "
            "the HTTP version receive content over an unencrypted connection."
        ),
        "recommendation": (
            "Configure your web server to issue a 301 redirect from HTTP to HTTPS "
            "for all requests."
        ),
    },
    "cert_expired": {
        "severity": "Critical",
        "confidence": "High",
        "impact": (
            "The TLS certificate has expired. Browsers will show a security warning "
            "and block access. Users who bypass the warning are exposed to "
            "man-in-the-middle attacks."
        ),
        "recommendation": (
            "Renew the TLS certificate immediately. Consider using Let's Encrypt "
            "with auto-renewal (certbot)."
        ),
    },
    "cert_expiring_soon": {
        "severity": "Medium",
        "confidence": "High",
        "impact": (
            "The TLS certificate expires within 30 days. If not renewed, browsers "
            "will block access and display security warnings."
        ),
        "recommendation": (
            "Renew the TLS certificate before it expires. Enable auto-renewal if "
            "using Let's Encrypt."
        ),
    },
    "cert_self_signed": {
        "severity": "High",
        "confidence": "High",
        "impact": (
            "Self-signed certificates are not trusted by browsers. Users see "
            "security warnings, reducing trust and potentially exposing them to "
            "man-in-the-middle attacks."
        ),
        "recommendation": (
            "Replace the self-signed certificate with one issued by a trusted "
            "Certificate Authority (CA) such as Let's Encrypt."
        ),
    },
    "permissions_policy_missing": {
        "severity": "Low",
        "confidence": "High",
        "impact": (
            "Without a Permissions-Policy header, browser features such as "
            "camera, microphone and geolocation may be accessible to embedded "
            "third-party content."
        ),
        "recommendation": (
            "Add a Permissions-Policy header to restrict access to browser APIs: "
            "Permissions-Policy: geolocation=(), microphone=(), camera=()"
        ),
    },
}

PRIVACY_RULES: dict[str, dict] = {
    "no_privacy_policy": {
        "severity": "High",
        "confidence": "High",
        "impact": (
            "Users cannot understand how their data is collected, used or shared. "
            "This may also violate GDPR, CCPA and other privacy regulations, "
            "resulting in significant fines."
        ),
        "recommendation": (
            "Create and publish a clear privacy policy page. Link to it in your "
            "site footer. Consult a legal professional for regulatory compliance."
        ),
    },
    "third_party_analytics": {
        "severity": "Medium",
        "confidence": "High",
        "impact": (
            "Third-party analytics services collect user behaviour data, IP "
            "addresses and browsing patterns. This data is shared with the "
            "analytics provider and may be used for profiling."
        ),
        "recommendation": (
            "Disclose analytics usage in your privacy policy. Consider using a "
            "privacy-respecting alternative (e.g., Plausible, Fathom) or "
            "configure consent management."
        ),
    },
    "third_party_advertising": {
        "severity": "High",
        "confidence": "High",
        "impact": (
            "Advertising trackers build detailed profiles of user behaviour across "
            "many websites. This is a significant privacy risk for visitors."
        ),
        "recommendation": (
            "Disclose all advertising partners in your privacy policy. Implement "
            "a cookie consent banner for GDPR compliance. Consider reducing "
            "reliance on behavioural advertising."
        ),
    },
    "third_party_social": {
        "severity": "Low",
        "confidence": "Medium",
        "impact": (
            "Social media widgets can track users who are not logged in to those "
            "platforms and share data with them without explicit consent."
        ),
        "recommendation": (
            "Use privacy-respecting social share buttons that do not load third-party "
            "resources until the user clicks them (click-to-activate approach)."
        ),
    },
    "third_party_fingerprinting": {
        "severity": "High",
        "confidence": "High",
        "impact": (
            "Fingerprinting scripts collect device characteristics to uniquely "
            "identify users without cookies, bypassing most privacy controls."
        ),
        "recommendation": (
            "Remove fingerprinting scripts. If fraud detection requires them, "
            "disclose their use prominently in your privacy policy and consider "
            "consent-based activation."
        ),
    },
    "privacy_policy_incomplete": {
        "severity": "Low",
        "confidence": "Medium",
        "impact": (
            "The privacy policy page was detected but may lack required disclosures "
            "about data collection, retention and user rights."
        ),
        "recommendation": (
            "Review your privacy policy against GDPR Article 13 / 14 requirements. "
            "Ensure it covers data controller identity, purposes, retention periods "
            "and user rights (access, deletion, portability)."
        ),
    },
    "external_requests_detected": {
        "severity": "Informational",
        "confidence": "Medium",
        "impact": (
            "The page loads resources from external domains. Each external request "
            "reveals the visitor's IP address to that domain."
        ),
        "recommendation": (
            "Audit all external resources. Self-host fonts, scripts and stylesheets "
            "where possible to reduce information sharing with third parties."
        ),
    },
}


def classify_finding(rule_key: str, category: str = "security") -> dict:
    """
    Look up the static rule for a finding and return classification data.

    Parameters
    ----------
    rule_key : str
        The key into SECURITY_RULES or PRIVACY_RULES.
    category : str
        'security' or 'privacy'.

    Returns
    -------
    dict with keys: severity, confidence, impact, recommendation
    """
    rules = SECURITY_RULES if category == "security" else PRIVACY_RULES
    rule = rules.get(rule_key, {})
    return {
        "severity": rule.get("severity", "Informational"),
        "confidence": rule.get("confidence", "Low"),
        "impact": rule.get("impact", "No impact information available."),
        "recommendation": rule.get("recommendation", "No recommendation available."),
    }
