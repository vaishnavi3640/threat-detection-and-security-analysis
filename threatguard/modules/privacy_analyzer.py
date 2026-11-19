"""
Privacy analyzer module for THREATGUARD.

Performs passive, read-only privacy checks:
  1. First-party and third-party cookie identification
  2. Third-party request/domain detection from page content
  3. Known analytics, advertising, social and fingerprinting domain matching
  4. Privacy-policy page detection
  5. Basic privacy disclosure keyword checks

All checks are non-intrusive and use only publicly observable information.

IMPORTANT: Detecting an external request does NOT confirm tracking.
           Only resources matching the known tracker domain list are
           classified as likely tracking. All findings are labelled
           with appropriate confidence levels.
"""
from __future__ import annotations

import json
import os
import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from modules.risk_classifier import classify_finding

_TIMEOUT = 15
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; ThreatGuard/1.0; "
        "+https://github.com/threatguard/threatguard)"
    )
}

# Load tracker domain list
_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
_TRACKER_FILE = os.path.join(_DATA_DIR, "tracker_domains.json")

try:
    with open(_TRACKER_FILE, "r", encoding="utf-8") as f:
        _TRACKER_DOMAINS: dict[str, list[str]] = json.load(f)
except Exception:
    _TRACKER_DOMAINS = {}

_ALL_TRACKERS: set[str] = set()
for _domains in _TRACKER_DOMAINS.values():
    _ALL_TRACKERS.update(_domains)

# Privacy policy indicator keywords
_PRIVACY_KEYWORDS = [
    "privacy policy", "privacy notice", "data protection",
    "gdpr", "personal data", "data we collect", "how we use your data",
    "cookie policy", "data retention", "your rights", "opt-out",
    "data controller", "data processor", "third party",
]

# Common privacy policy page URL patterns
_PRIVACY_URL_PATTERNS = [
    r"/privacy",
    r"/privacy-policy",
    r"/privacypolicy",
    r"/privacy_policy",
    r"/legal/privacy",
    r"/policies/privacy",
    r"/cookie",
    r"/data-protection",
    r"/gdpr",
]


def run_privacy_scan(url: str) -> list[dict]:
    """
    Run all passive privacy checks on the given URL.

    Returns
    -------
    list of finding dicts
    """
    findings: list[dict] = []

    parsed = urlparse(url)
    base_domain = parsed.hostname or ""

    # ── Fetch the page ────────────────────────────────────────────────────────
    try:
        response = requests.get(
            url, timeout=_TIMEOUT, headers=_HEADERS,
            allow_redirects=True, verify=False,
        )
        html = response.text
        cookies = response.cookies
    except Exception as exc:
        findings.append({
            "finding_name": "Privacy Scan Error",
            "category": "privacy",
            "severity": "Informational",
            "confidence": "Low",
            "evidence": f"Could not fetch page for privacy analysis: {str(exc)[:200]}",
            "impact": "Privacy checks could not be completed.",
            "recommendation": "Verify the URL is accessible and retry.",
        })
        return findings

    soup = BeautifulSoup(html, "html.parser")

    # ── 1. Cookie analysis ────────────────────────────────────────────────────
    first_party: list[str] = []
    third_party: list[str] = []

    for cookie in cookies:
        cookie_domain = cookie.domain.lstrip(".")
        if cookie_domain and base_domain and not base_domain.endswith(cookie_domain):
            third_party.append(f"{cookie.name} ({cookie.domain})")
        else:
            first_party.append(cookie.name)

    if third_party:
        rule = classify_finding("external_requests_detected", "privacy")
        findings.append({
            "finding_name": "Third-Party Cookies Detected",
            "category": "privacy",
            "severity": "Medium",
            "confidence": "High",
            "evidence": f"Third-party cookies: {', '.join(third_party[:10])}",
            "impact": (
                "Third-party cookies can track users across multiple websites "
                "and build behavioural profiles."
            ),
            "recommendation": (
                "Audit and minimise third-party cookies. Implement a cookie consent "
                "banner if cookies are used for non-essential purposes."
            ),
        })

    if first_party:
        findings.append({
            "finding_name": "First-Party Cookies Present",
            "category": "privacy",
            "severity": "Informational",
            "confidence": "High",
            "evidence": f"First-party cookies: {', '.join(first_party[:10])}",
            "impact": "First-party cookies are generally acceptable for site functionality.",
            "recommendation": "Ensure session cookies are cleared when the user logs out.",
        })

    # ── 2 & 3. External domain and tracker detection ──────────────────────────
    external_domains: set[str] = set()
    tracker_hits: dict[str, list[str]] = {}  # category → [domains]

    # Scan src attributes in script, img, iframe, link tags
    for tag in soup.find_all(["script", "img", "iframe", "link", "source"]):
        src = tag.get("src") or tag.get("href") or ""
        if not src:
            continue
        abs_src = urljoin(url, src)
        try:
            tag_host = urlparse(abs_src).hostname or ""
        except Exception:
            continue

        if not tag_host:
            continue

        # Is it external?
        if tag_host and base_domain and not tag_host.endswith(base_domain):
            external_domains.add(tag_host)

            # Match against tracker list
            for category, domains in _TRACKER_DOMAINS.items():
                for tracked in domains:
                    if tag_host == tracked or tag_host.endswith("." + tracked):
                        tracker_hits.setdefault(category, [])
                        if tag_host not in tracker_hits[category]:
                            tracker_hits[category].append(tag_host)

    # Also check inline script content for known tracker patterns
    for script in soup.find_all("script"):
        script_text = script.string or ""
        for category, domains in _TRACKER_DOMAINS.items():
            for d in domains:
                if d in script_text:
                    tracker_hits.setdefault(category, [])
                    if d not in tracker_hits[category]:
                        tracker_hits[category].append(d + " (inline script)")

    if external_domains:
        findings.append({
            "finding_name": "External Resources Detected",
            "category": "privacy",
            **classify_finding("external_requests_detected", "privacy"),
            "evidence": (
                f"{len(external_domains)} external domain(s) detected: "
                f"{', '.join(list(external_domains)[:8])}"
            ),
        })

    # Emit a finding per tracker category
    if "analytics" in tracker_hits:
        rule = classify_finding("third_party_analytics", "privacy")
        findings.append({
            "finding_name": "Third-Party Analytics Detected",
            "category": "privacy",
            **rule,
            "evidence": (
                f"Likely analytics resources from: "
                f"{', '.join(tracker_hits['analytics'][:6])}"
            ),
        })

    if "advertising" in tracker_hits:
        rule = classify_finding("third_party_advertising", "privacy")
        findings.append({
            "finding_name": "Advertising / Tracking Scripts Detected",
            "category": "privacy",
            **rule,
            "evidence": (
                f"Likely advertising resources from: "
                f"{', '.join(tracker_hits['advertising'][:6])}"
            ),
        })

    if "social" in tracker_hits:
        rule = classify_finding("third_party_social", "privacy")
        findings.append({
            "finding_name": "Social Media Widgets Detected",
            "category": "privacy",
            **rule,
            "evidence": (
                f"Social media resources from: "
                f"{', '.join(tracker_hits['social'][:6])}"
            ),
        })

    if "fingerprinting" in tracker_hits:
        rule = classify_finding("third_party_fingerprinting", "privacy")
        findings.append({
            "finding_name": "Browser Fingerprinting Script Detected",
            "category": "privacy",
            **rule,
            "evidence": (
                f"Fingerprinting resources from: "
                f"{', '.join(tracker_hits['fingerprinting'][:6])}"
            ),
        })

    # ── 4. Privacy policy detection ───────────────────────────────────────────
    privacy_page_found = False
    privacy_page_url = ""

    # Check all anchor tags
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].lower()
        link_text = a_tag.get_text(strip=True).lower()

        if any(re.search(p, href) for p in _PRIVACY_URL_PATTERNS):
            privacy_page_found = True
            privacy_page_url = urljoin(url, a_tag["href"])
            break

        if any(kw in link_text for kw in ["privacy", "privacy policy", "data protection"]):
            privacy_page_found = True
            privacy_page_url = urljoin(url, a_tag["href"])
            break

    if not privacy_page_found:
        # Try fetching /privacy-policy directly
        for path in ["/privacy-policy", "/privacy", "/privacy_policy"]:
            try:
                test_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                r = requests.get(
                    test_url, timeout=8, headers=_HEADERS,
                    allow_redirects=True, verify=False,
                )
                if r.status_code == 200 and len(r.text) > 500:
                    privacy_page_found = True
                    privacy_page_url = test_url
                    break
            except Exception:
                pass

    if not privacy_page_found:
        rule = classify_finding("no_privacy_policy", "privacy")
        findings.append({
            "finding_name": "Privacy Policy Page Not Found",
            "category": "privacy",
            **rule,
            "evidence": "No privacy policy link or page found on the homepage or common paths.",
        })
    else:
        # ── 5. Privacy disclosure keyword check ───────────────────────────────
        try:
            priv_resp = requests.get(
                privacy_page_url, timeout=10, headers=_HEADERS,
                allow_redirects=True, verify=False,
            )
            priv_text = priv_resp.text.lower()
            found_kws = [kw for kw in _PRIVACY_KEYWORDS if kw in priv_text]
            missing_kws = [kw for kw in _PRIVACY_KEYWORDS[:6] if kw not in priv_text]

            if len(found_kws) >= 4:
                findings.append({
                    "finding_name": "Privacy Policy Detected",
                    "category": "privacy",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": (
                        f"Privacy policy found at: {privacy_page_url}. "
                        f"Keywords present: {', '.join(found_kws[:6])}"
                    ),
                    "impact": "A privacy policy is present, which is a positive indicator.",
                    "recommendation": "Ensure the policy is kept up to date and covers all data practices.",
                })
            else:
                rule = classify_finding("privacy_policy_incomplete", "privacy")
                findings.append({
                    "finding_name": "Privacy Policy May Be Incomplete",
                    "category": "privacy",
                    **rule,
                    "evidence": (
                        f"Privacy policy found at: {privacy_page_url}, "
                        f"but fewer than 4 required keywords were found. "
                        f"Missing: {', '.join(missing_kws)}"
                    ),
                })
        except Exception:
            findings.append({
                "finding_name": "Privacy Policy Detected (Unverified)",
                "category": "privacy",
                "severity": "Informational",
                "confidence": "Medium",
                "evidence": f"Privacy policy link found at: {privacy_page_url} (content not verified).",
                "impact": "A privacy policy page link exists.",
                "recommendation": "Ensure the privacy policy is complete and regularly updated.",
            })

    return findings
