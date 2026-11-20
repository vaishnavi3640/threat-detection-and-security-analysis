"""
URL and input validation utilities for THREATGUARD.
"""
import re
import os
import ipaddress
import socket
import requests
from urllib.parse import urljoin, urlparse


ALLOWED_SCHEMES = {"http", "https"}

# Private / loopback / link-local ranges that must not be scanned
_BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
}
_BLOCKED_PREFIXES = (
    "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.",
)


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate a user-supplied URL.

    Returns
    -------
    (True, normalised_url)  if the URL is acceptable.
    (False, error_message)  if the URL is rejected.
    """
    url = url.strip()

    # Prepend scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        port = parsed.port
    except Exception as exc:
        return False, f"URL parsing failed: {exc}"

    # Scheme check
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"Unsupported scheme '{parsed.scheme}'. Only http and https are supported."

    # Hostname must exist
    host = parsed.hostname or ""
    if not host:
        return False, "No hostname found in the URL."
    if parsed.username or parsed.password:
        return False, "URLs containing embedded usernames or passwords are not accepted."

    # Development-only exception for the bundled demo server. It is bound to
    # loopback and fixed to one port; all other local/private targets remain blocked.
    if _is_enabled_demo_target(parsed):
        return True, url

    # Block private / loopback addresses
    if host in _BLOCKED_HOSTS:
        return False, f"Scanning '{host}' is not permitted (loopback / private address)."

    if any(host.startswith(prefix) for prefix in _BLOCKED_PREFIXES):
        return False, f"Scanning '{host}' is not permitted (private IP range)."

    try:
        if _is_ip(host):
            addresses = {ipaddress.ip_address(host)}
        else:
            addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, port or (443 if parsed.scheme == "https" else 80))}
    except (OSError, ValueError):
        return False, "The website host could not be resolved."
    if not addresses or any(not address.is_global for address in addresses):
        return False, "Private, local, and reserved network addresses cannot be scanned."

    # Basic hostname syntax check
    hostname_re = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    if not hostname_re.match(host) and not _is_valid_ipv4(host):
        return False, f"'{host}' does not appear to be a valid hostname."

    return True, url


def _is_enabled_demo_target(parsed) -> bool:
    """Allow only the local demo origin when explicitly enabled in development."""
    return (
        os.environ.get("APP_ENV", "").strip().lower() in {"dev", "development"}
        and os.environ.get("THREATGUARD_LOCAL_DEMO", "").strip() == "1"
        and parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and parsed.port == 8765
        and not parsed.username
        and not parsed.password
    )


def safe_get(url: str, *, max_redirects: int = 5, **kwargs) -> requests.Response:
    """GET an HTTP(S) URL, validating each redirect destination before use."""
    kwargs.pop("allow_redirects", None)
    current = url
    for _ in range(max_redirects + 1):
        valid, normalized = validate_url(current)
        if not valid:
            raise ValueError(normalized)
        response = requests.get(normalized, allow_redirects=False, **kwargs)
        response.url = normalized
        if response.status_code not in (301, 302, 303, 307, 308):
            return response
        location = response.headers.get("Location")
        if not location:
            return response
        current = urljoin(normalized, location)
    raise ValueError("The website redirected too many times.")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_valid_ipv4(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def sanitise_url(url: str) -> str:
    """Return a normalised URL (strips trailing slash, lowercases scheme+host)."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    normalised = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path.rstrip('/')}"
    if parsed.query:
        normalised += f"?{parsed.query}"
    return normalised
