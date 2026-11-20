"""
URL and input validation utilities for THREATGUARD.
"""
import re
from urllib.parse import urlparse


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
    except Exception as exc:
        return False, f"URL parsing failed: {exc}"

    # Scheme check
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"Unsupported scheme '{parsed.scheme}'. Only http and https are supported."

    # Hostname must exist
    host = parsed.hostname or ""
    if not host:
        return False, "No hostname found in the URL."

    # Block private / loopback addresses
    if host in _BLOCKED_HOSTS:
        return False, f"Scanning '{host}' is not permitted (loopback / private address)."

    if any(host.startswith(prefix) for prefix in _BLOCKED_PREFIXES):
        return False, f"Scanning '{host}' is not permitted (private IP range)."

    # Basic hostname syntax check
    hostname_re = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    if not hostname_re.match(host) and not _is_valid_ipv4(host):
        return False, f"'{host}' does not appear to be a valid hostname."

    return True, url


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
