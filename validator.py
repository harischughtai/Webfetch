"""
URL Validator — SSRF Protection Layer
--------------------------------------
Validates URLs before fetching to prevent Server-Side Request Forgery.
Blocks private IPs, cloud metadata endpoints, dangerous file types,
and non-HTTP schemes.
"""

import ipaddress
import socket
from urllib.parse import urlparse


class URLValidationError(Exception):
    """Raised when a URL fails security validation."""
    pass


# Dangerous file extensions that should never be fetched
BLOCKED_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".sh", ".ps1",
    ".dll", ".so", ".dylib",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".bin", ".iso", ".dmg",
    ".apk", ".deb", ".rpm",
}

# Allowed URL schemes
ALLOWED_SCHEMES = {"http", "https"}


def is_safe_url(url: str) -> bool:
    """
    Check if a URL is safe to fetch.
    Returns True if safe, raises URLValidationError if not.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        raise URLValidationError(f"Malformed URL: {url}")

    # 1. Scheme check — only HTTP/HTTPS allowed
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise URLValidationError(
            f"Blocked scheme '{parsed.scheme}'. Only HTTP/HTTPS allowed."
        )

    # 2. Must have a hostname
    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("URL has no hostname.")

    # 3. Block dangerous file extensions
    path_lower = parsed.path.lower()
    for ext in BLOCKED_EXTENSIONS:
        if path_lower.endswith(ext):
            raise URLValidationError(
                f"Blocked file extension '{ext}'. Dangerous file type."
            )

    # 4. Resolve hostname to IP and check for private/reserved ranges
    _check_hostname_safety(hostname)

    return True


def _check_hostname_safety(hostname: str) -> None:
    """
    Resolve hostname to IP address(es) and verify none are
    private, loopback, link-local, or reserved.
    """
    # Direct IP address check (no DNS needed)
    try:
        ip = ipaddress.ip_address(hostname)
        _validate_ip(ip, hostname)
        return
    except ValueError:
        pass  # Not a raw IP, proceed to DNS resolution

    # DNS resolution
    try:
        addr_infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
    except socket.gaierror:
        raise URLValidationError(f"Cannot resolve hostname: {hostname}")

    if not addr_infos:
        raise URLValidationError(f"No DNS records for: {hostname}")

    # Check ALL resolved IPs (DNS can return multiple)
    for family, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
            _validate_ip(ip, hostname)
        except ValueError:
            continue


def _validate_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, hostname: str) -> None:
    """Check if an IP address is in a blocked range."""

    # Loopback (127.0.0.0/8, ::1)
    if ip.is_loopback:
        raise URLValidationError(
            f"SSRF blocked: '{hostname}' resolves to loopback ({ip})"
        )

    # Private ranges (10.x, 172.16-31.x, 192.168.x)
    if ip.is_private:
        raise URLValidationError(
            f"SSRF blocked: '{hostname}' resolves to private IP ({ip})"
        )

    # Link-local (169.254.x.x — includes cloud metadata endpoint)
    if ip.is_link_local:
        raise URLValidationError(
            f"SSRF blocked: '{hostname}' resolves to link-local ({ip}). "
            f"This includes cloud metadata endpoints (169.254.169.254)."
        )

    # Reserved ranges
    if ip.is_reserved:
        raise URLValidationError(
            f"SSRF blocked: '{hostname}' resolves to reserved IP ({ip})"
        )

    # Unspecified (0.0.0.0, ::)
    if ip.is_unspecified:
        raise URLValidationError(
            f"SSRF blocked: '{hostname}' resolves to unspecified ({ip})"
        )

    # Multicast
    if ip.is_multicast:
        raise URLValidationError(
            f"SSRF blocked: '{hostname}' resolves to multicast ({ip})"
        )
