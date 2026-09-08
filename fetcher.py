"""
SafeFetcher — Core Async Web Fetcher
--------------------------------------
Fetches web pages asynchronously with:
- Pre-flight SSRF validation
- Streaming response with size cap
- Post-redirect URL re-validation
- Content-type filtering
- HTML sanitization
"""

import asyncio
import time
from dataclasses import dataclass, field

import aiohttp

from .sanitizer import clean_html
from .validator import URLValidationError, is_safe_url


# Content types we'll process
TEXT_CONTENT_TYPES = {
    "text/html",
    "text/plain",
    "text/markdown",
    "text/csv",
    "application/json",
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
}


@dataclass
class FetchResult:
    """Result of a URL fetch operation."""
    url: str
    final_url: str
    status: int
    content_type: str
    text: str
    byte_count: int
    fetch_time_ms: float
    was_redirected: bool
    error: str | None = None


@dataclass
class SafeFetcher:
    """
    Production-grade web fetcher with security protections.
    
    Usage:
        fetcher = SafeFetcher()
        result = await fetcher.fetch("https://example.com")
        print(result.text)
    """
    max_size_bytes: int = 5_000_000       # 5MB
    timeout_seconds: int = 15
    max_redirects: int = 5
    user_agent: str = "SafeFetch/1.0 (LLM-Agent-Tool)"
    max_text_length: int = 50_000         # Max chars after cleaning
    blocked_extensions: set = field(default_factory=lambda: {
        ".exe", ".msi", ".bat", ".cmd", ".sh", ".ps1",
        ".dll", ".so", ".dylib", ".zip", ".tar", ".gz",
    })

    async def fetch(self, url: str) -> dict:
        """
        Fetch a URL safely with all protections enabled.
        Returns a dict with text, status, metadata, or error.
        """
        start_time = time.time()

        # Step 1: Pre-flight URL validation (SSRF check)
        try:
            is_safe_url(url)
        except URLValidationError as e:
            return self._error_result(url, str(e), start_time)

        # Step 2: Async fetch with streaming
        try:
            result = await self._do_fetch(url, start_time)
            return result
        except asyncio.TimeoutError:
            return self._error_result(url, f"Timeout after {self.timeout_seconds}s", start_time)
        except aiohttp.ClientError as e:
            return self._error_result(url, f"HTTP error: {str(e)[:200]}", start_time)
        except Exception as e:
            return self._error_result(url, f"Unexpected error: {str(e)[:200]}", start_time)

    async def _do_fetch(self, url: str, start_time: float) -> dict:
        """Execute the actual HTTP request with all safety checks."""
        timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
        headers = {"User-Agent": self.user_agent}

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url,
                headers=headers,
                allow_redirects=True,
                max_redirects=self.max_redirects,
            ) as response:

                final_url = str(response.url)
                was_redirected = final_url != url

                # Step 3: Post-redirect validation
                # Critical: the initial URL was safe, but redirects
                # could have bounced us to an internal IP
                if was_redirected:
                    try:
                        is_safe_url(final_url)
                    except URLValidationError as e:
                        return self._error_result(
                            url,
                            f"Redirect target blocked: {e}",
                            start_time,
                            final_url=final_url,
                        )

                # Step 4: Content-type check
                content_type = response.content_type or ""
                if not any(ct in content_type for ct in TEXT_CONTENT_TYPES):
                    return self._error_result(
                        url,
                        f"Non-text content type: {content_type}",
                        start_time,
                        final_url=final_url,
                        status=response.status,
                    )

                # Step 5: Streaming read with size cap
                chunks = []
                total_bytes = 0

                async for chunk in response.content.iter_chunked(8192):
                    total_bytes += len(chunk)
                    if total_bytes > self.max_size_bytes:
                        return self._error_result(
                            url,
                            f"Response exceeds {self.max_size_bytes} byte limit",
                            start_time,
                            final_url=final_url,
                            status=response.status,
                        )
                    chunks.append(chunk)

                raw_bytes = b"".join(chunks)

                # Detect encoding
                encoding = response.charset or "utf-8"
                try:
                    raw_text = raw_bytes.decode(encoding, errors="replace")
                except (UnicodeDecodeError, LookupError):
                    raw_text = raw_bytes.decode("utf-8", errors="replace")

                # Step 6: Clean and sanitize
                if "html" in content_type:
                    clean_text = clean_html(raw_text, max_length=self.max_text_length)
                else:
                    # Plain text / JSON — just truncate and wrap
                    clean_text = raw_text[:self.max_text_length]

                elapsed_ms = (time.time() - start_time) * 1000

                return {
                    "status": "success",
                    "url": url,
                    "final_url": final_url,
                    "http_status": response.status,
                    "content_type": content_type,
                    "text": clean_text,
                    "byte_count": total_bytes,
                    "fetch_time_ms": round(elapsed_ms, 1),
                    "was_redirected": was_redirected,
                }

    def _error_result(
        self,
        url: str,
        error: str,
        start_time: float,
        final_url: str | None = None,
        status: int = 0,
    ) -> dict:
        """Build an error result dict."""
        elapsed_ms = (time.time() - start_time) * 1000
        return {
            "status": "error",
            "url": url,
            "final_url": final_url or url,
            "http_status": status,
            "content_type": "",
            "text": f"Fetch failed: {error}",
            "byte_count": 0,
            "fetch_time_ms": round(elapsed_ms, 1),
            "was_redirected": final_url is not None and final_url != url,
            "error": error,
        }


async def fetch_url(url: str, **kwargs) -> dict:
    """Convenience function for one-off fetches."""
    fetcher = SafeFetcher(**kwargs)
    return await fetcher.fetch(url)
