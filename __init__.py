"""
SafeFetch — Production-grade web fetcher for LLM agents.
Secure URL fetching with SSRF protection, redirect validation,
HTML sanitization, and prompt injection stripping.
"""

from .fetcher import SafeFetcher
from .validator import is_safe_url, URLValidationError
from .sanitizer import clean_html

__version__ = "1.0.0"
__all__ = ["SafeFetcher", "is_safe_url", "URLValidationError", "clean_html"]
