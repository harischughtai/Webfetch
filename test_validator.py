"""
Security Tests for SafeFetch URL Validator
-------------------------------------------
Ensures SSRF protection works correctly.
"""

import pytest

from safefetch.validator import URLValidationError, is_safe_url


class TestSSRFProtection:
    """Test that dangerous URLs are blocked."""

    def test_blocks_localhost(self):
        with pytest.raises(URLValidationError, match="loopback"):
            is_safe_url("http://localhost/admin")

    def test_blocks_127_ip(self):
        with pytest.raises(URLValidationError, match="loopback"):
            is_safe_url("http://127.0.0.1/secret")

    def test_blocks_private_10(self):
        with pytest.raises(URLValidationError, match="private"):
            is_safe_url("http://10.0.0.1/internal")

    def test_blocks_private_172(self):
        with pytest.raises(URLValidationError, match="private"):
            is_safe_url("http://172.16.0.1/api")

    def test_blocks_private_192(self):
        with pytest.raises(URLValidationError, match="private"):
            is_safe_url("http://192.168.1.1/config")

    def test_blocks_cloud_metadata(self):
        with pytest.raises(URLValidationError, match="link-local"):
            is_safe_url("http://169.254.169.254/latest/meta-data/")

    def test_blocks_file_scheme(self):
        with pytest.raises(URLValidationError, match="scheme"):
            is_safe_url("file:///etc/passwd")

    def test_blocks_ftp_scheme(self):
        with pytest.raises(URLValidationError, match="scheme"):
            is_safe_url("ftp://internal.server/data")

    def test_blocks_exe_extension(self):
        with pytest.raises(URLValidationError, match="extension"):
            is_safe_url("https://example.com/malware.exe")

    def test_blocks_sh_extension(self):
        with pytest.raises(URLValidationError, match="extension"):
            is_safe_url("https://example.com/script.sh")

    def test_blocks_no_hostname(self):
        with pytest.raises(URLValidationError):
            is_safe_url("http:///path")


class TestSafeURLs:
    """Test that legitimate URLs pass validation."""

    def test_allows_https(self):
        assert is_safe_url("https://example.com") is True

    def test_allows_http(self):
        assert is_safe_url("http://example.com") is True

    def test_allows_path(self):
        assert is_safe_url("https://example.com/page/article") is True

    def test_allows_query_params(self):
        assert is_safe_url("https://example.com/search?q=test") is True

    def test_allows_html_extension(self):
        assert is_safe_url("https://example.com/page.html") is True

    def test_allows_json_extension(self):
        assert is_safe_url("https://example.com/api/data.json") is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
