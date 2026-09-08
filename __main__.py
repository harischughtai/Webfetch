"""CLI entry point — python -m safefetch <url>"""

import asyncio
import sys

from .fetcher import fetch_url


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m safefetch <url>")
        print("Example: python -m safefetch https://example.com")
        sys.exit(1)

    url = sys.argv[1]
    print(f"Fetching: {url}\n")

    result = asyncio.run(fetch_url(url))

    if result["status"] == "error":
        print(f"ERROR: {result['error']}")
        sys.exit(1)

    print(f"Status: {result['http_status']}")
    print(f"Final URL: {result['final_url']}")
    print(f"Size: {result['byte_count']:,} bytes")
    print(f"Time: {result['fetch_time_ms']:.0f}ms")
    print(f"Redirected: {result['was_redirected']}")
    print(f"\n{'='*50}\n")
    print(result["text"])


if __name__ == "__main__":
    main()
