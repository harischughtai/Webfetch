# SafeFetch — Production-Grade Web Fetcher for LLM Agents

A secure, lightweight web fetching tool designed for LLM agent workflows. Fetches web pages with **SSRF protection**, **redirect safety validation**, **HTML sanitization**, and **prompt injection stripping** — everything you need to safely let an AI agent browse the web.

Built from real-world experience building production AI systems where LLM agents need to fetch external URLs without exposing internal infrastructure.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![aiohttp](https://img.shields.io/badge/aiohttp-async-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Why This Exists

When you give an LLM agent a "web fetch" tool, you open a massive attack surface:

- **SSRF (Server-Side Request Forgery)** — The agent could be tricked into fetching `http://169.254.169.254/` (cloud metadata) or `http://localhost:8080/admin`
- **Redirect attacks** — A safe-looking URL can redirect to an internal endpoint
- **Oversized responses** — A malicious URL could return gigabytes, crashing your agent
- **Prompt injection** — Fetched HTML could contain hidden instructions that hijack the agent
- **Dangerous files** — The agent might download `.exe`, `.sh`, or other executable files

SafeFetch handles all of these out of the box.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   SafeFetch Pipeline                      │
├──────────────────────────────────────────────────────────┤
│                                                            │
│   ┌──────────┐    ┌─────────────────┐                    │
│   │  Input    │───▶│  URL Validator   │                    │
│   │  URL      │    │  ───────────────│                    │
│   └──────────┘    │  • Scheme check  │                    │
│                    │  • SSRF block    │                    │
│                    │  • Extension ban │                    │
│                    └────────┬────────┘                    │
│                             │ ✅ Safe                      │
│                    ┌────────▼────────┐                    │
│                    │  Async Fetcher   │                    │
│                    │  ───────────────│                    │
│                    │  • aiohttp GET   │                    │
│                    │  • Size limit    │                    │
│                    │  • Timeout       │                    │
│                    │  • Stream read   │                    │
│                    └────────┬────────┘                    │
│                             │                              │
│                    ┌────────▼────────┐                    │
│                    │  Redirect Guard  │                    │
│                    │  ───────────────│                    │
│                    │  Re-validate     │                    │
│                    │  final URL after │                    │
│                    │  all redirects   │                    │
│                    └────────┬────────┘                    │
│                             │ ✅ Still safe                │
│                    ┌────────▼────────┐                    │
│                    │  Content Filter  │                    │
│                    │  ───────────────│                    │
│                    │  • MIME check    │                    │
│                    │  • HTML cleanup  │                    │
│                    │  • Script strip  │                    │
│                    │  • Injection     │                    │
│                    │    wrapper       │                    │
│                    └────────┬────────┘                    │
│                             │                              │
│                    ┌────────▼────────┐                    │
│                    │  Clean Text      │                    │
│                    │  Ready for LLM   │                    │
│                    └─────────────────┘                    │
│                                                            │
│   Security: SSRF ✓ | Redirects ✓ | Size ✓ | Injection ✓  │
└──────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
pip install -r requirements.txt
```

### Standalone Usage

```python
import asyncio
from safefetch import SafeFetcher

async def main():
    fetcher = SafeFetcher()
    result = await fetcher.fetch("https://example.com")
    print(result["text"])       # Clean text content
    print(result["status"])     # HTTP status code
    print(result["final_url"]) # After redirects

asyncio.run(main())
```

### LangChain Tool Integration

```python
from safefetch.langchain_tool import SafeFetchTool

tool = SafeFetchTool()
# Add to your LangChain agent's tool list
agent = create_react_agent(llm, tools=[tool, ...])
```

### CLI

```bash
python -m safefetch "https://example.com"
```

## Security Features

| Threat | Protection |
|--------|-----------|
| SSRF (localhost, internal IPs) | Blocks private/reserved IP ranges before connection |
| Cloud metadata endpoints | Blocks `169.254.169.254` and link-local range |
| Redirect attacks | Re-validates the final URL after all redirects |
| Oversized responses | Streaming read with configurable size cap (default 5MB) |
| Slow responses | Configurable timeout (default 15s) |
| Dangerous file types | Blocks `.exe`, `.sh`, `.bat`, `.dll`, etc. |
| Prompt injection in HTML | Wraps content in delimiter, strips scripts/styles |
| Non-text content | MIME type check, rejects binary content |

## Configuration

```python
fetcher = SafeFetcher(
    max_size_bytes=5_000_000,      # 5MB max response
    timeout_seconds=15,             # 15s timeout
    max_redirects=5,                # Max redirect hops
    blocked_extensions={".exe", ".sh", ".bat", ".dll", ".msi"},
    user_agent="SafeFetch/1.0",
)
```

## Project Structure

```
safefetch/
├── safefetch/
│   ├── __init__.py
│   ├── fetcher.py          # Core async fetcher
│   ├── validator.py        # URL validation & SSRF protection
│   ├── sanitizer.py        # HTML cleaning & prompt injection guard
│   └── langchain_tool.py   # LangChain BaseTool wrapper
├── tests/
│   └── test_validator.py   # Security tests
├── requirements.txt
├── .env.example
└── README.md
```

## What I Learned Building This

1. **SSRF validation timing is critical** — Validating only the initial URL is not enough. Redirects can bounce to internal IPs. You must re-validate after the final redirect resolves.
2. **Streaming > buffering** — Reading the entire response into memory before checking size is too late. Stream in chunks with a running byte counter and abort early.
3. **Prompt injection is a real threat** — Fetched web pages can contain hidden text like "Ignore all previous instructions." Wrapping content in a clear delimiter and stripping hidden elements is essential.

## License

MIT
