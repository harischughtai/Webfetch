"""
LangChain Tool Wrapper for SafeFetch
--------------------------------------
Drop-in BaseTool that can be added to any LangChain agent.
"""

import asyncio
from typing import Optional

from langchain_core.callbacks.manager import AsyncCallbackManagerForToolRun, CallbackManagerForToolRun
from langchain_core.tools import BaseTool

from .fetcher import SafeFetcher


class SafeFetchTool(BaseTool):
    """
    LangChain tool that safely fetches web pages for LLM agents.

    Features:
    - SSRF protection (blocks private IPs, cloud metadata)
    - Redirect safety validation
    - HTML sanitization with prompt injection boundaries
    - Configurable size limits and timeouts

    Usage:
        tool = SafeFetchTool()
        agent = create_react_agent(llm, tools=[tool])
    """

    name: str = "web_fetch"
    description: str = (
        "Fetch the content of a web page at a given URL. "
        "Returns the visible text content of the page, cleaned and sanitized. "
        "Use this when you need to read a specific web page. "
        "Input should be a valid HTTP or HTTPS URL."
    )

    max_size_bytes: int = 5_000_000
    timeout_seconds: int = 15

    def _get_fetcher(self) -> SafeFetcher:
        return SafeFetcher(
            max_size_bytes=self.max_size_bytes,
            timeout_seconds=self.timeout_seconds,
        )

    def _run(
        self,
        url: str,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        """Synchronous fetch — runs the async fetcher in an event loop."""
        fetcher = self._get_fetcher()

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(asyncio.run, fetcher.fetch(url)).result()
            else:
                result = loop.run_until_complete(fetcher.fetch(url))
        except RuntimeError:
            result = asyncio.run(fetcher.fetch(url))

        if result["status"] == "error":
            return f"Error fetching {url}: {result.get('error', 'Unknown error')}"

        return result["text"]

    async def _arun(
        self,
        url: str,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> str:
        """Async fetch — native async support for async agents."""
        fetcher = self._get_fetcher()
        result = await fetcher.fetch(url)

        if result["status"] == "error":
            return f"Error fetching {url}: {result.get('error', 'Unknown error')}"

        return result["text"]
