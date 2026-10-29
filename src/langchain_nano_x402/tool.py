"""LangChain BaseTool implementation for autonomous Nano x402 resource retrieval."""

from __future__ import annotations

import json
from typing import Any, Callable, Type

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from .client import NanoX402Client
from .guard import NanoPaymentGuard, PaymentGuardConfig


class NanoX402Input(BaseModel):
    """Input arguments for NanoX402Tool."""
    url: str = Field(description="The absolute HTTP(S) URL of the x402 resource to retrieve")
    method: str = Field(default="GET", description="HTTP method (GET or POST)")
    body: str | None = Field(default=None, description="Optional request body payload for POST requests")


class NanoX402Tool(BaseTool):
    """LangChain Tool enabling agents to buy and consume Nano x402 micro-API resources safely."""

    name: str = "nano_x402_fetch"
    description: str = (
        "Fetches a paid HTTP resource from a Nano x402 doorway (0.001 XNO per call). "
        "Automatically negotiates 402 challenges under strict local spend guards and returns the resource content."
    )
    args_schema: Type[BaseModel] = NanoX402Input

    # Internal client instance
    client: NanoX402Client = Field(default_factory=NanoX402Client)

    def __init__(
        self,
        *,
        signer: Callable[[str, int], dict] | None = None,
        guard_config: PaymentGuardConfig | None = None,
        guard: NanoPaymentGuard | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.client = NanoX402Client(signer=signer, guard=guard, guard_config=guard_config)

    def _run(self, url: str, method: str = "GET", body: str | None = None) -> str:
        """Synchronously execute the guarded x402 request."""
        data_bytes = body.encode("utf-8") if body else None
        status, headers, resp_body = self.client.request(
            url,
            method=method,
            data=data_bytes,
        )

        content_str = resp_body.decode("utf-8", errors="replace")
        if status >= 400:
            return f"Error {status}: {content_str}"

        return content_str

    async def _arun(self, url: str, method: str = "GET", body: str | None = None) -> str:
        """Async implementation delegates to sync run in threadpool."""
        return self._run(url, method=method, body=body)
