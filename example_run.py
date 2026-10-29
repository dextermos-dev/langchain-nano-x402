#!/usr/bin/env python3
"""Deterministic runner for NanoX402Tool.

Executes a guarded pay-per-call HTTP 402 request without requiring an LLM or OpenAI API key.

Usage:
    export NANO_SEED=<64 hex chars>
    python example_run.py [URL]
"""

import os
import sys
from langchain_nano_x402 import NanoX402Tool, PaymentGuardConfig


def main() -> None:
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://pursekeeper.dev/v1/echo?msg=langchain_deterministic_call"

    # Configure local payment guard invariants
    guard_config = PaymentGuardConfig(
        max_amount_raw_per_call=10**28,  # 0.01 XNO per call max (~$0.003)
        cumulative_cap_raw=10**29,       # 0.1 XNO cumulative cap
        allowed_network="nano:mainnet",
        max_timeout_seconds=60,
    )

    print(f"Initializing NanoX402Tool with guarded bounds...")
    tool = NanoX402Tool(guard_config=guard_config)

    print(f"Executing tool.invoke on: {target_url}")
    result = tool.invoke({"url": target_url, "method": "GET"})

    print("\n--- Tool Response ---")
    print(result)


if __name__ == "__main__":
    main()
