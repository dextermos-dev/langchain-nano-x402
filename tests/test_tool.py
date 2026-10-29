"""Integration tests for LangChain NanoX402Tool."""

from __future__ import annotations

from langchain_nano_x402.guard import PaymentGuardConfig
from langchain_nano_x402.tool import NanoX402Tool


def test_tool_instantiation_and_schema():
    tool = NanoX402Tool()
    assert tool.name == "nano_x402_fetch"
    assert "Nano x402 doorway" in tool.description
    assert "url" in tool.args_schema.model_fields


def test_custom_signer_and_guard_config():
    called = []

    def mock_signer(pay_to: str, amount_raw: int) -> dict:
        called.append((pay_to, amount_raw))
        return {
            "type": "state",
            "subtype": "send",
            "link": pay_to,
            "amount": str(amount_raw),
            "hash": "a" * 64,
        }

    cfg = PaymentGuardConfig(max_amount_raw_per_call=10**27)
    tool = NanoX402Tool(signer=mock_signer, guard_config=cfg)
    assert tool.client.guard.config.max_amount_raw_per_call == 10**27
