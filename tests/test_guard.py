"""Offline unit tests for NanoPaymentGuard and x402 safety invariants.

Tests run 100% offline against mocked 402 quotes, asserting all security invariants.
"""

from __future__ import annotations

import time
import pytest

from langchain_nano_x402.guard import (
    GuardViolationError,
    NanoPaymentGuard,
    PaymentGuardConfig,
)

VALID_PAY_TO = "nano_1xug1q5t7nxoj3ywwzokiea9jz8fq8qfgzp8pbyfr3co3e5xgj755uofu8ue"
OTHER_PAY_TO = "nano_3t6kheey6rimgt1br79egeqzgtg51cn3ocooxc91ggua4am3btgc7nnm64hz"


def make_valid_quote(
    *,
    scheme: str = "exact",
    network: str = "nano:mainnet",
    amount: str = "1000000000000000000000000000",  # 0.001 XNO (10^27 raw)
    pay_to: str = VALID_PAY_TO,
    max_timeout: int = 60,
) -> dict:
    return {
        "scheme": scheme,
        "network": network,
        "amount": amount,
        "payTo": pay_to,
        "maxTimeoutSeconds": max_timeout,
    }


def test_valid_quote_accepted():
    guard = NanoPaymentGuard()
    quote = make_valid_quote()
    amt = guard.check_quote(
        request_url="https://pursekeeper.dev/v1/echo?msg=test",
        target_url="https://pursekeeper.dev/v1/echo?msg=test",
        method="GET",
        request_body_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        quote=quote,
    )
    assert amt == 1000000000000000000000000000


def test_wrong_network_refused():
    guard = NanoPaymentGuard()
    quote = make_valid_quote(network="base:mainnet")
    with pytest.raises(GuardViolationError, match="wrong network"):
        guard.check_quote(
            request_url="https://pursekeeper.dev/v1/echo",
            target_url="https://pursekeeper.dev/v1/echo",
            method="GET",
            request_body_hash="",
            quote=quote,
        )


def test_pay_to_not_in_allowlist_refused():
    config = PaymentGuardConfig(allowed_pay_to={VALID_PAY_TO})
    guard = NanoPaymentGuard(config)
    quote = make_valid_quote(pay_to=OTHER_PAY_TO)
    with pytest.raises(GuardViolationError, match="not in operator allowlist"):
        guard.check_quote(
            request_url="https://pursekeeper.dev/v1/echo",
            target_url="https://pursekeeper.dev/v1/echo",
            method="GET",
            request_body_hash="",
            quote=quote,
        )


def test_amount_above_per_call_cap_refused():
    config = PaymentGuardConfig(max_amount_raw_per_call=10**26)  # Cap at 0.0001 XNO
    guard = NanoPaymentGuard(config)
    quote = make_valid_quote(amount="1000000000000000000000000000")  # 0.001 XNO > cap
    with pytest.raises(GuardViolationError, match="exceeds per-call cap"):
        guard.check_quote(
            request_url="https://pursekeeper.dev/v1/echo",
            target_url="https://pursekeeper.dev/v1/echo",
            method="GET",
            request_body_hash="",
            quote=quote,
        )


def test_cumulative_cap_refused():
    config = PaymentGuardConfig(cumulative_cap_raw=2 * 10**27)  # Cap at 0.002 XNO
    guard = NanoPaymentGuard(config)
    quote = make_valid_quote(amount=str(10**27))

    # First call: 0.001 XNO -> OK
    guard.check_quote(
        request_url="https://pursekeeper.dev/v1/echo?msg=1",
        target_url="https://pursekeeper.dev/v1/echo?msg=1",
        method="GET",
        request_body_hash="hash1",
        quote=quote,
    )
    guard.record_payment(
        request_url="https://pursekeeper.dev/v1/echo?msg=1",
        method="GET",
        request_body_hash="hash1",
        amount_raw=10**27,
    )

    # Second call: 0.001 XNO -> OK (Cumulative = 0.002 XNO)
    guard.check_quote(
        request_url="https://pursekeeper.dev/v1/echo?msg=2",
        target_url="https://pursekeeper.dev/v1/echo?msg=2",
        method="GET",
        request_body_hash="hash2",
        quote=quote,
    )
    guard.record_payment(
        request_url="https://pursekeeper.dev/v1/echo?msg=2",
        method="GET",
        request_body_hash="hash2",
        amount_raw=10**27,
    )

    # Third call: Exceeds cumulative cap -> MUST REFUSE
    with pytest.raises(GuardViolationError, match="cumulative cap reached"):
        guard.check_quote(
            request_url="https://pursekeeper.dev/v1/echo?msg=3",
            target_url="https://pursekeeper.dev/v1/echo?msg=3",
            method="GET",
            request_body_hash="hash3",
            quote=quote,
        )


def test_duplicate_request_never_signs_twice():
    guard = NanoPaymentGuard()
    quote = make_valid_quote()
    url = "https://pursekeeper.dev/v1/echo?msg=same"
    body_hash = "same_hash"

    # First sign and record
    guard.check_quote(
        request_url=url,
        target_url=url,
        method="GET",
        request_body_hash=body_hash,
        quote=quote,
    )
    guard.record_payment(
        request_url=url,
        method="GET",
        request_body_hash=body_hash,
        amount_raw=10**27,
    )

    # Identical second invocation -> MUST REFUSE
    with pytest.raises(GuardViolationError, match="duplicate request detected"):
        guard.check_quote(
            request_url=url,
            target_url=url,
            method="GET",
            request_body_hash=body_hash,
            quote=quote,
        )


def test_redirect_to_another_origin_never_paid():
    guard = NanoPaymentGuard()
    quote = make_valid_quote()
    with pytest.raises(GuardViolationError, match="redirect origin mismatch"):
        guard.check_quote(
            request_url="https://pursekeeper.dev/v1/echo",
            target_url="https://attacker.evil.com/v1/echo",
            method="GET",
            request_body_hash="",
            quote=quote,
        )


def test_malformed_quote_refused():
    guard = NanoPaymentGuard()

    # Missing payTo
    with pytest.raises(GuardViolationError, match="missing 'payTo'"):
        guard.check_quote(
            request_url="https://pursekeeper.dev/v1/echo",
            target_url="https://pursekeeper.dev/v1/echo",
            method="GET",
            request_body_hash="",
            quote={"scheme": "exact", "network": "nano:mainnet", "amount": "100"},
        )

    # Invalid address checksum
    with pytest.raises(GuardViolationError, match="invalid payTo address"):
        guard.check_quote(
            request_url="https://pursekeeper.dev/v1/echo",
            target_url="https://pursekeeper.dev/v1/echo",
            method="GET",
            request_body_hash="",
            quote={"scheme": "exact", "network": "nano:mainnet", "amount": "100", "payTo": "nano_invalid"},
        )

    # Non-integer amount
    with pytest.raises(GuardViolationError, match="non-integer raw amount"):
        guard.check_quote(
            request_url="https://pursekeeper.dev/v1/echo",
            target_url="https://pursekeeper.dev/v1/echo",
            method="GET",
            request_body_hash="",
            quote={"scheme": "exact", "network": "nano:mainnet", "amount": "invalid_raw", "payTo": VALID_PAY_TO},
        )


def test_expired_quote_refused():
    guard = NanoPaymentGuard()
    quote = make_valid_quote(max_timeout=30)
    # Quote received 45 seconds ago -> Expired
    received_at = time.time() - 45.0
    with pytest.raises(GuardViolationError, match="quote expired"):
        guard.check_quote(
            request_url="https://pursekeeper.dev/v1/echo",
            target_url="https://pursekeeper.dev/v1/echo",
            method="GET",
            request_body_hash="",
            quote=quote,
            quote_received_at=received_at,
        )
