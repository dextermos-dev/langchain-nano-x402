"""Payment guard for autonomous Nano x402 calls.

Enforces strict spend bounds, destination allowlists, origin redirect guards,
duplicate request protections, and quote validity checks before signing.
"""

from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Set

from .address import normalize_nano_address

RAW_PER_XNO = 10**30


class GuardViolationError(Exception):
    """Raised when an x402 payment quote violates configured safety invariants."""
    pass


@dataclass
class PaymentGuardConfig:
    """Security bounds and policy for an autonomous agent's Nano x402 payments."""
    max_amount_raw_per_call: int = 10**28  # Default: 0.01 XNO (~$0.003)
    cumulative_cap_raw: int = 10**29       # Default: 0.1 XNO cumulative cap
    allowed_pay_to: Set[str] = field(default_factory=set)  # Empty set = allow any valid address
    allowed_network: str = "nano:mainnet"
    max_timeout_seconds: int = 60


class NanoPaymentGuard:
    """Stateful payment guard tracking cumulative spend and preventing replay / double sign."""

    def __init__(self, config: PaymentGuardConfig | None = None) -> None:
        self.config = config or PaymentGuardConfig()
        self.cumulative_spent_raw: int = 0
        self._signed_request_keys: Set[str] = set()

    def check_quote(
        self,
        *,
        request_url: str,
        target_url: str,
        method: str,
        request_body_hash: str,
        quote: dict,
        quote_received_at: float | None = None,
    ) -> int:
        """Validate all security invariants on the 402 challenge quote.

        Returns:
            amount_raw (int): The validated amount to be signed.

        Raises:
            GuardViolationError: If any security invariant is breached.
        """
        # 1. Malformed quote structure checks
        if not isinstance(quote, dict):
            raise GuardViolationError(f"malformed quote: expected dict, got {type(quote)}")

        scheme = quote.get("scheme")
        if scheme != "exact":
            raise GuardViolationError(f"unsupported scheme: {scheme!r}; only 'exact' supported")

        network = quote.get("network")
        if network != self.config.allowed_network:
            raise GuardViolationError(
                f"wrong network: {network!r}; required {self.config.allowed_network!r}"
            )

        pay_to_raw = quote.get("payTo")
        if not pay_to_raw:
            raise GuardViolationError("malformed quote: missing 'payTo' field")

        try:
            pay_to = normalize_nano_address(pay_to_raw)
        except ValueError as e:
            raise GuardViolationError(f"malformed quote: invalid payTo address: {e}") from e

        # 2. Destination allowlist check
        if self.config.allowed_pay_to:
            normalized_allowlist = {normalize_nano_address(a) for a in self.config.allowed_pay_to}
            if pay_to not in normalized_allowlist:
                raise GuardViolationError(
                    f"payTo {pay_to} is not in operator allowlist"
                )

        # 3. Amount parsing & per-call cap
        amount_val = quote.get("amount")
        if amount_val is None:
            raise GuardViolationError("malformed quote: missing 'amount'")

        try:
            amount_raw = int(str(amount_val).strip())
        except ValueError as e:
            raise GuardViolationError(f"malformed quote: non-integer raw amount {amount_val!r}") from e

        if amount_raw <= 0:
            raise GuardViolationError(f"amount must be positive: {amount_raw}")

        if amount_raw > self.config.max_amount_raw_per_call:
            raise GuardViolationError(
                f"amount {amount_raw} raw exceeds per-call cap {self.config.max_amount_raw_per_call} raw"
            )

        # 4. Cumulative spend cap
        if self.cumulative_spent_raw + amount_raw > self.config.cumulative_cap_raw:
            raise GuardViolationError(
                f"cumulative cap reached: current spent {self.cumulative_spent_raw} + "
                f"new {amount_raw} raw > cap {self.config.cumulative_cap_raw} raw"
            )

        # 5. Origin redirect guard (never pay a cross-origin redirect)
        req_parsed = urllib.parse.urlparse(request_url)
        target_parsed = urllib.parse.urlparse(target_url)
        if (req_parsed.scheme, req_parsed.netloc) != (target_parsed.scheme, target_parsed.netloc):
            raise GuardViolationError(
                f"redirect origin mismatch: requested {request_url!r} redirected to {target_url!r}"
            )

        # 6. Quote timeout check
        now = time.time()
        received_at = quote_received_at or now
        quote_max_timeout = int(quote.get("maxTimeoutSeconds", self.config.max_timeout_seconds))
        if (now - received_at) > quote_max_timeout:
            raise GuardViolationError(
                f"quote expired: age {now - received_at:.1f}s > maxTimeoutSeconds {quote_max_timeout}s"
            )

        # 7. Duplicate request guard (never sign a second block for identical request)
        req_key = f"{method.upper()}:{request_url}:{request_body_hash}"
        if req_key in self._signed_request_keys:
            raise GuardViolationError(
                f"duplicate request detected: payment for {req_key} was already signed"
            )

        return amount_raw

    def record_payment(
        self,
        *,
        request_url: str,
        method: str,
        request_body_hash: str,
        amount_raw: int,
    ) -> None:
        """Record successful payment to advance cumulative cap and lock deduplication key."""
        req_key = f"{method.upper()}:{request_url}:{request_body_hash}"
        self._signed_request_keys.add(req_key)
        self.cumulative_spent_raw += amount_raw
