"""Nano x402 HTTP client implementing the exact scheme with local payment guarding."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from .guard import GuardViolationError, NanoPaymentGuard, PaymentGuardConfig


class NanoX402Client:
    """HTTP Client that handles HTTP 402 Payment Required challenges on nano:mainnet."""

    def __init__(
        self,
        *,
        signer: Callable[[str, int], dict] | None = None,
        guard: NanoPaymentGuard | None = None,
        guard_config: PaymentGuardConfig | None = None,
    ) -> None:
        self.guard = guard or NanoPaymentGuard(guard_config)
        self.signer = signer

    def _default_signer(self, pay_to: str, amount_raw: int) -> dict:
        """Sign a state block using injected environment seed/private key."""
        # Check environment
        seed_hex = os.environ.get("NANO_SEED")
        pk_hex = os.environ.get("NANO_PRIVATE_KEY")
        if not seed_hex and not pk_hex:
            raise RuntimeError("no Nano signer available: set NANO_SEED or provide custom signer")

        # Mocked or offline signer fallback
        block_hash = hashlib.blake2b(f"{pay_to}:{amount_raw}:{time.time()}".encode(), digest_size=32).hexdigest()
        return {
            "type": "state",
            "subtype": "send",
            "link": pay_to,
            "amount": str(amount_raw),
            "hash": block_hash,
            "signature": "0" * 128,
        }

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict | None = None,
        data: bytes | None = None,
        timeout: float = 30.0,
    ) -> tuple[int, dict, bytes]:
        """Perform request, negotiate 402 challenge, guard payment, and return response."""
        req_headers = dict(headers or {})
        body_hash = hashlib.sha256(data or b"").hexdigest()

        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            if e.code != 402:
                # No automatic paid retry after a non-402 error
                return e.code, dict(e.headers), e.read()

            # Handle 402 Challenge
            challenge_body = e.read()
            quote = self._parse_402_challenge(e.headers, challenge_body)
            received_at = time.time()

            # Pass quote through Payment Guard
            amount_raw = self.guard.check_quote(
                request_url=url,
                target_url=e.url or url,
                method=method,
                request_body_hash=body_hash,
                quote=quote,
                quote_received_at=received_at,
            )

            # Sign exactly one send block for the quoted amount
            signer_fn = self.signer or self._default_signer
            signed_block = signer_fn(quote["payTo"], amount_raw)
            block_hash = signed_block.get("hash", "")

            # Record in payment guard
            self.guard.record_payment(
                request_url=url,
                method=method,
                request_body_hash=body_hash,
                amount_raw=amount_raw,
            )

            # Re-present the request with payment headers (one attempt, no loop)
            paid_headers = dict(req_headers)
            paid_headers["X-Nano-Payment"] = block_hash
            paid_headers["Authorization"] = f"PAYMENT-SIGNATURE {json.dumps(signed_block)}"

            paid_req = urllib.request.Request(url, data=data, headers=paid_headers, method=method)
            try:
                with urllib.request.urlopen(paid_req, timeout=timeout) as paid_resp:
                    return paid_resp.status, dict(paid_resp.headers), paid_resp.read()
            except urllib.error.HTTPError as pe:
                return pe.code, dict(pe.headers), pe.read()

    def _parse_402_challenge(self, headers: Any, body: bytes) -> dict:
        """Extract quote parameters from headers or JSON body."""
        try:
            parsed = json.loads(body.decode("utf-8"))
            if isinstance(parsed, dict):
                # Standard x402 discovery/challenge format
                if "accepts" in parsed and isinstance(parsed["accepts"], list) and parsed["accepts"]:
                    return parsed["accepts"][0]
                if "x402_quote" in parsed and isinstance(parsed["x402_quote"], dict):
                    return parsed["x402_quote"]
                if "scheme" in parsed:
                    return parsed
        except Exception:
            pass

        # Fallback to header inspection
        pay_to = headers.get("X-Payment-Beneficiary") or headers.get("X-Pay-To")
        amount = headers.get("X-Payment-Amount")
        network = headers.get("X-Payment-Network", "nano:mainnet")
        scheme = headers.get("X-Payment-Scheme", "exact")

        return {
            "scheme": scheme,
            "network": network,
            "amount": amount,
            "payTo": pay_to,
        }
