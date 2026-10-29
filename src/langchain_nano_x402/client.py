"""Nano x402 HTTP client implementing the exact scheme with local payment guarding."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from .guard import GuardViolationError, NanoPaymentGuard, PaymentGuardConfig
from .nano_crypto import (
    address_to_pubkey,
    compute_state_block_hash,
    derive_keypair_from_secret,
    derive_keypair_from_seed,
    nano_sign,
)


class NanoX402Client:
    """HTTP Client that handles HTTP 402 Payment Required challenges on nano:mainnet."""

    def __init__(
        self,
        *,
        signer: Callable[[str, int], dict] | None = None,
        guard: NanoPaymentGuard | None = None,
        guard_config: PaymentGuardConfig | None = None,
        api_base: str = "https://pursekeeper.dev",
    ) -> None:
        self.guard = guard or NanoPaymentGuard(guard_config)
        self.signer = signer
        self.api_base = os.environ.get("API", api_base).rstrip("/")

    def _default_signer(self, pay_to: str, amount_raw: int, challenge: dict | None = None) -> dict:
        """Sign a valid Nano state block using environment seed or private key."""
        seed_hex = os.environ.get("NANO_SEED")
        pk_hex = os.environ.get("NANO_PRIVATE_KEY")
        if not seed_hex and not pk_hex:
            raise RuntimeError("no Nano signer available: set NANO_SEED or pass custom signer")

        if seed_hex:
            index = int(os.environ.get("NANO_INDEX", "0"))
            sk, account_pk, account = derive_keypair_from_seed(seed_hex.strip(), index)
        else:
            sk, account_pk, account = derive_keypair_from_secret(pk_hex.strip())

        sign_fn = lambda msg_hash: nano_sign(sk, msg_hash)

        # Query account_info
        info_url = f"{self.api_base}/v1/account_info?account={urllib.parse.quote(account)}"
        req = urllib.request.Request(info_url, headers={"User-Agent": "langchain-nano-x402/0.1.2"})
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            info = json.loads(resp.read().decode("utf-8"))

        if not info.get("found"):
            raise RuntimeError(f"account {account} has no opened blocks or is not funded")

        frontier = info["frontier"]
        balance_raw = int(info["balance_raw"])
        rep_address = info.get("representative") or account
        rep_pk = address_to_pubkey(rep_address)
        link_bytes = address_to_pubkey(pay_to)

        new_balance = balance_raw - amount_raw
        if new_balance < 0:
            raise RuntimeError(f"insufficient balance: have {balance_raw} raw, need {amount_raw} raw")

        # Compute hash
        block_hash_bytes = compute_state_block_hash(
            account_pk=account_pk,
            previous_hex=frontier,
            representative_pk=rep_pk,
            new_balance_raw=new_balance,
            link_bytes=link_bytes,
        )
        block_hash_hex = block_hash_bytes.hex().upper()

        # Compute or obtain work
        accepted_extra = {}
        if challenge and "accepts" in challenge and challenge["accepts"]:
            accepted_extra = challenge["accepts"][0].get("extra", {})

        seller_work = accepted_extra.get("workOptional") is True or accepted_extra.get("work") == "optional"

        # Sign block
        sig_bytes = sign_fn(block_hash_bytes)

        state_block = {
            "type": "state",
            "account": account,
            "previous": frontier,
            "representative": rep_address,
            "balance": str(new_balance),
            "link": link_bytes.hex().upper(),
            "link_as_account": pay_to,
            "signature": sig_bytes.hex().upper(),
        }

        if not seller_work or os.environ.get("FORCE_WORK"):
            try:
                work_url = f"{self.api_base}/v1/work"
                work_payload = json.dumps({"hash": frontier}).encode("utf-8")
                work_req = urllib.request.Request(
                    work_url,
                    data=work_payload,
                    headers={"Content-Type": "application/json", "User-Agent": "langchain-nano-x402/0.1.2"},
                )
                with urllib.request.urlopen(work_req, timeout=15.0) as wresp:
                    wdata = json.loads(wresp.read().decode("utf-8"))
                    state_block["work"] = wdata.get("work", "")
            except Exception:
                pass

        return {
            "block": state_block,
            "hash": block_hash_hex,
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
                return e.code, dict(e.headers), e.read()

            # Handle 402 Challenge
            challenge_body = e.read()
            quote, raw_challenge = self._parse_402_challenge(e.headers, challenge_body)
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
            if self.signer:
                signed_result = self.signer(quote["payTo"], amount_raw)
            else:
                signed_result = self._default_signer(quote["payTo"], amount_raw, raw_challenge)

            block = signed_result.get("block") or signed_result
            block_hash = signed_result.get("hash") or block.get("hash", "")

            # Record in payment guard
            self.guard.record_payment(
                request_url=url,
                method=method,
                request_body_hash=body_hash,
                amount_raw=amount_raw,
            )

            # Build x402 v2 payment payload
            resource = raw_challenge.get("resource", {"url": url})
            payment_payload = {
                "x402Version": 2,
                "resource": resource,
                "accepted": quote,
                "payload": {"block": block},
            }
            payment_sig_b64 = base64.b64encode(json.dumps(payment_payload).encode("utf-8")).decode("utf-8")

            paid_headers = dict(req_headers)
            paid_headers["Payment-Signature"] = payment_sig_b64

            # Handle broadcast and confirmation retry if seller responds "not yet confirmed"
            start_wait = time.time()
            retry_pattern = re.compile(
                r"not (yet )?confirmed|block not found|on the node but not|wait a second",
                re.IGNORECASE,
            )
            while True:
                paid_req = urllib.request.Request(url, data=data, headers=paid_headers, method=method)
                try:
                    with urllib.request.urlopen(paid_req, timeout=timeout) as paid_resp:
                        return paid_resp.status, dict(paid_resp.headers), paid_resp.read()
                except urllib.error.HTTPError as pe:
                    pe_body_bytes = pe.read()
                    pe_body_str = pe_body_bytes.decode("utf-8", errors="replace")

                    err_hint = pe_body_str
                    hdr_pr = pe.headers.get("Payment-Required")
                    if hdr_pr:
                        try:
                            decoded_pr = json.loads(base64.b64decode(hdr_pr).decode("utf-8"))
                            err_hint += " " + str(decoded_pr.get("error", ""))
                        except Exception:
                            pass

                    if pe.code == 402 and (time.time() - start_wait) < 30.0:
                        if retry_pattern.search(err_hint):
                            rep_tok = pe.headers.get("x-nano-represent")
                            if rep_tok:
                                paid_headers["x-nano-represent"] = rep_tok
                            else:
                                paid_headers.pop("x-nano-represent", None)
                            time.sleep(2.0)
                            continue
                    return pe.code, dict(pe.headers), pe_body_bytes

    def _parse_402_challenge(self, headers: Any, body: bytes) -> tuple[dict, dict]:
        """Extract quote parameters from Payment-Required header or JSON body."""
        raw_challenge: dict = {}

        # 1. Inspect PAYMENT-REQUIRED header (base64 JSON, standard x402 v2)
        for h_key in ["Payment-Required", "PAYMENT-REQUIRED", "payment-required"]:
            hdr_val = headers.get(h_key)
            if hdr_val:
                try:
                    decoded = base64.b64decode(hdr_val).decode("utf-8")
                    parsed = json.loads(decoded)
                    if isinstance(parsed, dict):
                        raw_challenge = parsed
                        break
                except Exception:
                    pass

        # 2. Inspect body if header not found
        if not raw_challenge:
            try:
                parsed = json.loads(body.decode("utf-8"))
                if isinstance(parsed, dict):
                    if "x402" in parsed and isinstance(parsed["x402"], dict):
                        raw_challenge = parsed["x402"]
                    else:
                        raw_challenge = parsed
            except Exception:
                pass

        # 3. Find nano:mainnet exact accept entry
        if "accepts" in raw_challenge and isinstance(raw_challenge["accepts"], list):
            for acc in raw_challenge["accepts"]:
                if isinstance(acc, dict) and acc.get("network") == "nano:mainnet" and acc.get("scheme") == "exact":
                    return acc, raw_challenge
            if raw_challenge["accepts"]:
                return raw_challenge["accepts"][0], raw_challenge

        # 4. Fallback to direct fields
        pay_to = raw_challenge.get("payTo") or headers.get("X-Payment-Beneficiary") or headers.get("X-Pay-To")
        amount = raw_challenge.get("amount") or headers.get("X-Payment-Amount")
        network = raw_challenge.get("network") or headers.get("X-Payment-Network", "nano:mainnet")
        scheme = raw_challenge.get("scheme") or headers.get("X-Payment-Scheme", "exact")

        quote = {
            "scheme": scheme,
            "network": network,
            "amount": amount,
            "payTo": pay_to,
        }
        return quote, raw_challenge
