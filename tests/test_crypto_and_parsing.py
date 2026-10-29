"""Tests for Nano Ed25519-Blake2b cryptography and 402 challenge parsing."""

import base64
import json
from langchain_nano_x402.client import NanoX402Client
from langchain_nano_x402.nano_crypto import (
    address_to_pubkey,
    compute_state_block_hash,
    derive_keypair_from_seed,
    nano_sign,
    pubkey_to_address,
)


def test_derive_keypair_and_address():
    seed = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
    sk, pk, addr = derive_keypair_from_seed(seed, 0)
    assert len(sk) == 32
    assert len(pk) == 32
    assert addr.startswith("nano_")
    assert address_to_pubkey(addr) == pk


def test_sign_state_block():
    seed = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
    sk, pk, addr = derive_keypair_from_seed(seed, 0)
    msg_hash = b"\x01" * 32
    sig = nano_sign(sk, msg_hash)
    assert len(sig) == 64


def test_parse_402_challenge_base64_header():
    client = NanoX402Client()
    challenge_payload = {
        "x402Version": 2,
        "resource": {"url": "https://pursekeeper.dev/v1/echo?msg=test"},
        "accepts": [
            {
                "scheme": "exact",
                "network": "nano:mainnet",
                "amount": "1000000000000000000000000000",
                "asset": "XNO",
                "payTo": "nano_1xug1q5t7nxoj3ywwzokiea9jz8fq8qfgzp8pbyfr3co3e5xgj755uofu8ue",
            }
        ],
    }
    b64_hdr = base64.b64encode(json.dumps(challenge_payload).encode()).decode()
    headers = {"Payment-Required": b64_hdr}
    body = b'{"error": "payment required"}'

    quote, raw = client._parse_402_challenge(headers, body)
    assert quote["payTo"] == "nano_1xug1q5t7nxoj3ywwzokiea9jz8fq8qfgzp8pbyfr3co3e5xgj755uofu8ue"
    assert quote["amount"] == "1000000000000000000000000000"
    assert quote["network"] == "nano:mainnet"
    assert quote["scheme"] == "exact"
    assert raw["x402Version"] == 2


def test_parse_402_challenge_body_x402():
    client = NanoX402Client()
    body_payload = {
        "error": "payment required",
        "x402": {
            "x402Version": 2,
            "resource": {"url": "https://pursekeeper.dev/v1/echo?msg=test"},
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "nano:mainnet",
                    "amount": "1000000000000000000000000000",
                    "payTo": "nano_1xug1q5t7nxoj3ywwzokiea9jz8fq8qfgzp8pbyfr3co3e5xgj755uofu8ue",
                }
            ],
        },
    }
    quote, raw = client._parse_402_challenge({}, json.dumps(body_payload).encode())
    assert quote["payTo"] == "nano_1xug1q5t7nxoj3ywwzokiea9jz8fq8qfgzp8pbyfr3co3e5xgj755uofu8ue"
    assert quote["amount"] == "1000000000000000000000000000"
