"""Nano address utilities: validation, normalization, and public key encoding."""

from __future__ import annotations

import hashlib
import re

_ALPHABET = "13456789abcdefghijkmnopqrstuwxyz"
_ADDRESS_RE = re.compile(r"(?:nano|xrb)_([13][13456789abcdefghijkmnopqrstuwxyz]{59})")


def normalize_nano_address(address: str) -> str:
    """Validate address (including blake2b checksum) and return with nano_ prefix."""
    match = _ADDRESS_RE.fullmatch(str(address).strip())
    if match is None or not _checksum_ok(match.group(1)):
        raise ValueError(f"not a valid Nano address: {address!r}")
    return "nano_" + match.group(1)


def is_nano_address(address: str) -> bool:
    """Return True if address is a well-formed Nano address with valid checksum."""
    try:
        normalize_nano_address(address)
        return True
    except ValueError:
        return False


def _checksum_ok(body: str) -> bool:
    """Validate the 8-char checksum of a 60-char address body."""
    bits = 0
    for char in body[:52]:
        bits = (bits << 5) | _ALPHABET.index(char)
    if bits >> 256:
        return False
    public_key = bits.to_bytes(32, "big")
    digest = hashlib.blake2b(public_key, digest_size=5).digest()[::-1]
    check = int.from_bytes(digest, "big")
    encoded = "".join(_ALPHABET[(check >> (5 * i)) & 31] for i in range(7, -1, -1))
    return encoded == body[52:]


def public_key_to_address(public_key: bytes) -> str:
    """Convert a 32-byte Ed25519 public key into a standard nano_ address."""
    if len(public_key) != 32:
        raise ValueError(f"expected 32-byte public key, got {len(public_key)}")
    bits = int.from_bytes(public_key, "big")
    encoded = "".join(_ALPHABET[(bits >> (5 * i)) & 31] for i in range(51, -1, -1))
    digest = hashlib.blake2b(public_key, digest_size=5).digest()[::-1]
    check = int.from_bytes(digest, "big")
    checksum = "".join(_ALPHABET[(check >> (5 * i)) & 31] for i in range(7, -1, -1))
    return "nano_" + encoded + checksum
