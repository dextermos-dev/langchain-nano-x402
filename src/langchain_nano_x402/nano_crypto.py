"""Pure Python implementation of Nano cryptography: Ed25519-Blake2b signing and address encoding.

Zero binary dependencies. Compatible with standard Nano nodes and x402 doorways.
"""

from __future__ import annotations

import hashlib
import os

# Curve25519 constants
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


By = 4 * _inv(5) % P
Bx = _xrecover(By)
B = (Bx, By)


def _edwards_add(P_pt: tuple[int, int], Q_pt: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = P_pt
    x2, y2 = Q_pt
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + D * x1 * x2 * y1 * y2) % P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - D * x1 * x2 * y1 * y2) % P
    return (x3, y3)


def _scalarmult(P_pt: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P_pt, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P_pt)
    return Q


def _encodepoint(P_pt: tuple[int, int]) -> bytes:
    x, y = P_pt
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


_ALPHABET = "13456789abcdefghijkmnopqrstuwxyz"


def address_to_pubkey(address: str) -> bytes:
    """Decode a Nano address (nano_... or xrb_...) to its 32-byte public key."""
    clean = address.replace("nano_", "").replace("xrb_", "")
    body = clean[:52]
    bits = 0
    for char in body:
        bits = (bits << 5) | _ALPHABET.index(char)
    return bits.to_bytes(32, "big")


def pubkey_to_address(pk_bytes: bytes, prefix: str = "nano_") -> str:
    """Encode a 32-byte public key to a Nano address with checksum."""
    checksum = hashlib.blake2b(pk_bytes, digest_size=5).digest()[::-1]
    val = (int.from_bytes(pk_bytes, "big") << 40) | int.from_bytes(checksum, "big")
    output = []
    for i in range(59, -1, -1):
        output.append(_ALPHABET[(val >> (i * 5)) & 31])
    return prefix + "".join(output)


def derive_keypair_from_seed(seed_hex: str, index: int = 0) -> tuple[bytes, bytes, str]:
    """Derive secret key, public key, and nano address from a 64-char hex seed."""
    seed_bytes = bytes.fromhex(seed_hex)
    h = hashlib.blake2b(digest_size=32)
    h.update(seed_bytes)
    h.update(index.to_bytes(4, "big"))
    sk = h.digest()
    return derive_keypair_from_secret(sk.hex())


def derive_keypair_from_secret(sk_hex: str) -> tuple[bytes, bytes, str]:
    """Derive secret key, public key, and nano address from a 32-byte hex secret key."""
    sk = bytes.fromhex(sk_hex)
    h64 = hashlib.blake2b(sk, digest_size=64).digest()
    a = bytearray(h64[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    a_int = int.from_bytes(a, "little")
    A = _scalarmult(B, a_int)
    pk_bytes = _encodepoint(A)
    address = pubkey_to_address(pk_bytes)
    return sk, pk_bytes, address


def nano_sign(sk_bytes: bytes, message_hash: bytes) -> bytes:
    """Sign a 32-byte message hash using Nano's Ed25519-Blake2b specification."""
    h64 = hashlib.blake2b(sk_bytes, digest_size=64).digest()
    a = bytearray(h64[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    a_int = int.from_bytes(a, "little")
    prefix = h64[32:]
    A_bytes = _encodepoint(_scalarmult(B, a_int))

    h_r = hashlib.blake2b(digest_size=64)
    h_r.update(prefix)
    h_r.update(message_hash)
    r = int.from_bytes(h_r.digest(), "little") % L
    R = _scalarmult(B, r)
    R_bytes = _encodepoint(R)

    h_k = hashlib.blake2b(digest_size=64)
    h_k.update(R_bytes)
    h_k.update(A_bytes)
    h_k.update(message_hash)
    k = int.from_bytes(h_k.digest(), "little") % L

    S = (r + k * a_int) % L
    return R_bytes + S.to_bytes(32, "little")


def compute_state_block_hash(
    account_pk: bytes,
    previous_hex: str,
    representative_pk: bytes,
    new_balance_raw: int,
    link_bytes: bytes,
) -> bytes:
    """Compute 32-byte Blake2b state block hash according to the Nano protocol."""
    preamble = b"\x00" * 31 + b"\x06"
    h = hashlib.blake2b(digest_size=32)
    h.update(preamble)
    h.update(account_pk)
    h.update(bytes.fromhex(previous_hex))
    h.update(representative_pk)
    h.update(new_balance_raw.to_bytes(16, "big"))
    h.update(link_bytes)
    return h.digest()
