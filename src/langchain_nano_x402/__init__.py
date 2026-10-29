"""LangChain integration for autonomous Nano x402 resource purchasing."""

from .address import is_nano_address, normalize_nano_address, public_key_to_address
from .client import NanoX402Client
from .guard import (
    GuardViolationError,
    NanoPaymentGuard,
    PaymentGuardConfig,
    RAW_PER_XNO,
)
from .tool import NanoX402Input, NanoX402Tool

__version__ = "0.1.0"

__all__ = [
    "NanoX402Tool",
    "NanoX402Input",
    "NanoX402Client",
    "NanoPaymentGuard",
    "PaymentGuardConfig",
    "GuardViolationError",
    "RAW_PER_XNO",
    "normalize_nano_address",
    "is_nano_address",
    "public_key_to_address",
]
