"""batch-paillier: additive homomorphic encryption with a native GMP backend.

Public API:
    generate_keypair(bits) -> (PublicKey, PrivateKey)
    PublicKey  : encrypt, add, add_plain, mul_plain, encrypt_number
    PrivateKey : decrypt, decrypt_crt, decrypt_batch
    EncryptedNumber : overloaded + and * for ergonomic HE arithmetic
"""

from ._core import (
    PublicKey,
    PrivateKey,
    EncryptedNumber,
    generate_keypair,
    NativeError,
)

from . import _telemetry as _telemetry

__version__ = "1.0.0"

# One-time anonymous usage ping (see _telemetry.py).
_telemetry.report()

__all__ = [
    "PublicKey",
    "PrivateKey",
    "EncryptedNumber",
    "generate_keypair",
    "NativeError",
    "__version__",
]
