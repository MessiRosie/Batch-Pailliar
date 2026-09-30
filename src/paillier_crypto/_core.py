"""ctypes binding to the native Paillier core (libpaillier).

All values cross the C boundary as lowercase hex strings and are exposed to
Python as plain ints. Raw operations require plaintexts in [0, n); use the
:class:`EncryptedNumber` wrapper for ergonomic arithmetic.
"""

import ctypes
import os
import sys

_LIBNAME = "libpaillier.dylib" if sys.platform == "darwin" else "libpaillier.so"
_LIBPATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), _LIBNAME)

_lib = ctypes.CDLL(_LIBPATH)

# --- prototypes ---
_lib.paillier_new.restype = ctypes.c_void_p
_lib.paillier_new.argtypes = []
_lib.paillier_free.argtypes = [ctypes.c_void_p]
_lib.paillier_free.restype = None
_lib.paillier_free_str.argtypes = [ctypes.c_void_p]
_lib.paillier_free_str.restype = None

_lib.paillier_keygen.argtypes = [ctypes.c_void_p, ctypes.c_int]
_lib.paillier_keygen.restype = ctypes.c_int
_lib.paillier_has_public.argtypes = [ctypes.c_void_p]
_lib.paillier_has_public.restype = ctypes.c_int
_lib.paillier_has_private.argtypes = [ctypes.c_void_p]
_lib.paillier_has_private.restype = ctypes.c_int

_lib.paillier_set_public_key.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
_lib.paillier_set_public_key.restype = ctypes.c_int
_lib.paillier_set_private_key.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
]
_lib.paillier_set_private_key.restype = ctypes.c_int

for _name in ("paillier_pub_n", "paillier_pub_g", "paillier_pub_n2",
              "paillier_priv_lambda", "paillier_priv_mu",
              "paillier_priv_p", "paillier_priv_q"):
    _fn = getattr(_lib, _name)
    _fn.argtypes = [ctypes.c_void_p]
    _fn.restype = ctypes.c_void_p

_lib.paillier_encrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_lib.paillier_encrypt.restype = ctypes.c_void_p
_lib.paillier_decrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_lib.paillier_decrypt.restype = ctypes.c_void_p
_lib.paillier_decrypt_crt.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_lib.paillier_decrypt_crt.restype = ctypes.c_void_p
_lib.paillier_add.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
_lib.paillier_add.restype = ctypes.c_void_p
_lib.paillier_add_plain.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
_lib.paillier_add_plain.restype = ctypes.c_void_p
_lib.paillier_mul_plain.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
_lib.paillier_mul_plain.restype = ctypes.c_void_p


class NativeError(RuntimeError):
    """Raised when the native core reports a failure."""


def _call_str(fn, *args):
    ptr = fn(*args)
    if not ptr:
        raise NativeError("native call failed")
    try:
        return ctypes.string_at(ptr).decode("ascii")
    finally:
        _lib.paillier_free_str(ptr)


def _i2h(v):
    if v < 0:
        raise ValueError("negative values unsupported; plaintext must be in [0, n)")
    return format(v, "x").encode("ascii")


def _h2i(s):
    return int(s, 16)


class PublicKey:
    """Public key (n, g). Supports encryption and homomorphic evaluation."""

    def __init__(self, n, g, n_square):
        self.n = int(n)
        self.g = int(g)
        self.n_square = int(n_square)
        self._ctx = _lib.paillier_new()
        if not self._ctx:
            raise NativeError("failed to allocate native context")
        if not _lib.paillier_set_public_key(self._ctx, _i2h(self.n), _i2h(self.g)):
            raise NativeError("failed to set public key")

    def encrypt(self, m):
        """Encrypt plaintext int m (0 <= m < n); returns ciphertext int."""
        return _h2i(_call_str(_lib.paillier_encrypt, self._ctx, _i2h(m)))

    def add(self, c1, c2):
        """Ciphertext + ciphertext (homomorphic addition)."""
        return _h2i(_call_str(_lib.paillier_add, self._ctx, _i2h(c1), _i2h(c2)))

    def add_plain(self, c, m):
        """Ciphertext + plaintext (homomorphic addition with a clear value)."""
        return _h2i(_call_str(_lib.paillier_add_plain, self._ctx, _i2h(c), _i2h(m)))

    def mul_plain(self, c, m):
        """Ciphertext * plaintext scalar (homomorphic multiplication)."""
        return _h2i(_call_str(_lib.paillier_mul_plain, self._ctx, _i2h(c), _i2h(m)))

    def encrypt_number(self, m):
        """Encrypt and wrap the result in an :class:`EncryptedNumber`."""
        return EncryptedNumber(self, self.encrypt(m))

    def __repr__(self):
        return "PublicKey(n=%s, g=%s)" % (self.n, self.g)


class PrivateKey:
    """Private key. Supports decryption (standard and CRT-accelerated)."""

    def __init__(self, n, g, n_square, lam, mu, p, q):
        self.n = int(n)
        self.g = int(g)
        self.n_square = int(n_square)
        self.lam = int(lam)
        self.mu = int(mu)
        self.p = int(p)
        self.q = int(q)
        self.public_key = PublicKey(n, g, n_square)
        self._ctx = _lib.paillier_new()
        if not self._ctx:
            raise NativeError("failed to allocate native context")
        if not _lib.paillier_set_private_key(
                self._ctx, _i2h(self.n), _i2h(self.lam),
                _i2h(self.mu), _i2h(self.p), _i2h(self.q)):
            raise NativeError("failed to set private key")

    def decrypt(self, c):
        return _h2i(_call_str(_lib.paillier_decrypt, self._ctx, _i2h(c)))

    def decrypt_crt(self, c):
        return _h2i(_call_str(_lib.paillier_decrypt_crt, self._ctx, _i2h(c)))

    def decrypt_batch(self, cs, use_crt=True):
        """Decrypt many ciphertexts at once (CRT path when use_crt=True)."""
        fn = _lib.paillier_decrypt_crt if use_crt else _lib.paillier_decrypt
        return [_h2i(_call_str(fn, self._ctx, _i2h(c))) for c in cs]

    def __repr__(self):
        return "PrivateKey(n=%s)" % self.n


class EncryptedNumber:
    """Ciphertext bound to a public key, with operator overloads."""

    def __init__(self, public_key, ciphertext):
        self.public_key = public_key
        self.ciphertext = int(ciphertext)

    def __add__(self, other):
        if isinstance(other, EncryptedNumber):
            return EncryptedNumber(
                self.public_key,
                self.public_key.add(self.ciphertext, other.ciphertext))
        return EncryptedNumber(
            self.public_key,
            self.public_key.add_plain(self.ciphertext, other))

    def __radd__(self, other):
        return self.__add__(other)

    def __mul__(self, other):
        if isinstance(other, EncryptedNumber):
            raise TypeError("ciphertext * ciphertext is not a Paillier operation")
        return EncryptedNumber(
            self.public_key,
            self.public_key.mul_plain(self.ciphertext, other))

    def __rmul__(self, other):
        return self.__mul__(other)

    def decrypt(self, private_key):
        return private_key.decrypt(self.ciphertext)

    def __repr__(self):
        return "EncryptedNumber(ciphertext=%s)" % self.ciphertext


def generate_keypair(bits=1024):
    """Generate a fresh (PublicKey, PrivateKey) pair. bits = bit length of n."""
    ctx = _lib.paillier_new()
    if not ctx:
        raise NativeError("failed to allocate native context")
    try:
        if not _lib.paillier_keygen(ctx, bits):
            raise NativeError("key generation failed")
        n = _h2i(_call_str(_lib.paillier_pub_n, ctx))
        g = _h2i(_call_str(_lib.paillier_pub_g, ctx))
        n2 = _h2i(_call_str(_lib.paillier_pub_n2, ctx))
        lam = _h2i(_call_str(_lib.paillier_priv_lambda, ctx))
        mu = _h2i(_call_str(_lib.paillier_priv_mu, ctx))
        p = _h2i(_call_str(_lib.paillier_priv_p, ctx))
        q = _h2i(_call_str(_lib.paillier_priv_q, ctx))
    finally:
        _lib.paillier_free(ctx)
    return PublicKey(n, g, n2), PrivateKey(n, g, n2, lam, mu, p, q)
