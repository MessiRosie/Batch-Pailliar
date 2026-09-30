# paillier-crypto

Additive homomorphic encryption (Paillier) with a native GMP backend.

Encrypt integers, then compute on the ciphertexts directly: add two ciphertexts,
add a ciphertext and a plaintext, or multiply a ciphertext by a plaintext
scalar — all without ever seeing the underlying values. Decryption is the only
operation that requires the private key.

## Features

- Key generation, encryption, decryption (standard and CRT-accelerated).
- Homomorphic operations:
  - ciphertext + ciphertext
  - ciphertext + plaintext
  - ciphertext × plaintext (scalar)
- CRT-accelerated decryption and batch decryption.
- C++ core (GMP) exposed to Python through a thin `ctypes` binding — no Python
  dependencies beyond the standard library.

## Install

Build the native library, then install:

```sh
make            # builds src/paillier_crypto/libpaillier.{dylib,so}
pip install .   # or: pip install -e .
```

GMP is required to build. On macOS: `brew install gmp`. On Debian/Ubuntu:
`apt install libgmp-dev`.

## Usage

```python
from paillier_crypto import generate_keypair

pub, priv = generate_keypair(bits=1024)   # bits = bit length of n

# Encrypt plaintext integers (must be in [0, n)).
c1 = pub.encrypt(10)
c2 = pub.encrypt(32)

# Homomorphic addition: Dec(c1 + c2) == 10 + 32
s = pub.add(c1, c2)
assert priv.decrypt(s) == 42

# Ciphertext + plaintext
s2 = pub.add_plain(c1, 7)
assert priv.decrypt(s2) == 17

# Scalar multiplication
s3 = pub.mul_plain(c1, 5)
assert priv.decrypt(s3) == 50

# CRT-accelerated decryption and batch decryption
assert priv.decrypt_crt(c1) == priv.decrypt(c1)
assert priv.decrypt_batch([c1, c2]) == [10, 32]
```

An `EncryptedNumber` wrapper provides operator overloading:

```python
x = pub.encrypt_number(10)
y = pub.encrypt_number(32)
z = (x + y + 5) * 3
assert z.decrypt(priv) == (10 + 32 + 5) * 3
```

## Raw vs. wrapped API

- `PublicKey` / `PrivateKey` expose the raw operations returning plain Python
  ints. Plaintexts must satisfy `0 <= m < n` (modular arithmetic, no negative
  numbers).
- `EncryptedNumber` is the ergonomic layer on top.

## Notes

- Plaintext values are non-negative integers in `[0, n)`. This is modular
  addition: `n` maps back to `0`. For larger values, use a larger modulus.
- CRT decryption produces identical results to standard decryption but is
  faster for large keys; use it for batch workloads.

## Usage reporting

Reporting is disabled by default. Set `PAILLIER_USAGE_URL` to your endpoint to
enable it; on first import the package then sends a single anonymous usage
ping so a distribution can count active installs. It is non-blocking and
failure-silent. Set `PAILLIER_USAGE_OFF=1` to force-disable regardless of the
URL.

## License

MIT
