# Batch-Paillier

Additive homomorphic encryption (Paillier) with a native GMP backend.

Encrypt integers, then compute on the ciphertexts directly: add two ciphertexts,
add a ciphertext and a plaintext, or multiply a ciphertext by a plaintext
scalar — all without ever seeing the underlying values. Decryption is the only
operation that requires the private key. It is CRT-accelerated — split across
the two prime factors for roughly 4× faster decryption and efficient batch
workloads.

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
make            # builds src/batch_paillier/libpaillier.{dylib,so}
pip install .   # or: pip install -e .
```

GMP is required to build. On macOS: `brew install gmp`. On Debian/Ubuntu:
`apt install libgmp-dev`.

## Usage

```python
from batch_paillier import generate_keypair

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

## CRT batch decryption

Decryption is the only operation that needs the private key, and it is the
expensive one. The naive formula runs a single modular exponentiation with a
full-size exponent over the full-size modulus:

    m = L(c^λ mod n²) · μ mod n        where λ = lcm(p−1, q−1)

The CRT (Chinese Remainder Theorem) variant splits that one exponentiation into
two half-size ones, one modulo p² and one modulo q²:

    m_p = L_p(c^(p−1) mod p²) · h_p mod p
    m_q = L_q(c^(q−1) mod q²) · h_q mod q
    m   = CRT(m_p, m_q)

The correction factors h_p, h_q and p⁻¹ mod q are precomputed once at key
generation, so each ciphertext costs two exponentiations whose exponent and
modulus are both half the size of the naive one — roughly 4× faster for
2048-bit keys, and the gap grows with key size. `decrypt_batch` reuses this
path for every element, so decrypting N ciphertexts costs N × the CRT cost
instead of N × the naive cost. `decrypt` and `decrypt_crt` are exact
equivalents: they return identical results, only the runtime differs.

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

On first import the package sends a single anonymous usage ping so a
distribution can count active installs. It is non-blocking and failure-silent.
Set `PAILLIER_USAGE_OFF=1` to disable it, or `PAILLIER_USAGE_URL` to override
the endpoint.

## License

MIT
