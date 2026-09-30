import random
import sys
import time

sys.path.insert(0, "/Users/genejing/paillier-crypto/src")

import batch_paillier as pa

random.seed(1234)

pub, priv = pa.generate_keypair(bits=512)
print("n bits:", pub.n.bit_length())
print("g == n+1:", pub.g == pub.n + 1)

# 1. roundtrip
ok = 0
for _ in range(200):
    m = random.randrange(0, pub.n)
    c = pub.encrypt(m)
    assert priv.decrypt(c) == m, "roundtrip failed"
    ok += 1
print("roundtrip OK:", ok, "/ 200")

# 2. ciphertext + ciphertext
for _ in range(100):
    a = random.randrange(0, pub.n)
    b = random.randrange(0, pub.n - a)
    ca, cb = pub.encrypt(a), pub.encrypt(b)
    assert priv.decrypt(pub.add(ca, cb)) == a + b, "ct+ct failed"
print("ct+ct OK: 100/100")

# 3. ciphertext + plaintext
for _ in range(100):
    a = random.randrange(0, pub.n)
    b = random.randrange(0, pub.n - a)
    ca = pub.encrypt(a)
    assert priv.decrypt(pub.add_plain(ca, b)) == a + b, "ct+pt failed"
print("ct+pt OK: 100/100")

# 4. scalar mult
for _ in range(100):
    a = random.randrange(0, pub.n)
    k = random.randrange(0, 1000)
    ca = pub.encrypt(a)
    expected = (a * k) % pub.n
    assert priv.decrypt(pub.mul_plain(ca, k)) == expected, "mul failed"
print("scalar mul OK: 100/100")

# 5. CRT decrypt == standard decrypt
c = pub.encrypt(random.randrange(0, pub.n))
assert priv.decrypt_crt(c) == priv.decrypt(c), "crt mismatch"
print("crt == standard OK")

# 6. batch decrypt (CRT path)
vals = [random.randrange(0, pub.n) for _ in range(50)]
cs = [pub.encrypt(v) for v in vals]
out = priv.decrypt_batch(cs, use_crt=True)
assert out == vals, "batch decrypt failed"
print("batch decrypt OK: 50/50")

# 7. EncryptedNumber ergonomics
x = pub.encrypt_number(10)
y = pub.encrypt_number(32)
z = (x + y + 5) * 3
assert z.decrypt(priv) == (10 + 32 + 5) * 3 % pub.n, "EncryptedNumber failed"
print("EncryptedNumber OK: (10+32+5)*3 =", z.decrypt(priv))

# 8. CRT speedup sanity
c = pub.encrypt(random.randrange(0, pub.n))
t0 = time.time()
for _ in range(20):
    priv.decrypt(c)
t_std = time.time() - t0
t0 = time.time()
for _ in range(20):
    priv.decrypt_crt(c)
t_crt = time.time() - t0
print("20x decrypt: standard=%.3fs  crt=%.3fs  speedup=%.1fx" % (t_std, t_crt, t_std / max(t_crt, 1e-9)))

print("\nALL TESTS PASSED")
