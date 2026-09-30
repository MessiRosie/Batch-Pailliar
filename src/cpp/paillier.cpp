#include "paillier.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

static std::string to_hex(const mpz_t v) {
    char* s = mpz_get_str(nullptr, 16, v);
    std::string out = s ? std::string(s) : std::string("0");
    if (s) free(s);
    return out;
}

static void from_hex(mpz_t out, const std::string& h) {
    if (mpz_set_str(out, h.c_str(), 16) != 0)
        throw std::runtime_error("invalid hex string");
}

Paillier::Paillier() {
    mpz_inits(n_, n2_, g_, lambda_, mu_, p_, q_, p2_, q2_, hp_, hq_, pinvq_, nullptr);
    gmp_randinit_mt(rng_);
    seed_rng();
}

Paillier::~Paillier() {
    mpz_clears(n_, n2_, g_, lambda_, mu_, p_, q_, p2_, q2_, hp_, hq_, pinvq_, nullptr);
    gmp_randclear(rng_);
}

void Paillier::seed_rng() {
    unsigned char seed[128];
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) throw std::runtime_error("cannot open /dev/urandom");
    if (fread(seed, 1, sizeof(seed), f) != sizeof(seed)) {
        fclose(f);
        throw std::runtime_error("cannot read /dev/urandom");
    }
    fclose(f);
    mpz_t seedz;
    mpz_init(seedz);
    mpz_import(seedz, sizeof(seed), 1, 1, 0, 0, seed);
    gmp_randseed(rng_, seedz);
    mpz_clear(seedz);
}

void Paillier::keygen(int bits) {
    if (bits < 32) throw std::runtime_error("bit length too small");
    int half = bits / 2;
    mpz_t pm1, qm1, t;
    mpz_inits(pm1, qm1, t, nullptr);

    mpz_urandomb(p_, rng_, half);
    mpz_nextprime(p_, p_);
    mpz_urandomb(q_, rng_, half);
    mpz_nextprime(q_, q_);
    while (mpz_cmp(p_, q_) == 0) {
        mpz_urandomb(q_, rng_, half);
        mpz_nextprime(q_, q_);
    }

    mpz_mul(n_, p_, q_);
    mpz_mul(n2_, n_, n_);
    mpz_add_ui(g_, n_, 1);   // g = n + 1

    mpz_sub_ui(pm1, p_, 1);
    mpz_sub_ui(qm1, q_, 1);
    mpz_lcm(lambda_, pm1, qm1);

    // mu = (L(g^lambda mod n^2))^-1 mod n
    mpz_powm(t, g_, lambda_, n2_);
    mpz_sub_ui(t, t, 1);
    mpz_divexact(t, t, n_);
    mpz_invert(mu_, t, n_);

    has_public_ = true;
    has_private_ = true;
    recompute_crt();

    mpz_clears(pm1, qm1, t, nullptr);
}

void Paillier::recompute_crt() {
    if (!has_private_) return;
    mpz_t pm1, qm1, t;
    mpz_inits(pm1, qm1, t, nullptr);

    mpz_mul(p2_, p_, p_);
    mpz_mul(q2_, q_, q_);
    mpz_sub_ui(pm1, p_, 1);
    mpz_sub_ui(qm1, q_, 1);

    // h_p = (L_p(g^(p-1) mod p^2))^-1 mod p
    mpz_powm(t, g_, pm1, p2_);
    mpz_sub_ui(t, t, 1);
    mpz_divexact(t, t, p_);
    mpz_invert(hp_, t, p_);

    // h_q = (L_q(g^(q-1) mod q^2))^-1 mod q
    mpz_powm(t, g_, qm1, q2_);
    mpz_sub_ui(t, t, 1);
    mpz_divexact(t, t, q_);
    mpz_invert(hq_, t, q_);

    // p^-1 mod q
    mpz_invert(pinvq_, p_, q_);

    mpz_clears(pm1, qm1, t, nullptr);
}

bool Paillier::set_public_key(const std::string& n_hex, const std::string& g_hex) {
    try {
        mpz_t n, g;
        mpz_inits(n, g, nullptr);
        from_hex(n, n_hex);
        from_hex(g, g_hex);
        mpz_set(n_, n);
        mpz_set(g_, g);
        mpz_mul(n2_, n_, n_);
        has_public_ = true;
        mpz_clears(n, g, nullptr);
        return true;
    } catch (...) {
        return false;
    }
}

bool Paillier::set_private_key(const std::string& n_hex, const std::string& lambda_hex,
                               const std::string& mu_hex, const std::string& p_hex,
                               const std::string& q_hex) {
    try {
        mpz_t v;
        mpz_init(v);
        from_hex(v, n_hex);      mpz_set(n_, v);
        mpz_mul(n2_, n_, n_);
        mpz_add_ui(g_, n_, 1);
        from_hex(v, lambda_hex); mpz_set(lambda_, v);
        from_hex(v, mu_hex);     mpz_set(mu_, v);
        from_hex(v, p_hex);      mpz_set(p_, v);
        from_hex(v, q_hex);      mpz_set(q_, v);
        mpz_clear(v);
        has_public_ = true;
        has_private_ = true;
        recompute_crt();
        return true;
    } catch (...) {
        return false;
    }
}

std::string Paillier::pub_n_hex() const  { ensure_public(); return to_hex(n_); }
std::string Paillier::pub_g_hex() const  { ensure_public(); return to_hex(g_); }
std::string Paillier::pub_n2_hex() const { ensure_public(); return to_hex(n2_); }
std::string Paillier::priv_lambda_hex() const { ensure_private(); return to_hex(lambda_); }
std::string Paillier::priv_mu_hex() const     { ensure_private(); return to_hex(mu_); }
std::string Paillier::priv_p_hex() const      { ensure_private(); return to_hex(p_); }
std::string Paillier::priv_q_hex() const      { ensure_private(); return to_hex(q_); }

void Paillier::ensure_public() const {
    if (!has_public_) throw std::runtime_error("public key not set");
}
void Paillier::ensure_private() const {
    if (!has_private_) throw std::runtime_error("private key not set");
}

std::string Paillier::encrypt(const std::string& m_hex) {
    ensure_public();
    mpz_t m, r, t, c;
    mpz_inits(m, r, t, c, nullptr);
    from_hex(m, m_hex);
    if (mpz_sgn(m) < 0 || mpz_cmp(m, n_) >= 0) {
        mpz_clears(m, r, t, c, nullptr);
        throw std::runtime_error("plaintext out of range [0, n)");
    }
    // c = (1 + m*n) * r^n mod n^2   (g = n+1  =>  g^m = 1 + m*n mod n^2)
    mpz_mul(t, m, n_);
    mpz_add_ui(t, t, 1);
    mpz_urandomm(r, rng_, n_);
    if (mpz_sgn(r) == 0) mpz_set_ui(r, 1);
    mpz_powm(r, r, n_, n2_);
    mpz_mul(c, t, r);
    mpz_mod(c, c, n2_);
    std::string out = to_hex(c);
    mpz_clears(m, r, t, c, nullptr);
    return out;
}

std::string Paillier::decrypt(const std::string& c_hex) {
    ensure_private();
    mpz_t c, t, m;
    mpz_inits(c, t, m, nullptr);
    from_hex(c, c_hex);
    // m = L(c^lambda mod n^2) * mu mod n
    mpz_powm(t, c, lambda_, n2_);
    mpz_sub_ui(t, t, 1);
    mpz_divexact(t, t, n_);
    mpz_mul(m, t, mu_);
    mpz_mod(m, m, n_);
    std::string out = to_hex(m);
    mpz_clears(c, t, m, nullptr);
    return out;
}

std::string Paillier::decrypt_crt(const std::string& c_hex) {
    ensure_private();
    mpz_t c, mp, mq, t, d, m, pm1, qm1;
    mpz_inits(c, mp, mq, t, d, m, pm1, qm1, nullptr);
    from_hex(c, c_hex);

    mpz_sub_ui(pm1, p_, 1);
    mpz_sub_ui(qm1, q_, 1);

    // m_p = L_p(c^(p-1) mod p^2) * h_p mod p
    mpz_powm(t, c, pm1, p2_);
    mpz_sub_ui(t, t, 1);
    mpz_divexact(t, t, p_);
    mpz_mul(mp, t, hp_);
    mpz_mod(mp, mp, p_);

    // m_q = L_q(c^(q-1) mod q^2) * h_q mod q
    mpz_powm(t, c, qm1, q2_);
    mpz_sub_ui(t, t, 1);
    mpz_divexact(t, t, q_);
    mpz_mul(mq, t, hq_);
    mpz_mod(mq, mq, q_);

    // CRT: m = m_p + p * ((m_q - m_p) * p^-1 mod q)
    mpz_sub(d, mq, mp);
    mpz_mul(d, d, pinvq_);
    mpz_mod(d, d, q_);
    mpz_mul(d, d, p_);
    mpz_add(m, mp, d);
    mpz_mod(m, m, n_);

    std::string out = to_hex(m);
    mpz_clears(c, mp, mq, t, d, m, pm1, qm1, nullptr);
    return out;
}

std::string Paillier::add(const std::string& c1_hex, const std::string& c2_hex) {
    ensure_public();
    mpz_t c1, c2, c;
    mpz_inits(c1, c2, c, nullptr);
    from_hex(c1, c1_hex);
    from_hex(c2, c2_hex);
    mpz_mul(c, c1, c2);
    mpz_mod(c, c, n2_);
    std::string out = to_hex(c);
    mpz_clears(c1, c2, c, nullptr);
    return out;
}

std::string Paillier::add_plain(const std::string& c_hex, const std::string& m_hex) {
    ensure_public();
    mpz_t c, m, t, out;
    mpz_inits(c, m, t, out, nullptr);
    from_hex(c, c_hex);
    from_hex(m, m_hex);
    // c' = c * g^m = c * (1 + m*n) mod n^2
    mpz_mul(t, m, n_);
    mpz_add_ui(t, t, 1);
    mpz_mul(out, c, t);
    mpz_mod(out, out, n2_);
    std::string res = to_hex(out);
    mpz_clears(c, m, t, out, nullptr);
    return res;
}

std::string Paillier::mul_plain(const std::string& c_hex, const std::string& m_hex) {
    ensure_public();
    mpz_t c, m, out;
    mpz_inits(c, m, out, nullptr);
    from_hex(c, c_hex);
    from_hex(m, m_hex);
    // c' = c^m mod n^2
    mpz_powm(out, c, m, n2_);
    std::string res = to_hex(out);
    mpz_clears(c, m, out, nullptr);
    return res;
}
