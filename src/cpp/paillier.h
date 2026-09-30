#pragma once

#include <gmp.h>
#include <string>
#include <stdexcept>

// Paillier homomorphic encryption.
//
// Public key  : (n, g) with g = n + 1, n = p * q.
// Private key : lambda = lcm(p-1, q-1), mu = (L(g^lambda mod n^2))^-1 mod n,
//               plus p, q for CRT-accelerated decryption.
//
// Homomorphic properties:
//   Dec(c1 * c2  mod n^2) = m1 + m2      (ciphertext + ciphertext)
//   Dec(c  * g^m mod n^2) = m_c + m      (ciphertext + plaintext)
//   Dec(c ^ m    mod n^2) = m_c * m      (ciphertext * plaintext scalar)
//
// All values cross this class boundary as lowercase hex strings.
class Paillier {
public:
    Paillier();
    ~Paillier();
    Paillier(const Paillier&) = delete;
    Paillier& operator=(const Paillier&) = delete;

    // Generate a fresh key pair. bits = bit length of n (= p*q).
    void keygen(int bits);

    // Import keys (hex strings) to reload a persisted key pair.
    bool set_public_key(const std::string& n_hex, const std::string& g_hex);
    bool set_private_key(const std::string& n_hex, const std::string& lambda_hex,
                         const std::string& mu_hex, const std::string& p_hex,
                         const std::string& q_hex);

    // Key material export (hex).
    std::string pub_n_hex() const;
    std::string pub_g_hex() const;
    std::string pub_n2_hex() const;
    std::string priv_lambda_hex() const;
    std::string priv_mu_hex() const;
    std::string priv_p_hex() const;
    std::string priv_q_hex() const;

    // Core operations (hex in / hex out). Plaintexts must be in [0, n).
    std::string encrypt(const std::string& m_hex);
    std::string decrypt(const std::string& c_hex);
    std::string decrypt_crt(const std::string& c_hex);   // CRT-accelerated

    std::string add(const std::string& c1_hex, const std::string& c2_hex);
    std::string add_plain(const std::string& c_hex, const std::string& m_hex);
    std::string mul_plain(const std::string& c_hex, const std::string& m_hex);

    bool has_public() const { return has_public_; }
    bool has_private() const { return has_private_; }

private:
    void ensure_public() const;
    void ensure_private() const;
    void recompute_crt();
    void seed_rng();

    mpz_t n_, n2_, g_;          // public
    mpz_t lambda_, mu_;         // private (fast decryption)
    mpz_t p_, q_;               // private (CRT)
    mpz_t p2_, q2_, hp_, hq_;   // CRT precompute: p^2, q^2, h_p, h_q
    mpz_t pinvq_;               // p^-1 mod q
    gmp_randstate_t rng_;
    bool has_public_ = false;
    bool has_private_ = false;
};
