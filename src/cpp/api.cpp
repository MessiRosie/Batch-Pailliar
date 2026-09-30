#include "paillier.h"

#include <cstdlib>
#include <cstring>

extern "C" {

static char* dup(const std::string& s) {
    char* p = (char*)malloc(s.size() + 1);
    if (p) memcpy(p, s.c_str(), s.size() + 1);
    return p;
}

void* paillier_new() {
    try { return new Paillier(); } catch (...) { return nullptr; }
}

void paillier_free(void* h) {
    if (h) delete (Paillier*)h;
}

void paillier_free_str(char* s) {
    if (s) free(s);
}

int paillier_keygen(void* h, int bits) {
    if (!h) return 0;
    try { ((Paillier*)h)->keygen(bits); return 1; } catch (...) { return 0; }
}

int paillier_has_public(void* h)  { return h ? ((Paillier*)h)->has_public() : 0; }
int paillier_has_private(void* h) { return h ? ((Paillier*)h)->has_private() : 0; }

int paillier_set_public_key(void* h, const char* n, const char* g) {
    if (!h || !n || !g) return 0;
    try { return ((Paillier*)h)->set_public_key(n, g) ? 1 : 0; } catch (...) { return 0; }
}

int paillier_set_private_key(void* h, const char* n, const char* lambda,
                             const char* mu, const char* p, const char* q) {
    if (!h || !n || !lambda || !mu || !p || !q) return 0;
    try {
        return ((Paillier*)h)->set_private_key(n, lambda, mu, p, q) ? 1 : 0;
    } catch (...) { return 0; }
}

char* paillier_pub_n(void* h) { if (!h) return nullptr; try { return dup(((Paillier*)h)->pub_n_hex()); } catch (...) { return nullptr; } }
char* paillier_pub_g(void* h) { if (!h) return nullptr; try { return dup(((Paillier*)h)->pub_g_hex()); } catch (...) { return nullptr; } }
char* paillier_pub_n2(void* h) { if (!h) return nullptr; try { return dup(((Paillier*)h)->pub_n2_hex()); } catch (...) { return nullptr; } }
char* paillier_priv_lambda(void* h) { if (!h) return nullptr; try { return dup(((Paillier*)h)->priv_lambda_hex()); } catch (...) { return nullptr; } }
char* paillier_priv_mu(void* h) { if (!h) return nullptr; try { return dup(((Paillier*)h)->priv_mu_hex()); } catch (...) { return nullptr; } }
char* paillier_priv_p(void* h) { if (!h) return nullptr; try { return dup(((Paillier*)h)->priv_p_hex()); } catch (...) { return nullptr; } }
char* paillier_priv_q(void* h) { if (!h) return nullptr; try { return dup(((Paillier*)h)->priv_q_hex()); } catch (...) { return nullptr; } }

char* paillier_encrypt(void* h, const char* m) {
    if (!h || !m) return nullptr;
    try { return dup(((Paillier*)h)->encrypt(m)); } catch (...) { return nullptr; }
}

char* paillier_decrypt(void* h, const char* c) {
    if (!h || !c) return nullptr;
    try { return dup(((Paillier*)h)->decrypt(c)); } catch (...) { return nullptr; }
}

char* paillier_decrypt_crt(void* h, const char* c) {
    if (!h || !c) return nullptr;
    try { return dup(((Paillier*)h)->decrypt_crt(c)); } catch (...) { return nullptr; }
}

char* paillier_add(void* h, const char* c1, const char* c2) {
    if (!h || !c1 || !c2) return nullptr;
    try { return dup(((Paillier*)h)->add(c1, c2)); } catch (...) { return nullptr; }
}

char* paillier_add_plain(void* h, const char* c, const char* m) {
    if (!h || !c || !m) return nullptr;
    try { return dup(((Paillier*)h)->add_plain(c, m)); } catch (...) { return nullptr; }
}

char* paillier_mul_plain(void* h, const char* c, const char* m) {
    if (!h || !c || !m) return nullptr;
    try { return dup(((Paillier*)h)->mul_plain(c, m)); } catch (...) { return nullptr; }
}

}  // extern "C"
