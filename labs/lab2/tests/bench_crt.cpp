// Замер ускорения CRT: c^d mod N напрямую против Гарнера.
#include "rsa_core.hpp"
#include <x86intrin.h>
#include <algorithm>
#include <cstdio>
#include <vector>
int main() {
    PublicKey pub; PrivateKey prv; nt::generate_keypair(pub, prv, cfg::RSA_BITS);
    BigInt m, c, r; nt::random_bits(m, cfg::RSA_BITS - 8, false); rsa::encrypt_raw(c, m, pub);
    std::vector<uint64_t> a, b;
    for (int i = 0; i < 40; ++i) {
        uint64_t t = __rdtsc(); rsa::decrypt_plain(r, c, prv); a.push_back(__rdtsc() - t);
        t = __rdtsc(); rsa::decrypt_crt(r, c, prv); b.push_back(__rdtsc() - t);
    }
    std::sort(a.begin(), a.end()); std::sort(b.begin(), b.end());
    std::printf("прямое c^d mod N : %.0f тактов\nCRT (Гарнер)     : %.0f тактов\nускорение        : %.2fx\n", double(a[20]), double(b[20]), double(a[20]) / b[20]);
}
