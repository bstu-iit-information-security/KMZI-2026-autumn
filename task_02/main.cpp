#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <x86intrin.h>
#include "oaep.hpp"

static void hex(const std::uint8_t* d, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) std::printf("%02x", d[i]);
}

static bool check_sha3() {
    std::uint8_t out[32];
    const char* abc = "abc";
    sha3::sha3_256(out, nullptr, 0);
    const std::uint8_t e0[32] = {0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47,
                                 0x56, 0xa0, 0x61, 0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b,
                                 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a};
    bool ok = std::memcmp(out, e0, 32) == 0;
    sha3::sha3_256(out, reinterpret_cast<const std::uint8_t*>(abc), 3);
    const std::uint8_t e1[32] = {0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17,
                                 0x2d, 0x6b, 0xd3, 0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d,
                                 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32};
    ok = ok && std::memcmp(out, e1, 32) == 0;
    return ok;
}

static std::uint64_t median(std::array<std::uint64_t, 31>& a) {
    std::sort(a.begin(), a.end());
    return a[a.size() / 2];
}

int main() {
    std::printf("SHA3-256 KAT: %s\n", check_sha3() ? "OK" : "FAIL");

    static rsa::PublicKey pub;
    static rsa::PrivateKey prv;
    auto t0 = std::chrono::steady_clock::now();
    rsa::generate_keypair(pub, prv, 3072);
    auto t1 = std::chrono::steady_clock::now();
    std::printf("keygen 3072 bit: %.2f s, bitlen(N)=%d\n",
                std::chrono::duration<double>(t1 - t0).count(), bn::bitlen(pub.n));

    bn::Big one = bn::from_u64(1), pm1, qm1, t, ed, rem;
    bn::sub(pm1, prv.p, one);
    bn::sub(qm1, prv.q, one);
    bn::mul(ed, prv.e, prv.d);
    bn::divmod(t, rem, ed, pm1);
    bool kc1 = bn::eq_u64(rem, 1);
    bn::divmod(t, rem, ed, qm1);
    bool kc2 = bn::eq_u64(rem, 1);
    std::printf("e*d = 1 mod (p-1), mod (q-1): %s\n", (kc1 && kc2) ? "OK" : "FAIL");

    bool all_ok = true;
    for (int i = 0; i < 5; ++i) {
        std::uint8_t buf[384];
        bn::Big m, c, m_plain, m_crt, m_blind;
        rsa::random_bytes(buf, 384);
        buf[0] = 0;
        bn::from_bytes_be(m, buf, 384);
        rsa::rsa_encrypt(c, m, pub);
        rsa::rsa_decrypt_plain(m_plain, c, prv);
        rsa::rsa_decrypt_crt(m_crt, c, prv);
        rsa::rsa_decrypt_blinded(m_blind, c, prv);
        bool ok = bn::cmp(m, m_plain) == 0 && bn::cmp(m, m_crt) == 0 && bn::cmp(m, m_blind) == 0;
        all_ok = all_ok && ok;
    }
    std::printf("raw RSA: plain == CRT == blinded == m: %s\n", all_ok ? "OK" : "FAIL");

    const std::size_t lens[] = {0, 1, 17, 100, 317, oaep::MAXMSG};
    for (std::size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); ++li) {
        std::size_t len = lens[li];
        std::uint8_t msg[oaep::MAXMSG];
        std::uint8_t ct[oaep::K];
        std::uint8_t out[oaep::MAXMSG];
        std::size_t outlen = 0;
        rsa::random_bytes(msg, oaep::MAXMSG);
        bool e = oaep::oaep_encrypt(ct, msg, len, pub);
        bool d = oaep::oaep_decrypt(out, outlen, ct, prv);
        bool ok = e && d && outlen == len && std::memcmp(out, msg, len) == 0;
        std::printf("OAEP roundtrip len=%3zu: %s\n", len, ok ? "OK" : "FAIL");
    }

    {
        std::uint8_t msg[oaep::MAXMSG + 1];
        std::uint8_t ct[oaep::K];
        std::memset(msg, 0x41, sizeof(msg));
        bool e = oaep::oaep_encrypt(ct, msg, oaep::MAXMSG + 1, pub);
        std::printf("OAEP len=%zu rejected: %s\n", oaep::MAXMSG + 1, e ? "FAIL" : "OK");
    }

    {
        std::uint8_t msg[32];
        std::uint8_t ct1[oaep::K];
        std::uint8_t ct2[oaep::K];
        rsa::random_bytes(msg, 32);
        oaep::oaep_encrypt(ct1, msg, 32, pub);
        oaep::oaep_encrypt(ct2, msg, 32, pub);
        std::printf("OAEP probabilistic (ct1 != ct2): %s\n",
                    std::memcmp(ct1, ct2, oaep::K) != 0 ? "OK" : "FAIL");
    }

    {
        std::uint8_t msg[64];
        std::uint8_t ct[oaep::K];
        std::uint8_t bad[oaep::K];
        std::uint8_t out[oaep::MAXMSG];
        std::size_t outlen = 0;
        rsa::random_bytes(msg, 64);
        oaep::oaep_encrypt(ct, msg, 64, pub);
        std::memcpy(bad, ct, oaep::K);
        bad[200] ^= 0x01;
        bool d = oaep::oaep_decrypt(out, outlen, bad, prv);
        bool zeroed = true;
        for (std::size_t i = 0; i < oaep::MAXMSG; ++i) zeroed = zeroed && out[i] == 0;
        std::printf("corrupted ciphertext rejected: %s, output zeroed: %s, outlen=%zu\n",
                    d ? "FAIL" : "OK", zeroed ? "yes" : "no", outlen);
    }

    {
        std::uint8_t msg[64];
        std::uint8_t ct[oaep::K];
        std::uint8_t bad[oaep::K];
        std::uint8_t out[oaep::MAXMSG];
        std::size_t outlen = 0;
        rsa::random_bytes(msg, 64);
        oaep::oaep_encrypt(ct, msg, 64, pub);
        std::memcpy(bad, ct, oaep::K);
        bad[200] ^= 0x01;
        std::array<std::uint64_t, 31> tv, tb;
        for (std::size_t i = 0; i < tv.size(); ++i) {
            unsigned aux;
            std::uint64_t a = __rdtscp(&aux);
            oaep::oaep_decrypt(out, outlen, ct, prv);
            std::uint64_t b = __rdtscp(&aux);
            oaep::oaep_decrypt(out, outlen, bad, prv);
            std::uint64_t c = __rdtscp(&aux);
            tv[i] = b - a;
            tb[i] = c - b;
        }
        std::uint64_t mv = median(tv);
        std::uint64_t mb = median(tb);
        double diff = 100.0 * ((double)mb - (double)mv) / (double)mv;
        std::printf("cycles median valid=%llu corrupted=%llu diff=%.2f%%\n",
                    (unsigned long long)mv, (unsigned long long)mb, diff);
    }

    {
        std::uint8_t msg[16];
        std::uint8_t em[oaep::K];
        std::uint8_t seed[oaep::HLEN];
        for (std::size_t i = 0; i < 16; ++i) msg[i] = (std::uint8_t)i;
        for (std::size_t i = 0; i < oaep::HLEN; ++i) seed[i] = (std::uint8_t)(0xA0 + i);
        oaep::oaep_encode(em, msg, 16, seed);
        std::printf("EM[0..16]=");
        hex(em, 16);
        std::printf("\n");
    }
    return 0;
}
