#include "oaep.hpp"
#include "rng.hpp"
#include "rsa_core.hpp"
#include "rsa_math.hpp"
#include "sha256.hpp"
#include "ct.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

static int g_fail = 0;

static void check(bool cond, const char* name)
{
    std::printf("[%s] %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) {
        g_fail++;
    }
}

static uint64_t ticks()
{
#if defined(__x86_64__) || defined(__i386__)
    _mm_lfence();
    uint64_t t = __rdtsc();
    _mm_lfence();
    return t;
#else
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
#endif
}

static double seconds_now()
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

static void test_sha256()
{
    std::printf("\n=== SHA-256 ===\n");
    uint8_t out[32];
    const uint8_t abc_expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    const uint8_t empty_expected[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    sha256(reinterpret_cast<const uint8_t*>("abc"), 3, out);
    check(std::memcmp(out, abc_expected, 32) == 0, "SHA-256(\"abc\")");
    sha256(nullptr, 0, out);
    check(std::memcmp(out, empty_expected, 32) == 0, "SHA-256(\"\")");
}

static void test_number_theory()
{
    std::printf("\n=== Number theory module ===\n");
    BigInt x;
    BigInt y;
    BigInt g = ext_gcd(BigInt(240), BigInt(46), x, y);
    check(g == BigInt(2) && BigInt(240) * x + BigInt(46) * y == g, "extended Euclid: 240*x + 46*y = gcd = 2");
    check(mod_inverse(BigInt(17), BigInt(3120)) == BigInt(2753), "modular inverse 17^-1 mod 3120 = 2753");
    check(mod_pow(BigInt(4), BigInt(13), BigInt(497)) == BigInt(445), "modular exponentiation 4^13 mod 497 = 445");
    BigInt m127 = BigInt(1).shifted_left(127) - BigInt(1);
    check(is_probable_prime(BigInt(7919), 20), "Miller-Rabin: 7919 is prime");
    check(is_probable_prime(m127, 20), "Miller-Rabin: 2^127-1 is prime");
    check(!is_probable_prime(BigInt(561), 20), "Miller-Rabin: Carmichael number 561 is composite");
    check(!is_probable_prime(BigInt(1).shifted_left(127) + BigInt(1), 20), "Miller-Rabin: 2^127+1 is composite");
}

static void test_crt_demo()
{
    std::printf("\n=== CRT / Garner demo on small numbers ===\n");
    PrivateKey k;
    k.p = BigInt(61);
    k.q = BigInt(53);
    k.n = k.p * k.q;
    BigInt lambda = lcm(k.p - BigInt(1), k.q - BigInt(1));
    BigInt e(17);
    k.d = mod_inverse(e, lambda);
    k.dp = k.d % (k.p - BigInt(1));
    k.dq = k.d % (k.q - BigInt(1));
    k.qinv = mod_inverse(k.q, k.p);
    PublicKey pub;
    pub.n = k.n;
    pub.e = e;
    std::printf("p=%lu q=%lu N=%lu lambda=%lu e=%lu d=%lu\n", k.p.to_ulong(), k.q.to_ulong(), k.n.to_ulong(),
                lambda.to_ulong(), e.to_ulong(), k.d.to_ulong());
    std::printf("dp=%lu dq=%lu qinv=%lu\n", k.dp.to_ulong(), k.dq.to_ulong(), k.qinv.to_ulong());
    BigInt m(65);
    BigInt c = rsa_encrypt_raw(m, pub);
    std::printf("m=%lu c=m^e mod N=%lu\n", m.to_ulong(), c.to_ulong());
    BigInt m1 = mod_pow(c % k.p, k.dp, k.p);
    BigInt m2 = mod_pow(c % k.q, k.dq, k.q);
    BigInt diff = m1 - m2;
    if (diff < BigInt(0)) {
        diff = diff + k.p;
    }
    BigInt h = (k.qinv * diff) % k.p;
    BigInt result = m2 + h * k.q;
    std::printf("m1=c^dp mod p=%lu m2=c^dq mod q=%lu (m1-m2) mod p=%lu h=%lu m=m2+h*q=%lu\n",
                m1.to_ulong(), m2.to_ulong(), diff.to_ulong(), h.to_ulong(), result.to_ulong());
    check(result == m, "Garner steps restore the message");
    check(rsa_decrypt_crt(c, k) == m, "rsa_decrypt_crt on small key");
    check(rsa_decrypt_plain(c, k) == m, "rsa_decrypt_plain on small key");
}

static KeyPair g_keys;

static void test_keygen()
{
    std::printf("\n=== Key generation (2048 bit) ===\n");
    double t0 = seconds_now();
    g_keys = generate_keypair(2048);
    double t1 = seconds_now();
    std::printf("key generation time: %.2f s\n", t1 - t0);
    const PrivateKey& k = g_keys.priv;
    check(g_keys.pub.n.bit_length() == 2048, "modulus N has exactly 2048 bits");
    check(k.p.bit_length() == 1024 && k.q.bit_length() == 1024, "p and q have 1024 bits each");
    check(k.p * k.q == g_keys.pub.n, "N = p * q");
    BigInt lambda = lcm(k.p - BigInt(1), k.q - BigInt(1));
    check((g_keys.pub.e * k.d) % lambda == BigInt(1), "e*d = 1 mod lambda(N)");
    check((k.q * k.qinv) % k.p == BigInt(1), "q*qinv = 1 mod p");
    check(k.dp == k.d % (k.p - BigInt(1)) && k.dq == k.d % (k.q - BigInt(1)), "dp, dq computed correctly");
    uint8_t buf[255];
    random_bytes(buf, sizeof(buf));
    BigInt m = BigInt::from_bytes(buf, sizeof(buf));
    BigInt c = rsa_encrypt_raw(m, g_keys.pub);
    check(rsa_decrypt_crt(c, k) == m, "raw RSA with CRT: decrypt(encrypt(m)) = m");
    check(rsa_decrypt_crt(c, k) == rsa_decrypt_plain(c, k), "CRT result equals plain c^d mod N");

    const int iterations = 20;
    double a0 = seconds_now();
    for (int i = 0; i < iterations; i++) {
        rsa_decrypt_plain(c, k);
    }
    double a1 = seconds_now();
    for (int i = 0; i < iterations; i++) {
        rsa_decrypt_crt(c, k);
    }
    double a2 = seconds_now();
    double plain = (a1 - a0) / iterations;
    double crt = (a2 - a1) / iterations;
    std::printf("plain decrypt: %.3f ms, CRT decrypt: %.3f ms, speedup: x%.2f\n", plain * 1e3, crt * 1e3, plain / crt);
    check(crt < plain, "CRT decryption is faster than plain decryption");
}

static void test_oaep_roundtrip()
{
    std::printf("\n=== OAEP encrypt/decrypt (k=%zu, hLen=%zu, max message=%zu) ===\n", OAEP_K, OAEP_HLEN, OAEP_MAX_MSG);
    const size_t lengths[] = {0, 1, 16, 100, OAEP_MAX_MSG - 1, OAEP_MAX_MSG};
    for (size_t t = 0; t < sizeof(lengths) / sizeof(lengths[0]); t++) {
        size_t len = lengths[t];
        uint8_t msg[OAEP_MAX_MSG];
        uint8_t ct[OAEP_K];
        OaepResult res;
        random_bytes(msg, sizeof(msg));
        bool enc = oaep_encrypt(msg, len, nullptr, 0, g_keys.pub, ct);
        bool dec = oaep_decrypt(ct, nullptr, 0, g_keys.priv, res);
        bool same = enc && dec && res.ok == 1 && res.len == len && (len == 0 || std::memcmp(res.msg, msg, len) == 0);
        char name[96];
        std::snprintf(name, sizeof(name), "roundtrip, message length = %zu bytes", len);
        check(same, name);
    }
    uint8_t big[OAEP_MAX_MSG + 1];
    uint8_t ct[OAEP_K];
    random_bytes(big, sizeof(big));
    check(!oaep_encrypt(big, sizeof(big), nullptr, 0, g_keys.pub, ct), "message longer than k-2*hLen-2 is rejected");

    const uint8_t label[] = {'l', 'a', 'b', 'e', 'l'};
    const uint8_t msg2[] = {'h', 'e', 'l', 'l', 'o'};
    OaepResult res;
    oaep_encrypt(msg2, sizeof(msg2), label, sizeof(label), g_keys.pub, ct);
    oaep_decrypt(ct, label, sizeof(label), g_keys.priv, res);
    check(res.ok == 1 && res.len == sizeof(msg2) && std::memcmp(res.msg, msg2, sizeof(msg2)) == 0, "roundtrip with non-empty label");
    oaep_decrypt(ct, nullptr, 0, g_keys.priv, res);
    check(res.ok == 0 && res.len == 0, "wrong label is rejected");

    uint8_t ct1[OAEP_K];
    uint8_t ct2[OAEP_K];
    oaep_encrypt(msg2, sizeof(msg2), nullptr, 0, g_keys.pub, ct1);
    oaep_encrypt(msg2, sizeof(msg2), nullptr, 0, g_keys.pub, ct2);
    check(std::memcmp(ct1, ct2, OAEP_K) != 0, "OAEP is probabilistic: same message gives different ciphertexts");

    oaep_encrypt(msg2, sizeof(msg2), nullptr, 0, g_keys.pub, ct1);
    ct1[OAEP_K - 1] ^= 0x01;
    bool dec = oaep_decrypt(ct1, nullptr, 0, g_keys.priv, res);
    check(dec && res.ok == 0 && res.len == 0, "corrupted ciphertext is rejected");
    bool all_zero = true;
    for (size_t i = 0; i < OAEP_MAX_MSG; i++) {
        if (res.msg[i] != 0) {
            all_zero = false;
        }
    }
    check(all_zero, "rejected output buffer contains no data");
}

constexpr int CLASSES = 6;
constexpr int SAMPLES = 20000;
static uint64_t g_samples[CLASSES][SAMPLES];

static uint64_t median_of(uint64_t* data, int n)
{
    std::sort(data, data + n);
    return data[n / 2];
}

static double mean_of(const uint64_t* data, int n)
{
    double s = 0;
    for (int i = 0; i < n; i++) {
        s += static_cast<double>(data[i]);
    }
    return s / n;
}

static void test_unpad_validity_and_timing()
{
    std::printf("\n=== OAEP unpad: structural cases and constant-time measurement ===\n");
    uint8_t ems[CLASSES][OAEP_K];
    const char* names[CLASSES] = {
        "valid, message 0 bytes", "valid, message 190 bytes", "invalid first byte", "invalid lHash",
        "no 0x01 separator", "garbage byte in PS"
    };
    uint8_t msg[OAEP_MAX_MSG];
    random_bytes(msg, sizeof(msg));
    const uint8_t other_label[] = {'x'};

    oaep_pad(msg, 0, nullptr, 0, ems[0]);
    oaep_pad(msg, OAEP_MAX_MSG, nullptr, 0, ems[1]);
    oaep_pad(msg, 10, nullptr, 0, ems[2]);
    ems[2][0] = 0x01;
    oaep_pad(msg, 10, other_label, 1, ems[3]);

    uint8_t db[OAEP_DBLEN];
    uint8_t seed[OAEP_HLEN];
    random_bytes(seed, sizeof(seed));
    std::memset(db, 0, sizeof(db));
    sha256(nullptr, 0, db);
    oaep_encode(db, seed, ems[4]);

    std::memset(db, 0, sizeof(db));
    sha256(nullptr, 0, db);
    db[OAEP_HLEN + 5] = 0x02;
    db[OAEP_DBLEN - 6] = 0x01;
    oaep_encode(db, seed, ems[5]);

    OaepResult res;
    oaep_unpad(ems[0], nullptr, 0, res);
    check(res.ok == 1 && res.len == 0, "unpad accepts valid EM with empty message");
    oaep_unpad(ems[1], nullptr, 0, res);
    check(res.ok == 1 && res.len == OAEP_MAX_MSG && std::memcmp(res.msg, msg, OAEP_MAX_MSG) == 0, "unpad accepts valid EM with maximum message");
    for (int c = 2; c < CLASSES; c++) {
        oaep_unpad(ems[c], nullptr, 0, res);
        char name[96];
        std::snprintf(name, sizeof(name), "unpad rejects EM: %s", names[c]);
        check(res.ok == 0 && res.len == 0, name);
    }

    uint32_t sink = 0;
    for (int i = 0; i < 2000; i++) {
        for (int c = 0; c < CLASSES; c++) {
            oaep_unpad(ems[c], nullptr, 0, res);
            sink |= res.ok;
        }
    }
    for (int i = 0; i < SAMPLES; i++) {
        for (int c = 0; c < CLASSES; c++) {
            uint64_t t0 = ticks();
            oaep_unpad(ems[c], nullptr, 0, res);
            uint64_t t1 = ticks();
            g_samples[c][i] = t1 - t0;
            sink |= res.ok;
        }
    }
    double means[CLASSES];
    uint64_t medians[CLASSES];
    for (int c = 0; c < CLASSES; c++) {
        means[c] = mean_of(g_samples[c], SAMPLES);
        medians[c] = median_of(g_samples[c], SAMPLES);
    }
    std::printf("%-28s %12s %12s %10s\n", "EM class", "median", "mean", "vs valid");
    double worst = 0;
    for (int c = 0; c < CLASSES; c++) {
        double rel = (static_cast<double>(medians[c]) - static_cast<double>(medians[0])) * 100.0 / static_cast<double>(medians[0]);
        if (rel < 0) {
            rel = -rel;
        }
        if (rel > worst) {
            worst = rel;
        }
        std::printf("%-28s %12llu %12.1f %9.2f%%\n", names[c], static_cast<unsigned long long>(medians[c]), means[c],
                    (static_cast<double>(medians[c]) - static_cast<double>(medians[0])) * 100.0 / static_cast<double>(medians[0]));
    }
    std::printf("max median deviation between classes: %.2f%% (sink=%u)\n", worst, sink);
    check(worst < 5.0, "unpad timing is independent of EM validity (median deviation < 5%)");
}

static void test_decrypt_timing()
{
    std::printf("\n=== Full decryption: valid vs corrupted ciphertext (cycles) ===\n");
    const int n = 400;
    static uint64_t valid_t[400];
    static uint64_t bad_t[400];
    uint8_t msg[32];
    uint8_t ct_valid[OAEP_K];
    uint8_t ct_bad[OAEP_K];
    OaepResult res;
    uint32_t sink = 0;
    random_bytes(msg, sizeof(msg));
    oaep_encrypt(msg, sizeof(msg), nullptr, 0, g_keys.pub, ct_valid);
    std::memcpy(ct_bad, ct_valid, OAEP_K);
    ct_bad[OAEP_K - 1] ^= 0x01;
    for (int i = 0; i < 20; i++) {
        oaep_decrypt(ct_valid, nullptr, 0, g_keys.priv, res);
        oaep_decrypt(ct_bad, nullptr, 0, g_keys.priv, res);
    }
    for (int i = 0; i < n; i++) {
        uint64_t t0 = ticks();
        oaep_decrypt(ct_valid, nullptr, 0, g_keys.priv, res);
        uint64_t t1 = ticks();
        sink |= res.ok;
        valid_t[i] = t1 - t0;
        uint64_t t2 = ticks();
        oaep_decrypt(ct_bad, nullptr, 0, g_keys.priv, res);
        uint64_t t3 = ticks();
        sink |= res.ok;
        bad_t[i] = t3 - t2;
    }
    double mv = mean_of(valid_t, n);
    double mb = mean_of(bad_t, n);
    uint64_t dv = median_of(valid_t, n);
    uint64_t db = median_of(bad_t, n);
    double rel = (static_cast<double>(db) - static_cast<double>(dv)) * 100.0 / static_cast<double>(dv);
    std::printf("valid ciphertext:     median %llu mean %.1f\n", static_cast<unsigned long long>(dv), mv);
    std::printf("corrupted ciphertext: median %llu mean %.1f\n", static_cast<unsigned long long>(db), mb);
    std::printf("median difference: %.2f%% (sink=%u)\n", rel, sink);
    check((rel < 0 ? -rel : rel) < 5.0, "decrypt time of valid and corrupted ciphertext is the same (< 5%)");
}

int main()
{
    test_sha256();
    test_number_theory();
    test_crt_demo();
    test_keygen();
    test_oaep_roundtrip();
    test_unpad_validity_and_timing();
    test_decrypt_timing();
    std::printf("\nTOTAL FAILED: %d\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
