#include "oaep.hpp"
#include "rsa_core.hpp"
#include "rsa_math.hpp"
#include "sha256.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

int g_failed = 0;

std::string hex_of(const uint8_t* data, std::size_t n) {
    static const char* kDigits = "0123456789abcdef";
    std::string out(n * 2, '0');
    for (std::size_t i = 0; i < n; ++i) {
        out[2 * i] = kDigits[data[i] >> 4];
        out[2 * i + 1] = kDigits[data[i] & 0x0F];
    }
    return out;
}

void expect_true(const char* name, bool ok) {
    if (ok) {
        std::printf("  [OK] %s\n", name);
        return;
    }
    std::printf("  [FAIL] %s\n", name);
    ++g_failed;
}

void expect_eq(const char* name, const std::string& got, const std::string& want) {
    if (got == want) {
        std::printf("  [OK] %s\n", name);
        return;
    }
    std::printf("  [FAIL] %s\n    got  %s\n    want %s\n", name, got.c_str(), want.c_str());
    ++g_failed;
}

void expect_word(const char* name, const Bn& v, unsigned long w) {
    expect_true(name, BN_is_word(v.raw(), static_cast<BN_ULONG>(w)) == 1);
}

uint64_t nsec_now() {
    using clock = std::chrono::steady_clock;
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(clock::now().time_since_epoch()).count());
}

uint64_t ticks_now() {
    uint64_t v;
    asm volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

struct Sample {
    uint64_t ns = 0;
    uint64_t ticks = 0;
};

Sample median_of(std::vector<Sample> v) {
    std::sort(v.begin(), v.end(), [](const Sample& a, const Sample& b) { return a.ns < b.ns; });
    return v[v.size() / 2];
}

void print_samples(const char* name, const std::vector<Sample>& v) {
    const Sample med = median_of(v);
    uint64_t mn = v[0].ns;
    uint64_t mx = v[0].ns;
    for (const Sample& s : v) {
        mn = std::min(mn, s.ns);
        mx = std::max(mx, s.ns);
    }
    std::printf("  %-28s  median %8.3f ms  (%llu ticks)   min %6.3f  max %6.3f\n", name,
                static_cast<double>(med.ns) / 1e6, static_cast<unsigned long long>(med.ticks),
                static_cast<double>(mn) / 1e6, static_cast<double>(mx) / 1e6);
}

void test_sha256() {
    std::printf("\n== SHA-256 ==\n");
    uint8_t out[32];
    Sha256::hash(nullptr, 0, out);
    expect_eq("пустая строка", hex_of(out, 32),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const uint8_t abc[] = {'a', 'b', 'c'};
    Sha256::hash(abc, 3, out);
    expect_eq("abc", hex_of(out, 32),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

void test_math() {
    std::printf("\n== Арифметика: экспонента, обратный, Евклид ==\n");
    Bn base;
    Bn exp;
    Bn mod;
    Bn out;
    Bn a;
    Bn b;
    RsaMath::from_word(base, 2);
    RsaMath::from_word(exp, 10);
    RsaMath::from_word(mod, 1000);
    expect_true("2^10 mod 1000", RsaMath::mod_exp(out, base, exp, mod));
    expect_word("2^10 mod 1000 = 24", out, 24);

    RsaMath::from_word(base, 42);
    RsaMath::from_word(exp, 7);
    RsaMath::from_word(mod, 187);
    expect_true("42^7 mod 187", RsaMath::mod_exp(out, base, exp, mod));
    expect_word("42^7 mod 187 = 15", out, 15);

    RsaMath::from_word(a, 7);
    RsaMath::from_word(mod, 80);
    expect_true("inv(7, 80)", RsaMath::mod_inverse(out, a, mod));
    expect_word("inv(7, 80) = 23", out, 23);

    RsaMath::from_word(a, 17);
    RsaMath::from_word(mod, 11);
    expect_true("inv(17, 11)", RsaMath::mod_inverse(out, a, mod));
    expect_word("inv(17, 11) = 2", out, 2);

    Bn g;
    Bn x;
    Bn y;
    RsaMath::from_word(a, 7);
    RsaMath::from_word(b, 80);
    expect_true("extended_gcd(7, 80)", RsaMath::extended_gcd(g, x, y, a, b));
    expect_word("gcd = 1", g, 1);

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* left = BN_new();
    BIGNUM* t1 = BN_new();
    BIGNUM* t2 = BN_new();
    BN_mul(t1, a.raw(), x.raw(), ctx);
    BN_mul(t2, b.raw(), y.raw(), ctx);
    BN_add(left, t1, t2);
    expect_true("7*x + 80*y = 1", BN_is_one(left) == 1);
    BN_free(left);
    BN_free(t1);
    BN_free(t2);
    BN_CTX_free(ctx);
}

void test_small_rsa() {
    std::printf("\n== RSA-CRT на малых числах: p=11, q=17, e=7, m=42 ==\n");
    RsaPrivateKey key;
    RsaMath::from_word(key.p, 11);
    RsaMath::from_word(key.q, 17);
    RsaMath::from_word(key.e, 7);
    expect_true("derive_private", RsaMath::derive_private(key));
    expect_word("n = 187", key.n, 187);
    expect_word("d = 23", key.d, 23);
    expect_word("dp = 3", key.dp, 3);
    expect_word("dq = 7", key.dq, 7);
    expect_word("qinv = 2", key.qinv, 2);

    Bn message;
    Bn cipher;
    Bn back;
    RsaMath::from_word(message, 42);
    expect_true("encrypt", RsaCore::encrypt(cipher, message, key.e, key.n));
    expect_word("c = 15", cipher, 15);

    expect_true("naive decrypt", RsaCore::decrypt_naive(back, cipher, key.d, key.n));
    expect_word("naive -> 42", back, 42);
    expect_true("crt decrypt", RsaCore::decrypt_crt(back, cipher, key));
    expect_word("crt -> 42", back, 42);

    RsaCore::GarnerTrace tr;
    expect_true("trace m=42", RsaCore::decrypt_crt_trace(back, tr, cipher, key));
    std::printf("  след Гарнера для m=42, c=15:\n");
    std::printf("    m1 = %s (mod p)\n", RsaMath::hex(tr.m1).c_str());
    std::printf("    m2 = %s (mod q)\n", RsaMath::hex(tr.m2).c_str());
    std::printf("    m1 < m2: %s\n", tr.diff_was_negative ? "да" : "нет");
    std::printf("    (m1-m2) mod p = %s\n", RsaMath::hex(tr.diff).c_str());
    std::printf("    h = %s\n", RsaMath::hex(tr.h).c_str());
    std::printf("    m = %s\n", RsaMath::hex(tr.message).c_str());
    expect_word("m1 = 9", tr.m1, 9);
    expect_word("m2 = 8", tr.m2, 8);
    expect_word("diff = 1", tr.diff, 1);
    expect_word("h = 2", tr.h, 2);

    RsaMath::from_word(message, 22);
    expect_true("encrypt m=22", RsaCore::encrypt(cipher, message, key.e, key.n));
    expect_word("c = 44", cipher, 44);
    expect_true("trace m=22", RsaCore::decrypt_crt_trace(back, tr, cipher, key));
    std::printf("  след Гарнера для m=22, c=44 (m1 < m2):\n");
    std::printf("    m1 = %s, m2 = %s, отрицательная разность: %s\n", RsaMath::hex(tr.m1).c_str(),
                RsaMath::hex(tr.m2).c_str(), tr.diff_was_negative ? "да" : "нет");
    std::printf("    (m1-m2) mod p = %s, h = %s, m = %s\n", RsaMath::hex(tr.diff).c_str(),
                RsaMath::hex(tr.h).c_str(), RsaMath::hex(tr.message).c_str());
    expect_true("m1 < m2", tr.diff_was_negative);
    expect_word("m1 = 0", tr.m1, 0);
    expect_word("m2 = 5", tr.m2, 5);
    expect_word("diff = 6", tr.diff, 6);
    expect_word("h = 1", tr.h, 1);
    expect_word("восстановлено 22", back, 22);
}

bool set_bases_words(Bn* bases, const unsigned long* words, int n) {
    for (int i = 0; i < n; ++i) {
        if (!RsaMath::from_word(bases[i], words[i])) {
            return false;
        }
    }
    return true;
}

void test_miller_rabin() {
    std::printf("\n== Миллер–Рабин: корректность CT и VT ==\n");
    const unsigned long primes[] = {97, 101, 103, 409, 1223};
    const unsigned long composites[] = {91, 341, 561, 1001, 2047};
    Bn bases[8];
    const unsigned long witnesses[] = {2, 3, 5, 7, 11};
    expect_true("базы", set_bases_words(bases, witnesses, 5));

    for (unsigned long p : primes) {
        Bn n;
        RsaMath::from_word(n, p);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "CT %lu простое", p);
        expect_true(buf, RsaMath::miller_rabin_ct(n, bases, 5));
        std::snprintf(buf, sizeof(buf), "VT %lu простое", p);
        expect_true(buf, RsaMath::miller_rabin_vt(n, bases, 5));
    }
    for (unsigned long c : composites) {
        Bn n;
        RsaMath::from_word(n, c);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "CT %lu составное", c);
        expect_true(buf, !RsaMath::miller_rabin_ct(n, bases, 5));
        std::snprintf(buf, sizeof(buf), "VT %lu составное", c);
        expect_true(buf, !RsaMath::miller_rabin_vt(n, bases, 5));
    }

    Bn n2047;
    RsaMath::from_word(n2047, 2047);
    Bn only2;
    RsaMath::from_word(only2, 2);
    expect_true("2047 — сильное псевдопростое по базе 2", RsaMath::miller_rabin_ct(n2047, &only2, 1));
    const unsigned long two_three[] = {2, 3};
    Bn bases23[2];
    set_bases_words(bases23, two_three, 2);
    expect_true("2047 составное по базам 2 и 3", !RsaMath::miller_rabin_ct(n2047, bases23, 2));

    int agree = 0;
    int checked = 0;
    for (int i = 0; i < 40; ++i) {
        Bn n;
        if (BN_rand(n.raw(), 48, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD) != 1) {
            expect_true("BN_rand", false);
            return;
        }
        Bn rnd[4];
        if (!RsaMath::random_bases(rnd, 4, n)) {
            expect_true("random_bases", false);
            return;
        }
        const bool ct = RsaMath::miller_rabin_ct(n, rnd, 4);
        const bool vt = RsaMath::miller_rabin_vt(n, rnd, 4);
        ++checked;
        if (ct == vt) {
            ++agree;
        }
    }
    std::printf("  совпадение CT и VT на %d/%d случайных 48-битных числах\n", agree, checked);
    expect_true("CT и VT дают один вердикт", agree == checked);
}

void test_oaep() {
    std::printf("\n== OAEP-SHA256, k=384 ==\n");
    const uint8_t msg[] = {'K', 'M', 'Z', 'I', '-', '1', '1'};
    uint8_t seed[Oaep::kHashLen];
    for (int i = 0; i < Oaep::kHashLen; ++i) {
        seed[i] = static_cast<uint8_t>(i);
    }
    std::array<uint8_t, Oaep::kModulusBytes> em{};
    expect_true("encode_with_seed", Oaep::encode_with_seed(msg, sizeof(msg), nullptr, 0, seed, em));
    static const char* kExpected =
        "0062a15e5e9621b6813a04c637a2e7a75269e5cc71795268f5398591ce946cf0"
        "b69344c47fca4af717407eda5bbc04e0a2927ac9d4fc20ea3f18c681d71e31c2"
        "d104a6950a06d3e3308ad7d3606ef810eb124e3943404ca746a12c51c7bf7768"
        "390f8d842ac9cb62349779a7537a78327d545aaeb33b2d42c7d1dc3680a4b236"
        "28627e9db8ad47bfe76dbe653d03d2c0a35999ed28a5023924150d72508668d2"
        "442f95db4b0a7de880458b19966f21918f9644106e8d2eb4aff23845703cd214"
        "920c1c9b0bc4358902b823c7675320d59ded234f308b9dfa5f8d844d1978330c"
        "669fa873071768cf46b419ad2867bb6312b759007caf966dff1f1e9950229960"
        "2725fbe9f84015dbf3deed592b4af13de19dcafdaf729d58add39b4d6816a697"
        "802b7390608b26e7e3394e8eb2ec91e1474d6d664728c40bd4b0350f0ed520c7"
        "5e20fedac6fb8bfe49466701cb209dbd0d4d3184904f31c6399b9cac1b320f5c"
        "176be449f0331e44c422cf803352422c53fcdffc15c3b33a20096fc5c91e80db";
    expect_eq("детерминированный EM", hex_of(em.data(), em.size()), kExpected);
    expect_true("ведущий байт EM = 0x00", em[0] == 0x00);

    std::array<uint8_t, Oaep::kMaxMessage> back{};
    std::size_t back_len = 99;
    expect_true("decode CT", Oaep::decode(em, nullptr, 0, back, back_len));
    expect_true("длина 7", back_len == sizeof(msg));
    expect_true("сообщение KMZI-11", std::memcmp(back.data(), msg, sizeof(msg)) == 0);
    std::size_t vt_len = 0;
    expect_true("decode VT совпал", Oaep::decode_variable_time(em, nullptr, 0, back, vt_len) &&
                                        vt_len == sizeof(msg));

    std::array<uint8_t, Oaep::kModulusBytes> bad = em;
    bad[0] ^= 0x01;
    expect_true("битый первый байт отвергнут CT", !Oaep::decode(bad, nullptr, 0, back, back_len));
    expect_true("битый первый байт отвергнут VT",
                !Oaep::decode_variable_time(bad, nullptr, 0, back, vt_len));
    expect_true("при ошибке длина 0", back_len == 0);

    bad = em;
    bad[40] ^= 0x5A;
    expect_true("битый блок DB отвергнут", !Oaep::decode(bad, nullptr, 0, back, back_len));

    expect_true("пустое сообщение", Oaep::encode_with_seed(nullptr, 0, nullptr, 0, seed, em));
    expect_true("decode пустого", Oaep::decode(em, nullptr, 0, back, back_len) && back_len == 0);

    std::array<uint8_t, Oaep::kMaxMessage> full{};
    full.fill(0xA5);
    expect_true("максимальное сообщение",
                Oaep::encode_with_seed(full.data(), full.size(), nullptr, 0, seed, em));
    expect_true("decode максимального", Oaep::decode(em, nullptr, 0, back, back_len) &&
                                             back_len == static_cast<std::size_t>(Oaep::kMaxMessage) &&
                                             std::memcmp(back.data(), full.data(), full.size()) == 0);

    expect_true("слишком длинное отвергнуто",
                !Oaep::encode_with_seed(full.data(), full.size() + 1, nullptr, 0, seed, em));

    const uint8_t label[] = {'l', 'a', 'b'};
    expect_true("метка", Oaep::encode_with_seed(msg, sizeof(msg), label, sizeof(label), seed, em));
    expect_true("верная метка", Oaep::decode(em, label, sizeof(label), back, back_len) && back_len == sizeof(msg));
    expect_true("чужая метка", !Oaep::decode(em, nullptr, 0, back, back_len));

    std::array<uint8_t, Oaep::kModulusBytes> em2{};
    expect_true("случайный seed 1", Oaep::encode(msg, sizeof(msg), nullptr, 0, em));
    expect_true("случайный seed 2", Oaep::encode(msg, sizeof(msg), nullptr, 0, em2));
    expect_true("два seed дают разные EM", em != em2);
    expect_true("оба вскрываются", Oaep::decode(em, nullptr, 0, back, back_len) && back_len == sizeof(msg) &&
                                       Oaep::decode(em2, nullptr, 0, back, back_len));
}

void flip_bit(Bn& n, int bit) {
    if (BN_is_bit_set(n.raw(), bit)) {
        BN_clear_bit(n.raw(), bit);
    } else {
        BN_set_bit(n.raw(), bit);
    }
}

void time_miller_rabin(const char* title, const Bn& prime, int rounds_outer) {
    std::printf("\n== Время Миллера–Рабина (%s, %d бит) ==\n", title, RsaMath::bit_length(prime));
    Bn composite = prime;
    flip_bit(composite, 16);
    Bn bases[RsaMath::kMrRounds];
    expect_true("свидетели", RsaMath::random_bases(bases, RsaMath::kMrRounds, prime));
    const bool prime_ct = RsaMath::miller_rabin_ct(prime, bases, RsaMath::kMrRounds);
    const bool prime_vt = RsaMath::miller_rabin_vt(prime, bases, RsaMath::kMrRounds);
    const bool comp_ct = RsaMath::miller_rabin_ct(composite, bases, RsaMath::kMrRounds);
    const bool comp_vt = RsaMath::miller_rabin_vt(composite, bases, RsaMath::kMrRounds);
    expect_true("CT признаёт простое", prime_ct);
    expect_true("VT признаёт простое", prime_vt);
    expect_true("CT отвергает составное", !comp_ct);
    expect_true("VT отвергает составное", !comp_vt);

    volatile unsigned sink = 0;
    auto bench = [&](auto&& fn, const Bn& n) {
        std::vector<Sample> samples;
        for (int i = 0; i < rounds_outer + 1; ++i) {
            const uint64_t t0 = ticks_now();
            const uint64_t n0 = nsec_now();
            const bool verdict = fn(n, bases, RsaMath::kMrRounds);
            const uint64_t n1 = nsec_now();
            const uint64_t t1 = ticks_now();
            sink ^= verdict ? 1u : 0u;
            if (i == 0) {
                continue;
            }
            samples.push_back(Sample{n1 - n0, t1 - t0});
        }
        return samples;
    };

    const auto ct_p = bench(RsaMath::miller_rabin_ct, prime);
    const auto ct_c = bench(RsaMath::miller_rabin_ct, composite);
    const auto vt_p = bench(RsaMath::miller_rabin_vt, prime);
    const auto vt_c = bench(RsaMath::miller_rabin_vt, composite);
    print_samples("CT простое", ct_p);
    print_samples("CT составное", ct_c);
    print_samples("VT простое", vt_p);
    print_samples("VT составное", vt_c);
    const double ct_ratio =
        static_cast<double>(median_of(ct_c).ns) / static_cast<double>(median_of(ct_p).ns);
    const double vt_ratio =
        static_cast<double>(median_of(vt_c).ns) / static_cast<double>(median_of(vt_p).ns);
    std::printf("  отношение составное/простое: CT %.3f, VT %.3f\n", ct_ratio, vt_ratio);
    std::printf("  (sink %u)\n", sink);
}

void time_oaep() {
    std::printf("\n== Время деинкапсуляции OAEP ==\n");
    const uint8_t msg[] = "constant-time oaep padding check";
    uint8_t seed[Oaep::kHashLen];
    for (int i = 0; i < Oaep::kHashLen; ++i) {
        seed[i] = static_cast<uint8_t>(0xA0 + i);
    }
    std::array<uint8_t, Oaep::kModulusBytes> em{};
    expect_true("стенд OAEP", Oaep::encode_with_seed(msg, sizeof(msg) - 1, nullptr, 0, seed, em));
    std::array<uint8_t, Oaep::kModulusBytes> bad = em;
    bad[0] = 0x01;

    std::array<uint8_t, Oaep::kMaxMessage> out{};
    volatile unsigned sink = 0;
    constexpr int kIters = 2000;
    auto bench = [&](auto&& fn, const std::array<uint8_t, Oaep::kModulusBytes>& block) {
        const uint64_t t0 = ticks_now();
        const uint64_t n0 = nsec_now();
        for (int i = 0; i < kIters; ++i) {
            std::size_t len = 0;
            const bool ok = fn(block, nullptr, 0, out, len);
            sink ^= ok ? 1u : 0u;
            sink += static_cast<unsigned>(len);
        }
        const uint64_t n1 = nsec_now();
        const uint64_t t1 = ticks_now();
        return Sample{(n1 - n0) / static_cast<uint64_t>(kIters), (t1 - t0) / static_cast<uint64_t>(kIters)};
    };
    const Sample ct_ok = bench(Oaep::decode, em);
    const Sample ct_bad = bench(Oaep::decode, bad);
    const Sample vt_ok = bench(Oaep::decode_variable_time, em);
    const Sample vt_bad = bench(Oaep::decode_variable_time, bad);
    auto line = [](const char* name, Sample s) {
        std::printf("  %-28s  %8.3f us   (%llu ticks)\n", name, static_cast<double>(s.ns) / 1e3,
                    static_cast<unsigned long long>(s.ticks));
    };
    line("CT валидный EM", ct_ok);
    line("CT битый первый байт", ct_bad);
    line("VT валидный EM", vt_ok);
    line("VT битый первый байт", vt_bad);
    std::printf("  CT битый/валидный = %.3f, VT битый/валидный = %.3f\n",
                static_cast<double>(ct_bad.ns) / static_cast<double>(ct_ok.ns),
                static_cast<double>(vt_bad.ns) / static_cast<double>(vt_ok.ns));
    std::printf("  (sink %u)\n", sink);
}

bool seal(std::array<uint8_t, Oaep::kModulusBytes>& ct, const RsaPrivateKey& key, const uint8_t* msg,
          std::size_t len) {
    std::array<uint8_t, Oaep::kModulusBytes> em{};
    if (!Oaep::encode(msg, len, nullptr, 0, em)) {
        return false;
    }
    Bn m;
    Bn c;
    if (!RsaMath::from_bytes(m, em.data(), Oaep::kModulusBytes)) {
        return false;
    }
    if (!RsaCore::encrypt(c, m, key.e, key.n)) {
        return false;
    }
    return RsaMath::to_bytes_pad(c, ct.data(), Oaep::kModulusBytes);
}

bool open_message(std::array<uint8_t, Oaep::kMaxMessage>& msg, std::size_t& len, const RsaPrivateKey& key,
                  const std::array<uint8_t, Oaep::kModulusBytes>& ct) {
    Bn c;
    Bn m;
    if (!RsaMath::from_bytes(c, ct.data(), Oaep::kModulusBytes)) {
        return false;
    }
    if (!RsaCore::decrypt_crt(m, c, key)) {
        return false;
    }
    std::array<uint8_t, Oaep::kModulusBytes> em{};
    if (!RsaMath::to_bytes_pad(m, em.data(), Oaep::kModulusBytes)) {
        return false;
    }
    return Oaep::decode(em, nullptr, 0, msg, len);
}

void expect_roundtrip(const char* name, const RsaPrivateKey& key, const uint8_t* msg, std::size_t len) {
    std::array<uint8_t, Oaep::kModulusBytes> ct{};
    std::array<uint8_t, Oaep::kMaxMessage> back{};
    std::size_t back_len = 0;
    const bool ok = seal(ct, key, msg, len) && open_message(back, back_len, key, ct) && back_len == len &&
                    (len == 0 || std::memcmp(back.data(), msg, len) == 0);
    expect_true(name, ok);
}

void test_full_key() {
    std::printf("\n== Ключ RSA-%d и сквозной OAEP ==\n", RsaMath::kModulusBits);
    RsaPrivateKey key;
    const uint64_t t0 = nsec_now();
    expect_true("генерация ключа", RsaMath::generate_keypair(key, RsaMath::kModulusBits));
    const uint64_t t1 = nsec_now();
    if (g_failed > 0 && RsaMath::bit_length(key.n) != RsaMath::kModulusBits) {
        return;
    }
    std::printf("  генерация заняла %.2f с\n", static_cast<double>(t1 - t0) / 1e9);
    std::printf("  биты: n=%d p=%d q=%d d=%d e=%lu\n", RsaMath::bit_length(key.n),
                RsaMath::bit_length(key.p), RsaMath::bit_length(key.q), RsaMath::bit_length(key.d),
                RsaMath::kPublicExponent);
    std::printf("  n = %s\n", RsaMath::hex(key.n).c_str());
    std::printf("  e = %s\n", RsaMath::hex(key.e).c_str());
    std::printf("  d = %s\n", RsaMath::hex(key.d).c_str());
    std::printf("  p = %s\n", RsaMath::hex(key.p).c_str());
    std::printf("  q = %s\n", RsaMath::hex(key.q).c_str());
    std::printf("  dp = %s\n", RsaMath::hex(key.dp).c_str());
    std::printf("  dq = %s\n", RsaMath::hex(key.dq).c_str());
    std::printf("  qinv = %s\n", RsaMath::hex(key.qinv).c_str());

    expect_roundtrip("пустое сообщение", key, nullptr, 0);
    const uint8_t text[] = "Variant 11: RSA-3072, SHA-256, CRT, OAEP";
    expect_roundtrip("короткое сообщение", key, text, sizeof(text) - 1);
    std::array<uint8_t, Oaep::kMaxMessage> full{};
    for (std::size_t i = 0; i < full.size(); ++i) {
        full[i] = static_cast<uint8_t>(i * 17u + 3u);
    }
    expect_roundtrip("максимальная длина 318 байт", key, full.data(), full.size());

    std::array<uint8_t, Oaep::kModulusBytes> ct{};
    expect_true("seal для порчи", seal(ct, key, text, sizeof(text) - 1));
    std::array<uint8_t, Oaep::kModulusBytes> damaged = ct;
    damaged[Oaep::kModulusBytes - 1] ^= 0x01;
    Bn cdamaged;
    RsaMath::from_bytes(cdamaged, damaged.data(), Oaep::kModulusBytes);
    expect_true("испорченный шифртекст < n", BN_cmp(cdamaged.raw(), key.n.raw()) < 0);
    std::array<uint8_t, Oaep::kMaxMessage> back{};
    std::size_t back_len = 1;
    expect_true("битый шифртекст отвергнут", !open_message(back, back_len, key, damaged));

    std::printf("\n== Время расшифрования: наивное, CRT, валидный и битый шифртекст ==\n");
    Bn mword;
    Bn cipher;
    RsaMath::from_word(mword, 42);
    expect_true("сырое шифрование 42", RsaCore::encrypt(cipher, mword, key.e, key.n));
    volatile unsigned sink = 0;
    auto bench_raw = [&](auto&& fn) {
        std::vector<Sample> samples;
        for (int i = 0; i < 4; ++i) {
            Bn out;
            const uint64_t t_a = ticks_now();
            const uint64_t n_a = nsec_now();
            const bool ok = fn(out);
            const uint64_t n_b = nsec_now();
            const uint64_t t_b = ticks_now();
            sink ^= ok ? 1u : 0u;
            if (i == 0) {
                continue;
            }
            samples.push_back(Sample{n_b - n_a, t_b - t_a});
        }
        return samples;
    };
    const auto naive = bench_raw([&](Bn& out) { return RsaCore::decrypt_naive(out, cipher, key.d, key.n); });
    const auto crt = bench_raw([&](Bn& out) { return RsaCore::decrypt_crt(out, cipher, key); });
    print_samples("наивное c^d mod n", naive);
    print_samples("CRT Гарнера", crt);
    std::printf("  ускорение CRT: %.2f раз\n",
                static_cast<double>(median_of(naive).ns) / static_cast<double>(median_of(crt).ns));

    Bn check;
    expect_true("CRT сырого блока = 42", RsaCore::decrypt_crt(check, cipher, key) && BN_is_word(check.raw(), 42));

    auto bench_open = [&](const std::array<uint8_t, Oaep::kModulusBytes>& block) {
        std::vector<Sample> samples;
        for (int i = 0; i < 4; ++i) {
            std::array<uint8_t, Oaep::kMaxMessage> buf{};
            std::size_t len = 0;
            const uint64_t t_a = ticks_now();
            const uint64_t n_a = nsec_now();
            const bool ok = open_message(buf, len, key, block);
            const uint64_t n_b = nsec_now();
            const uint64_t t_b = ticks_now();
            sink ^= ok ? 1u : 0u;
            if (i == 0) {
                continue;
            }
            samples.push_back(Sample{n_b - n_a, t_b - t_a});
        }
        return samples;
    };
    const auto good_open = bench_open(ct);
    const auto bad_open = bench_open(damaged);
    print_samples("OAEP+CRT валидный", good_open);
    print_samples("OAEP+CRT битый", bad_open);
    std::printf("  битый/валидный = %.3f\n",
                static_cast<double>(median_of(bad_open).ns) / static_cast<double>(median_of(good_open).ns));
    std::printf("  (sink %u)\n", sink);

    time_miller_rabin("простое из ключа", key.p, 4);
}

}

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    std::printf("Лабораторная работа 2, вариант 11\n");
    std::printf("RSA-%d, SHA-256, CRT, OAEP, constant-time Миллер–Рабин (%d раундов, %d квадратов)\n",
                RsaMath::kModulusBits, RsaMath::kMrRounds, RsaMath::kFixedSquarings);
    test_sha256();
    test_math();
    test_small_rsa();
    test_miller_rabin();
    test_oaep();
    if (g_failed != 0) {
        std::printf("\nПровалено проверок до измерения времени: %d. Генерация ключа пропущена.\n", g_failed);
        return 1;
    }
    time_oaep();
    {
        std::printf("\n== Подготовка 512-битного простого для замера MR ==\n");
        Bn prime;
        expect_true("простое 512 бит", RsaMath::generate_prime(prime, 512, RsaMath::kPublicExponent));
        if (g_failed == 0) {
            time_miller_rabin("отдельный замер", prime, 5);
        }
    }
    if (g_failed != 0) {
        std::printf("\nПровалено проверок: %d\n", g_failed);
        return 1;
    }
    test_full_key();
    std::printf("\n%s, провалов: %d\n", g_failed == 0 ? "Все проверки пройдены" : "Есть ошибки", g_failed);
    return g_failed == 0 ? 0 : 1;
}
