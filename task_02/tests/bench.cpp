// Замер тактов процессора (rdtsc): валидный vs повреждённый шифротекст,
// CRT vs обычное расшифрование.  Запуск: ./rsa_bench [повторов]  (по умолчанию 200)
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "bigint_math.hpp"
#include "rsa_oaep.hpp"

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
static inline uint64_t ticks() { _mm_lfence(); uint64_t t = __rdtsc(); _mm_lfence(); return t; }
static const char* UNIT = "тактов TSC";
#else
static inline uint64_t ticks() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch()).count();
}
static const char* UNIT = "нс";
#endif

struct Stat { double med, mean, sd, mn; };
static Stat stat(std::vector<uint64_t> v) {
    std::sort(v.begin(), v.end());
    double sum = 0;
    for (auto x : v) sum += x;
    double mean = sum / v.size(), var = 0;
    for (auto x : v) var += (x - mean) * (x - mean);
    return {double(v[v.size() / 2]), mean, std::sqrt(var / v.size()), double(v[0])};
}
static void line(const char* name, const Stat& s) {
    std::printf("  %-34s медиана=%12.0f  среднее=%12.0f  σ=%10.0f  мин=%12.0f\n", name, s.med, s.mean, s.sd, s.mn);
}

int main(int argc, char** argv) {
    int N = argc > 1 ? std::atoi(argv[1]) : 200;
    std::printf("Генерация ключа RSA-3072 ...\n");
    auto t0 = std::chrono::steady_clock::now();
    rsa::PublicKey pub; rsa::PrivateKey priv;
    rsa::generate_keypair(pub, priv);
    double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::printf("  готово за %.2f с\n", sec);

    using namespace oaep;
    uint8_t msg[100]; for (int i = 0; i < 100; ++i) msg[i] = uint8_t(i);
    uint8_t ct_ok[K], ct_bad[K], out[MAX_MSG]; size_t olen;
    rsa::oaep_encrypt(pub, msg, 100, nullptr, 0, ct_ok);

    // --- Тип 1: ПОЛНЫЙ конвейер, шифротекст испорчен (случайный EM после RSA)
    std::memcpy(ct_bad, ct_ok, K); ct_bad[K - 5] ^= 0x5A;

    // --- Типы 2-4: корректный RSA, но структурно неверный EM (атака Мангера):
    //     портим первый байт / lHash / разделитель ДО шифрования
    uint8_t seed[HLEN]; for (size_t i = 0; i < HLEN; ++i) seed[i] = uint8_t(0x40 + i);
    uint8_t em[K];
    uint8_t ct_b0[K], ct_lh[K], ct_sep[K];
    encode_with_seed(em, msg, 100, nullptr, 0, seed);
    em[0] = 0x01; rsa::rsa_encrypt_em(pub, em, ct_b0);           // первый байт != 0
    // портим lHash: маскированный DB, меняем 1 байт в области lHash
    encode_with_seed(em, msg, 100, nullptr, 0, seed);
    em[1 + HLEN + 3] ^= 0x01; rsa::rsa_encrypt_em(pub, em, ct_lh);
    encode_with_seed(em, msg, 100, nullptr, 0, seed);
    em[K - 1] ^= 0x80; em[1 + HLEN + HLEN + 2] ^= 0x04; rsa::rsa_encrypt_em(pub, em, ct_sep);

    struct Case { const char* name; uint8_t* ct; std::vector<uint64_t> t; } cases[] = {
        {"валидный шифротекст", ct_ok, {}},
        {"испорчен шифротекст (случайный EM)", ct_bad, {}},
        {"EM: первый байт != 0x00", ct_b0, {}},
        {"EM: испорчен lHash", ct_lh, {}},
        {"EM: испорчен PS/разделитель", ct_sep, {}},
    };
    for (auto& c : cases) c.t.reserve(N);

    for (int w = 0; w < 10; ++w)  // прогрев
        for (auto& c : cases) rsa::oaep_decrypt(priv, c.ct, nullptr, 0, out, &olen);

    // чередуем варианты, чтобы дрейф частоты/кэша влиял на всех поровну
    for (int i = 0; i < N; ++i)
        for (auto& c : cases) {
            uint64_t a = ticks();
            rsa::oaep_decrypt(priv, c.ct, nullptr, 0, out, &olen);
            uint64_t b = ticks();
            c.t.push_back(b - a);
        }

    std::printf("\n=== OAEP-расшифрование целиком (RSA-CRT + OAEP-decode), %d повторов, %s ===\n", N, UNIT);
    Stat base = stat(cases[0].t);
    for (auto& c : cases) {
        Stat s = stat(c.t);
        line(c.name, s);
    }
    std::printf("\n  Отличие медианы от валидного шифротекста:\n");
    for (size_t i = 1; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        Stat s = stat(cases[i].t);
        std::printf("    %-36s %+.3f %%\n", cases[i].name, 100.0 * (s.med - base.med) / base.med);
    }

    // --- Только OAEP-decode (без RSA): здесь именно нет раннего выхода
    uint8_t em_ok[K], em_bad[K];
    encode_with_seed(em_ok, msg, 100, nullptr, 0, seed);
    std::memcpy(em_bad, em_ok, K); em_bad[0] = 0x01;
    std::vector<uint64_t> ta, tb;
    const int M = N * 50;
    for (int w = 0; w < 100; ++w) { decode(out, &olen, em_ok, nullptr, 0); decode(out, &olen, em_bad, nullptr, 0); }
    for (int i = 0; i < M; ++i) {
        uint64_t a = ticks(); decode(out, &olen, em_ok, nullptr, 0); uint64_t b = ticks();
        decode(out, &olen, em_bad, nullptr, 0); uint64_t c = ticks();
        ta.push_back(b - a); tb.push_back(c - b);
    }
    std::printf("\n=== Только oaep::decode (валидный EM vs EM с ошибкой), %d повторов ===\n", M);
    Stat sa = stat(ta), sb = stat(tb);
    line("валидный EM", sa);
    line("EM с ошибкой (первый байт)", sb);
    std::printf("  Отличие медианы: %+.3f %%\n", 100.0 * (sb.med - sa.med) / sa.med);

    // --- CRT vs обычное расшифрование
    std::vector<uint64_t> tc, tp;
    mpz_class c = rsa::random_bits(3000), m1, m2;
    int R = std::max(10, N / 10);
    for (int i = 0; i < R; ++i) {
        uint64_t a = ticks(); rsa::rsa_decrypt_crt(m1, c, priv); uint64_t b = ticks();
        rsa::rsa_decrypt_plain(m2, c, priv); uint64_t d = ticks();
        tc.push_back(b - a); tp.push_back(d - b);
    }
    Stat sc = stat(tc), sp = stat(tp);
    std::printf("\n=== Сырое RSA-расшифрование: CRT vs обычное (d, 3072 бит), %d повторов ===\n", R);
    line("CRT (Гарнер)", sc);
    line("без CRT", sp);
    std::printf("  Ускорение: %.2f x   (результаты равны: %s)\n", sp.med / sc.med, m1 == m2 ? "да" : "НЕТ");

    // --- Joye-Tun: время не зависит от значения экспоненты
    std::vector<uint64_t> t0v, t1v;
    mpz_class e0 = 1, e1 = (mpz_class(1) << 1535) - 1, rr;  // "почти все нули" vs "почти все единицы"
    mpz_class base_x = rsa::random_bits(1500);
    for (int i = 0; i < R * 2; ++i) {
        uint64_t a = ticks(); rsa::powm_joye_tun(rr, base_x, e0, priv.p, 1536); uint64_t b = ticks();
        rsa::powm_joye_tun(rr, base_x, e1, priv.p, 1536); uint64_t d = ticks();
        t0v.push_back(b - a); t1v.push_back(d - b);
    }
    Stat s0 = stat(t0v), s1 = stat(t1v);
    std::printf("\n=== Joye-Tun: экспонента из ОДНОЙ единицы vs из 1535 единиц (1536 бит) ===\n");
    line("e = 1 (почти все биты 0)", s0);
    line("e = 2^1535 - 1 (почти все биты 1)", s1);
    std::printf("  Отличие медианы: %+.3f %%\n", 100.0 * (s1.med - s0.med) / s0.med);
    return 0;
}
