// Тесты и замеры для варианта 3 (N=3072, SHA-512, constant-time Гарнер).
#include "numtheory.hpp"
#include "rsa_core.hpp"
#include "oaep.hpp"
#include "sha512.hpp"
#include "random.hpp"
#include "ct.hpp"
#include <x86intrin.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace cfg;
static int g_fail = 0;
#define CHECK(cond, name) do { bool ok_ = (cond); std::printf("  [%s] %s\n", ok_ ? "OK" : "FAIL", name); if (!ok_) ++g_fail; } while (0)

static std::string hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef"; std::string s;
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
static std::string sha_hex(const std::string& m) {
    uint8_t h[64]; Sha512::hash(reinterpret_cast<const uint8_t*>(m.data()), m.size(), h); return hex(h, 64);
}
static unsigned long to_ul(const BigInt& x) { return mpz_fdiv_ui(x.get(), ~0UL); }
static inline uint64_t tsc() { _mm_lfence(); uint64_t t = __rdtsc(); _mm_lfence(); return t; }
static double median(std::vector<uint64_t>& v) { std::sort(v.begin(), v.end()); return double(v[v.size() / 2]); }

// ---------- эталонная (УЯЗВИМАЯ) деинкапсуляция с ранними выходами: только для демонстрации утечки ----------
static bool decode_naive(const uint8_t em[K], const uint8_t* label, size_t llen, uint8_t* out, size_t* outlen) {
    if (em[0] != 0) return false;                                   // early exit №1 (атака Мангера)
    uint8_t lhash[HLEN], seedMask[HLEN], seed[HLEN], mask[DB_LEN], db[DB_LEN];
    Sha512::hash(label, llen, lhash);
    oaep::mgf1(em + 1 + HLEN, DB_LEN, seedMask, HLEN);
    for (size_t i = 0; i < HLEN; ++i) seed[i] = em[1 + i] ^ seedMask[i];
    oaep::mgf1(seed, HLEN, mask, DB_LEN);
    for (size_t i = 0; i < DB_LEN; ++i) db[i] = em[1 + HLEN + i] ^ mask[i];
    if (std::memcmp(db, lhash, HLEN) != 0) return false;            // early exit №2
    size_t i = HLEN;
    while (i < DB_LEN && db[i] == 0) ++i;
    if (i == DB_LEN || db[i] != 1) return false;                    // early exit №3
    *outlen = DB_LEN - i - 1; std::memcpy(out, db + i + 1, *outlen); return true;
}

// строим EM из произвольного DB (для тестов дефектов)
static void em_from_db(const uint8_t db[DB_LEN], const uint8_t seed[HLEN], uint8_t em[K]) {
    uint8_t mask[DB_LEN], mdb[DB_LEN], smask[HLEN];
    oaep::mgf1(seed, HLEN, mask, DB_LEN);
    for (size_t i = 0; i < DB_LEN; ++i) mdb[i] = db[i] ^ mask[i];
    oaep::mgf1(mdb, DB_LEN, smask, HLEN);
    em[0] = 0; for (size_t i = 0; i < HLEN; ++i) em[1 + i] = seed[i] ^ smask[i];
    std::memcpy(em + 1 + HLEN, mdb, DB_LEN);
}

static void t_sha() {
    std::puts("\n[1] SHA-512: известные ответы (FIPS 180-4)");
    CHECK(sha_hex("abc") == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", "SHA-512(\"abc\")");
    CHECK(sha_hex("") == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "SHA-512(\"\")");
    CHECK(sha_hex("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") ==
          "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909", "SHA-512 (112 байт, 2 блока)");
}

static void t_numtheory() {
    std::puts("\n[2] Теория чисел");
    BigInt g, x, y, a(240), b(46);
    nt::ext_gcd(g, x, y, a, b);
    CHECK(to_ul(g) == 2 && mpz_cmp_ui(x.get(), 0) < 0, "ext_gcd(240,46): gcd=2, коэффициент x<0 (x=-9, y=47)");
    BigInt r, e(17), m(3120);
    CHECK(nt::mod_inverse(r, e, m) && to_ul(r) == 2753, "17^{-1} mod 3120 = 2753");
    BigInt bad(6), m2(9);
    CHECK(!nt::mod_inverse(r, bad, m2), "6^{-1} mod 9 не существует");
    BigInt c561(561), p104729(104729), mers; mpz_set_ui(mers.get(), 1); 
    for (int i = 0; i < 127; ++i) mpz_add(mers.get(), mers.get(), mers.get());   // 2^127
    mpz_sub_ui(mers.get(), mers.get(), 1);
    CHECK(!nt::miller_rabin(c561, 20), "Миллер-Рабин: число Кармайкла 561 - составное");
    CHECK(nt::miller_rabin(p104729, 20) && nt::miller_rabin(mers, 20), "Миллер-Рабин: 104729 и 2^127-1 - простые");
    BigInt base(4), ex(13), mod(497), res;
    nt::mod_pow(res, base, ex, mod, false);
    CHECK(to_ul(res) == 445, "mod_pow: 4^13 mod 497 = 445");
}

static void small_crt(unsigned long P, unsigned long Q, const char* title) {
    BigInt p(P), q(Q), n, d(2753), pm1(P - 1), qm1(Q - 1), dp, dq, qinv, one(1);
    mpz_mul(n.get(), p.get(), q.get());
    mpz_mod(dp.get(), d.get(), pm1.get()); mpz_mod(dq.get(), d.get(), qm1.get());
    nt::mod_inverse(qinv, q, p);
    std::printf("  %s: p=%lu q=%lu N=%lu dp=%lu dq=%lu qinv=%lu\n", title, P, Q, to_ul(n), to_ul(dp), to_ul(dq), to_ul(qinv));
    BigInt e(17); unsigned long N = to_ul(n); int bad = 0, lt = 0, ge = 0;
    for (unsigned long mv = 0; mv < N; ++mv) {
        BigInt m(mv), c, cp, cq, m1, m2, r1, r2;
        nt::mod_pow(c, m, e, n, false);
        mpz_mod(cp.get(), c.get(), p.get()); mpz_mod(cq.get(), c.get(), q.get());
        nt::mod_pow(m1, cp, dp, p, false); nt::mod_pow(m2, cq, dq, q, false);
        if (mpz_cmp(m1.get(), m2.get()) < 0) ++lt; else ++ge;
        rsa::garner_combine_ct(r1, m1, m2, p, q, qinv);
        rsa::garner_combine_naive(r2, m1, m2, p, q, qinv);
        if (mpz_cmp(r1.get(), m.get()) || mpz_cmp(r2.get(), m.get())) ++bad;
    }
    std::printf("  перебор всех m in [0,N): случаев m1<m2: %d, m1>=m2: %d\n", lt, ge);
    CHECK(bad == 0, "CT-Гарнер и эталон дают m для всех m (обе ветви m1<m2 / m1>=m2)");
}

static void t_garner_small() {
    std::puts("\n[3] Алгоритм Гарнера на малых числах (e=17, d=2753)");
    BigInt p(61), q(53), n(3233), c(2790), dp(53), dq(49), qinv(38), m1, m2, m;
    nt::mod_pow(m1, c, dp, p, false); nt::mod_pow(m2, c, dq, q, false);
    rsa::garner_combine_ct(m, m1, m2, p, q, qinv);
    std::printf("  c=2790: m1=%lu m2=%lu (m1-m2)=%ld -> m=%lu\n", to_ul(m1), to_ul(m2), (long)to_ul(m1) - (long)to_ul(m2), to_ul(m));
    CHECK(to_ul(m) == 65, "дешифровка c=2790 даёт m=65");
    small_crt(61, 53, "p>q");
    small_crt(53, 61, "p<q (m2 может превышать p - нужна нормализация)");
}

static PublicKey g_pub; static PrivateKey g_prv;

static void t_keygen() {
    std::puts("\n[4] Генерация ключей RSA-3072");
    nt::generate_keypair(g_pub, g_prv, RSA_BITS);
    CHECK(g_prv.n.bits() == RSA_BITS, "N имеет ровно 3072 бита");
    CHECK(g_prv.p.bits() == PRIME_BITS && g_prv.q.bits() == PRIME_BITS, "p и q имеют по 1536 бит");
    CHECK(mpz_cmp(g_prv.p.get(), g_prv.q.get()) != 0, "p != q");
    CHECK(nt::miller_rabin(g_prv.p, 10) && nt::miller_rabin(g_prv.q, 10), "p, q проходят Миллера-Рабина");
    BigInt t, pm1, qm1, tmp; 
    mpz_sub_ui(pm1.get(), g_prv.p.get(), 1); mpz_sub_ui(qm1.get(), g_prv.q.get(), 1);
    mpz_mul(tmp.get(), g_prv.e.get(), g_prv.dp.get()); mpz_mod(t.get(), tmp.get(), pm1.get());
    bool a = to_ul(t) == 1;
    mpz_mul(tmp.get(), g_prv.e.get(), g_prv.dq.get()); mpz_mod(t.get(), tmp.get(), qm1.get());
    bool b = to_ul(t) == 1;
    mpz_mul(tmp.get(), g_prv.q.get(), g_prv.qinv.get()); mpz_mod(t.get(), tmp.get(), g_prv.p.get());
    CHECK(a && b, "e*dp = 1 (mod p-1), e*dq = 1 (mod q-1)");
    CHECK(to_ul(t) == 1, "q * q_inv = 1 (mod p)");
}

static void t_crt_random() {
    std::puts("\n[5] CRT против прямого c^d mod N; CT-Гарнер против эталона на 1536-битных m1, m2");
    int bad = 0;
    for (int i = 0; i < 20; ++i) {
        BigInt m, c, r1, r2;
        nt::random_bits(m, RSA_BITS - 8, false);
        rsa::encrypt_raw(c, m, g_pub);
        rsa::decrypt_crt(r1, c, g_prv); rsa::decrypt_plain(r2, c, g_prv);
        if (mpz_cmp(r1.get(), m.get()) || mpz_cmp(r2.get(), m.get())) ++bad;
    }
    CHECK(bad == 0, "20 случайных m: CRT == прямое == исходное");
    int mism = 0, lt = 0;
    for (int i = 0; i < 20000; ++i) {
        BigInt m1, m2, r1, r2, d1, d2;
        BigInt a, b; nt::random_bits(a, PRIME_BITS, false); nt::random_bits(b, PRIME_BITS, false);
        mpz_mod(m1.get(), a.get(), g_prv.p.get()); mpz_mod(m2.get(), b.get(), g_prv.q.get());
        if (mpz_cmp(m1.get(), m2.get()) < 0) ++lt;
        rsa::garner_diff_ct(d1, m1, m2, g_prv.p); rsa::garner_diff_naive(d2, m1, m2, g_prv.p);
        if (mpz_cmp(d1.get(), d2.get())) ++mism;
    }
    std::printf("  случаев m1<m2: %d из 20000\n", lt);
    CHECK(mism == 0, "garner_diff_ct == garner_diff_naive (20000 пар)");
}

static void t_oaep() {
    std::puts("\n[6] OAEP: границы длин, метка, дефекты");
    const size_t lens[] = {0, 1, 100, MAX_MSG};
    for (size_t L : lens) {
        uint8_t msg[MAX_MSG], ct_[K], out[MAX_MSG]; size_t ol = 99;
        random_bytes(msg, MAX_MSG);
        bool e = oaep::encrypt(g_pub, msg, L, nullptr, 0, ct_);
        bool d = oaep::decrypt(g_prv, ct_, nullptr, 0, out, &ol);
        char name[96]; std::snprintf(name, sizeof name, "шифр/дешифр: длина сообщения = %zu%s", L, L == MAX_MSG ? " (максимум k-2hLen-2)" : L == 0 ? " (пустое)" : "");
        CHECK(e && d && ol == L && std::memcmp(out, msg, L) == 0, name);
    }
    { uint8_t msg[MAX_MSG + 1] = {0}, ct_[K]; CHECK(!oaep::encrypt(g_pub, msg, MAX_MSG + 1, nullptr, 0, ct_), "длина 255 отвергается"); }
    { uint8_t ct_[K], out[MAX_MSG]; size_t ol; const uint8_t m[] = "secret", l1[] = "A", l2[] = "B";
      oaep::encrypt(g_pub, m, 6, l1, 1, ct_);
      CHECK(oaep::decrypt(g_prv, ct_, l1, 1, out, &ol) && ol == 6, "метка совпадает - успех");
      CHECK(!oaep::decrypt(g_prv, ct_, l2, 1, out, &ol) && ol == 0, "метка не совпадает - отказ"); }
    { uint8_t m[] = "same", c1[K], c2[K]; oaep::encrypt(g_pub, m, 4, nullptr, 0, c1); oaep::encrypt(g_pub, m, 4, nullptr, 0, c2);
      CHECK(std::memcmp(c1, c2, K) != 0, "шифрование вероятностное (два шифротекста различны)"); }
    { uint8_t ct_[K], out[MAX_MSG]; size_t ol; const uint8_t m[] = "hello";
      oaep::encrypt(g_pub, m, 5, nullptr, 0, ct_); ct_[100] ^= 0x01;
      CHECK(!oaep::decrypt(g_prv, ct_, nullptr, 0, out, &ol), "повреждённый шифротекст отвергается"); }
    { uint8_t ct_[K], out[MAX_MSG]; size_t ol; std::memset(ct_, 0xFF, K);
      CHECK(!oaep::decrypt(g_prv, ct_, nullptr, 0, out, &ol), "c >= N отвергается"); }

    // дефекты структуры DB
    uint8_t lh[HLEN], seed[HLEN], db[DB_LEN], em[K], out[MAX_MSG]; size_t ol;
    Sha512::hash(nullptr, 0, lh); random_bytes(seed, HLEN);
    auto fresh = [&]() { std::memset(db, 0, DB_LEN); std::memcpy(db, lh, HLEN); db[DB_LEN - 4] = 1; db[DB_LEN - 3] = 'a'; db[DB_LEN - 2] = 'b'; db[DB_LEN - 1] = 'c'; };
    fresh(); em_from_db(db, seed, em);
    CHECK(oaep::decode(em, nullptr, 0, out, &ol) == 1 && ol == 3 && std::memcmp(out, "abc", 3) == 0, "эталонный EM корректно распаковывается");
    fresh(); em_from_db(db, seed, em); em[0] = 0x01;
    CHECK(oaep::decode(em, nullptr, 0, out, &ol) == 0 && ol == 0, "дефект: первый байт != 0x00");
    fresh(); db[3] ^= 0x80; em_from_db(db, seed, em);
    CHECK(oaep::decode(em, nullptr, 0, out, &ol) == 0, "дефект: lHash не совпадает");
    fresh(); db[HLEN + 10] = 0x05; em_from_db(db, seed, em);
    CHECK(oaep::decode(em, nullptr, 0, out, &ol) == 0, "дефект: ненулевой байт в PS");
    fresh(); db[DB_LEN - 4] = 0; em_from_db(db, seed, em);
    CHECK(oaep::decode(em, nullptr, 0, out, &ol) == 0, "дефект: нет разделителя 0x01");
    bool allzero = true; for (size_t i = 0; i < MAX_MSG; ++i) allzero &= (out[i] == 0);
    CHECK(allzero, "при ошибке выходной буфер обнулён (нет утечки частичных данных)");
}

// ---------------- замеры ----------------
static void report(const char* name, std::vector<uint64_t>& a, std::vector<uint64_t>& b, const char* la, const char* lb, double thr) {
    double ma = median(a), mb = median(b), rel = 100.0 * (mb - ma) / ma;
    std::printf("  %-34s %-10s медиана %10.0f | %-10s медиана %10.0f | Δ = %+6.2f %% %s\n", name, la, ma, lb, mb, rel,
                (rel < thr && rel > -thr) ? "(различий нет)" : "(ЗАМЕТНАЯ РАЗНИЦА)");
}

static void t_timing() {
    std::puts("\n[7] Измерение тактов (rdtsc, чередование замеров, медиана)");
    // 7a. деинкапсуляция OAEP: валидный vs разные дефекты
    uint8_t lh[HLEN], seed[HLEN], db[DB_LEN], em_ok[K], em_bad0[K], em_badh[K], em_nosep[K], out[MAX_MSG]; size_t ol;
    Sha512::hash(nullptr, 0, lh); random_bytes(seed, HLEN);
    std::memset(db, 0, DB_LEN); std::memcpy(db, lh, HLEN); db[DB_LEN - 11] = 1; std::memset(db + DB_LEN - 10, 'x', 10);
    em_from_db(db, seed, em_ok);
    std::memcpy(em_bad0, em_ok, K); em_bad0[0] = 1;
    uint8_t db2[DB_LEN]; std::memcpy(db2, db, DB_LEN); db2[0] ^= 1; em_from_db(db2, seed, em_badh);
    std::memcpy(db2, db, DB_LEN); db2[DB_LEN - 11] = 0; em_from_db(db2, seed, em_nosep);

    const int N = 6000;
    std::vector<uint64_t> tv, tb0, tbh, tbs, nv, nb0;
    for (int i = 0; i < N; ++i) {
        uint64_t t0;
        t0 = tsc(); oaep::decode(em_ok,    nullptr, 0, out, &ol); tv.push_back(tsc() - t0);
        t0 = tsc(); oaep::decode(em_bad0,  nullptr, 0, out, &ol); tb0.push_back(tsc() - t0);
        t0 = tsc(); oaep::decode(em_badh,  nullptr, 0, out, &ol); tbh.push_back(tsc() - t0);
        t0 = tsc(); oaep::decode(em_nosep, nullptr, 0, out, &ol); tbs.push_back(tsc() - t0);
        t0 = tsc(); decode_naive(em_ok,   nullptr, 0, out, &ol); nv.push_back(tsc() - t0);
        t0 = tsc(); decode_naive(em_bad0, nullptr, 0, out, &ol); nb0.push_back(tsc() - t0);
    }
    std::puts(" OAEP decode (CT-реализация):");
    report("валидный vs em[0]!=0",     tv, tb0, "valid", "bad", 3.0);
    report("валидный vs неверный lHash", tv, tbh, "valid", "bad", 3.0);
    report("валидный vs нет разделителя", tv, tbs, "valid", "bad", 3.0);
    std::puts(" Для сравнения - наивная версия с ранними return:");
    report("валидный vs em[0]!=0 (naive)", nv, nb0, "valid", "bad", 3.0);

    // 7b. полный цикл расшифрования
    uint8_t m[] = "constant-time test", ct_ok[K], ct_bad[K];
    oaep::encrypt(g_pub, m, 18, nullptr, 0, ct_ok);
    std::memcpy(ct_bad, ct_ok, K); ct_bad[200] ^= 0x10;
    const int M = 250; std::vector<uint64_t> dv, db_;
    for (int i = 0; i < M; ++i) {
        uint64_t t0 = tsc(); oaep::decrypt(g_prv, ct_ok,  nullptr, 0, out, &ol); dv.push_back(tsc() - t0);
        t0 = tsc();          oaep::decrypt(g_prv, ct_bad, nullptr, 0, out, &ol); db_.push_back(tsc() - t0);
    }
    std::puts(" Полное RSA-OAEP расшифрование (CRT + CT-Гарнер + CT-OAEP):");
    report("валидный vs повреждённый шифротекст", dv, db_, "valid", "corrupt", 3.0);

    // 7c. шаг Гарнера: m1<m2 против m1>m2, реальные 1536-битные p, q
    BigInt m1a, m2a, m1b, m2b, a, b, d;
    nt::random_bits(a, PRIME_BITS, false); nt::random_bits(b, PRIME_BITS, false);
    mpz_mod(a.get(), a.get(), g_prv.p.get()); mpz_mod(b.get(), b.get(), g_prv.q.get());
    if (mpz_cmp(a.get(), b.get()) > 0) mpz_swap(a.get(), b.get());          // a < b
    mpz_set(m1a.get(), a.get()); mpz_set(m2a.get(), b.get());               // m1 < m2
    mpz_set(m1b.get(), b.get()); mpz_set(m2b.get(), a.get());               // m1 > m2 (обе < p)
    mpz_mod(m1b.get(), m1b.get(), g_prv.p.get());
    const int G = 3000, R = 200;                                           // R вызовов на один замер - выше разрешение
    std::vector<uint64_t> c_lt, c_ge, n_lt, n_ge;
    for (int i = 0; i < G; ++i) {
        uint64_t t0;
        t0 = tsc(); for (int r = 0; r < R; ++r) rsa::garner_diff_ct(d, m1a, m2a, g_prv.p);    c_lt.push_back(tsc() - t0);
        t0 = tsc(); for (int r = 0; r < R; ++r) rsa::garner_diff_ct(d, m1b, m2b, g_prv.p);    c_ge.push_back(tsc() - t0);
        t0 = tsc(); for (int r = 0; r < R; ++r) rsa::garner_diff_naive(d, m1a, m2a, g_prv.p); n_lt.push_back(tsc() - t0);
        t0 = tsc(); for (int r = 0; r < R; ++r) rsa::garner_diff_naive(d, m1b, m2b, g_prv.p); n_ge.push_back(tsc() - t0);
    }
    std::puts(" Шаг Гарнера (m1 - m2) mod p:");
    report("CT-версия: m1<m2 vs m1>=m2 (x200)", c_lt, c_ge, "m1<m2", "m1>=m2", 3.0);
    report("naive (if): m1<m2 vs m1>=m2 (x200)", n_lt, n_ge, "m1<m2", "m1>=m2", 3.0);
}

int main() {
    std::puts("=== Лабораторная №2, вариант 3: RSA-3072, OAEP-SHA-512, constant-time Гарнер ===");
    t_sha(); t_numtheory(); t_garner_small(); t_keygen(); t_crt_random(); t_oaep(); t_timing();
    std::printf("\nИтог: %s (провалено проверок: %d)\n", g_fail ? "ЕСТЬ ОШИБКИ" : "ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ", g_fail);
    return g_fail ? 1 : 0;
}
