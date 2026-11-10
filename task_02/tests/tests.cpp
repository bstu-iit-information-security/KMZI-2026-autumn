// Тесты корректности (вариант 8). Запуск: ./rsa_tests
#include <cstdio>
#include <cstring>
#include <string>

#include "bigint_math.hpp"
#include "rsa_oaep.hpp"
#include "sha256.hpp"

static int g_fail = 0, g_total = 0;
#define CHECK(cond, name)                                         \
    do {                                                          \
        ++g_total;                                                \
        if (cond) std::printf("  [ OK ] %s\n", name);             \
        else { ++g_fail; std::printf("  [FAIL] %s\n", name); }   \
    } while (0)

static std::string hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}

static void test_sha256() {
    std::printf("\n== SHA-256 (известные векторы FIPS 180-4) ==\n");
    uint8_t h[32];
    sha::sha256(reinterpret_cast<const uint8_t*>(""), 0, h);
    CHECK(hex(h, 32) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256(\"\")");
    sha::sha256(reinterpret_cast<const uint8_t*>("abc"), 3, h);
    CHECK(hex(h, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA256(\"abc\")");
    const char* m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha::sha256(reinterpret_cast<const uint8_t*>(m), std::strlen(m), h);
    CHECK(hex(h, 32) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "SHA256(448-bit)");
}

static void test_numtheory() {
    std::printf("\n== Модуль 1: теория чисел ==\n");
    mpz_class g, x, y;
    rsa::ext_gcd(g, x, y, 240, 46);
    CHECK(g == 2 && 240 * x + 46 * y == 2, "ext_gcd(240,46) = 2, 240x+46y=2");
    mpz_class inv;
    CHECK(rsa::mod_inverse(inv, 17, 3120) && inv == 2753, "17^-1 mod 3120 = 2753");
    CHECK(!rsa::mod_inverse(inv, 6, 9), "6 не обратим mod 9");

    bool ok = true;
    for (int i = 0; i < 200 && ok; ++i) {
        unsigned bits = 64 + (i * 37) % 1500;
        mpz_class mod = rsa::random_bits(bits) | 1;
        if (mod < 3) mod = 3;
        mpz_class b = rsa::random_bits(bits), e = rsa::random_bits(bits / 2 + 1), r, ref;
        rsa::powm_joye_tun(r, b, e, mod, bits / 2 + 1);
        mpz_powm(ref.get_mpz_t(), b.get_mpz_t(), e.get_mpz_t(), mod.get_mpz_t());
        ok = (r == ref);
    }
    CHECK(ok, "Joye-Tun == mpz_powm на 200 случайных тестах");
    mpz_class r;
    rsa::powm_joye_tun(r, 7, 0, 13, 8);
    CHECK(r == 1, "7^0 mod 13 = 1");
    rsa::powm_joye_tun(r, 7, 1, 13, 8);
    CHECK(r == 7, "7^1 mod 13 = 7");
    rsa::powm_joye_tun(r, 4, 13, 497, 8);
    CHECK(r == 445, "4^13 mod 497 = 445 (классический пример)");
    CHECK(rsa::miller_rabin(65537, 10) && !rsa::miller_rabin(561, 10) && !rsa::miller_rabin(65537u * 3u, 10),
          "Миллер-Рабин: 65537 простое, 561 (Кармайкл) и 196611 составные");
}

static void test_crt_small() {
    std::printf("\n== Математика CRT на малых числах (p=61, q=53, e=17) ==\n");
    mpz_class p = 61, q = 53, n = p * q, e = 17, lambda = 780, d, c, m;
    rsa::mod_inverse(d, e, lambda);
    mpz_class dp = d % (p - 1), dq = d % (q - 1), qinv;
    rsa::mod_inverse(qinv, q, p);
    std::printf("  N=%s  d=%s  dp=%s  dq=%s  qinv=%s\n", n.get_str().c_str(), d.get_str().c_str(),
                dp.get_str().c_str(), dq.get_str().c_str(), qinv.get_str().c_str());
    mpz_class msg = 65;
    rsa::powm_joye_tun(c, msg, e, n, 8);
    mpz_class m1, m2;
    rsa::powm_joye_tun(m1, c % p, dp, p, 6);
    rsa::powm_joye_tun(m2, c % q, dq, q, 6);
    mpz_class h = (qinv * (m1 - m2 + p)) % p;
    m = m2 + h * q;
    std::printf("  m=65 -> c=%s;  m1=%s  m2=%s  h=%s  =>  m=m2+h*q=%s\n", c.get_str().c_str(),
                m1.get_str().c_str(), m2.get_str().c_str(), h.get_str().c_str(), m.get_str().c_str());
    CHECK(d == 413 && dp == 53 && dq == 49 && qinv == 38, "d=413, dp=53, dq=49, qinv=38");
    CHECK(c == 2790 && m == 65, "c=2790, CRT-расшифрование даёт m=65");
}

static rsa::PublicKey g_pub;
static rsa::PrivateKey g_priv;

static void test_rsa() {
    std::printf("\n== Модули 1-2: ключи 3072 бит, CRT ==\n");
    rsa::generate_keypair(g_pub, g_priv);
    CHECK(mpz_sizeinbase(g_pub.n.get_mpz_t(), 2) == 3072, "N имеет ровно 3072 бита");
    CHECK(mpz_sizeinbase(g_priv.p.get_mpz_t(), 2) == 1536 && mpz_sizeinbase(g_priv.q.get_mpz_t(), 2) == 1536,
          "p и q по 1536 бит");
    CHECK(mpz_probab_prime_p(g_priv.p.get_mpz_t(), 30) && mpz_probab_prime_p(g_priv.q.get_mpz_t(), 30),
          "p, q простые (перепроверка GMP)");
    CHECK(g_priv.p * g_priv.q == g_pub.n, "N = p*q");
    mpz_class lambda = (g_priv.p - 1) / rsa::gcd(g_priv.p - 1, g_priv.q - 1) * (g_priv.q - 1);
    CHECK((g_priv.e * g_priv.d) % lambda == 1, "e*d = 1 mod lambda(N)");
    CHECK((g_priv.q * g_priv.qinv) % g_priv.p == 1, "q*qinv = 1 mod p");
    CHECK(g_priv.dp == g_priv.d % (g_priv.p - 1) && g_priv.dq == g_priv.d % (g_priv.q - 1), "dp, dq верны");

    bool ok = true;
    for (int i = 0; i < 10 && ok; ++i) {
        mpz_class m = rsa::random_bits(3000), c, m2, m3;
        rsa::rsa_encrypt_raw(c, m, g_pub);
        rsa::rsa_decrypt_crt(m2, c, g_priv);
        rsa::rsa_decrypt_plain(m3, c, g_priv);
        ok = (m2 == m) && (m3 == m);
    }
    CHECK(ok, "raw RSA: decrypt_crt == decrypt_plain == исходное m (10 раз)");
}

static void test_oaep() {
    std::printf("\n== Модуль 3: OAEP (k=384, hLen=32, max M = 318) ==\n");
    using namespace oaep;
    static_assert(MAX_MSG == 318, "max len");
    uint8_t ct[K], out[MAX_MSG];
    size_t olen = 0;
    const uint8_t* noLabel = nullptr;

    // граница 0 байт
    CHECK(rsa::oaep_encrypt(g_pub, nullptr, 0, noLabel, 0, ct) == 0 &&
              rsa::oaep_decrypt(g_priv, ct, noLabel, 0, out, &olen) == 0 && olen == 0,
          "M длиной 0 байт: шифр/расшифр успешно");

    // 1 байт
    uint8_t one = 0xAB;
    CHECK(rsa::oaep_encrypt(g_pub, &one, 1, noLabel, 0, ct) == 0 &&
              rsa::oaep_decrypt(g_priv, ct, noLabel, 0, out, &olen) == 0 && olen == 1 && out[0] == 0xAB,
          "M длиной 1 байт");

    // максимум 318 байт (включая нулевые байты в конце и в начале сообщения)
    uint8_t big[MAX_MSG];
    for (size_t i = 0; i < MAX_MSG; ++i) big[i] = static_cast<uint8_t>(i * 7 + 3);
    big[0] = 0x00; big[MAX_MSG - 1] = 0x00;
    CHECK(rsa::oaep_encrypt(g_pub, big, MAX_MSG, noLabel, 0, ct) == 0 &&
              rsa::oaep_decrypt(g_priv, ct, noLabel, 0, out, &olen) == 0 && olen == MAX_MSG &&
              std::memcmp(out, big, MAX_MSG) == 0,
          "M длиной 318 = k-2*hLen-2 (максимум)");

    // 319 байт -- отказ
    uint8_t toolong[MAX_MSG + 1] = {0};
    CHECK(rsa::oaep_encrypt(g_pub, toolong, MAX_MSG + 1, noLabel, 0, ct) == -1, "M длиной 319: отказ");

    // сообщение, начинающееся с 0x01 / нулей, не должно сбивать поиск разделителя
    uint8_t tricky[5] = {0x00, 0x00, 0x01, 0x00, 0x01};
    CHECK(rsa::oaep_encrypt(g_pub, tricky, 5, noLabel, 0, ct) == 0 &&
              rsa::oaep_decrypt(g_priv, ct, noLabel, 0, out, &olen) == 0 && olen == 5 &&
              std::memcmp(out, tricky, 5) == 0,
          "M = 00 00 01 00 01 восстанавливается точно");

    // вероятностность
    const char* txt = "hello OAEP";
    uint8_t ct2[K];
    rsa::oaep_encrypt(g_pub, reinterpret_cast<const uint8_t*>(txt), 10, noLabel, 0, ct);
    rsa::oaep_encrypt(g_pub, reinterpret_cast<const uint8_t*>(txt), 10, noLabel, 0, ct2);
    CHECK(std::memcmp(ct, ct2, K) != 0, "два шифрования одного M дают разные шифротексты");

    // label
    const uint8_t lab[3] = {'a', 'b', 'c'};
    rsa::oaep_encrypt(g_pub, reinterpret_cast<const uint8_t*>(txt), 10, lab, 3, ct);
    CHECK(rsa::oaep_decrypt(g_priv, ct, lab, 3, out, &olen) == 0 && olen == 10, "метка совпала -> успех");
    CHECK(rsa::oaep_decrypt(g_priv, ct, noLabel, 0, out, &olen) == -1 && olen == 0, "метка не совпала -> отказ");

    // повреждение шифротекста
    rsa::oaep_encrypt(g_pub, reinterpret_cast<const uint8_t*>(txt), 10, noLabel, 0, ct);
    ct[K - 1] ^= 0x01;
    CHECK(rsa::oaep_decrypt(g_priv, ct, noLabel, 0, out, &olen) == -1 && olen == 0, "повреждённый шифротекст -> отказ");
    bool zeros = true;
    for (size_t i = 0; i < MAX_MSG; ++i) zeros &= (out[i] == 0);
    CHECK(zeros, "при отказе выходной буфер полностью обнулён");

    // шифротекст >= N
    uint8_t ff[K];
    std::memset(ff, 0xFF, K);
    CHECK(rsa::oaep_decrypt(g_priv, ff, noLabel, 0, out, &olen) == -1, "c >= N -> отказ");

    // Структурные ошибки EM (каждая проверяется отдельно)
    std::printf("-- структурные ошибки EM (декодер напрямую) --\n");
    uint8_t seed[HLEN], em[K], good[K];
    for (size_t i = 0; i < HLEN; ++i) seed[i] = static_cast<uint8_t>(0x11 + i);
    encode_with_seed(good, reinterpret_cast<const uint8_t*>(txt), 10, noLabel, 0, seed);
    std::memcpy(em, good, K);
    CHECK(decode(out, &olen, em, noLabel, 0) == 0 && olen == 10 && std::memcmp(out, txt, 10) == 0,
          "эталонный EM декодируется");
    std::memcpy(em, good, K); em[0] = 0x01;
    CHECK(decode(out, &olen, em, noLabel, 0) == -1, "первый байт != 0x00 -> отказ");
    std::memcpy(em, good, K); em[1 + HLEN + 5] ^= 0x80;   // портим maskedDB -> ломается lHash/структура
    CHECK(decode(out, &olen, em, noLabel, 0) == -1, "испорчен maskedDB -> отказ");
    std::memcpy(em, good, K); em[5] ^= 0x01;              // портим maskedSeed
    CHECK(decode(out, &olen, em, noLabel, 0) == -1, "испорчен maskedSeed -> отказ");

    // Собираем EM вручную, чтобы сломать ровно один элемент структуры:
    auto build = [&](const uint8_t* lh, size_t ps_zeros, uint8_t sep, uint8_t* dest) {
        uint8_t db[DBLEN];
        std::memcpy(db, lh, HLEN);
        std::memset(db + HLEN, 0, DBLEN - HLEN);
        db[HLEN + ps_zeros] = sep;  // разделитель
        uint8_t dbm[DBLEN], sm[HLEN];
        mgf1_sha256(seed, HLEN, dbm, DBLEN);
        for (size_t i = 0; i < DBLEN; ++i) db[i] ^= dbm[i];
        mgf1_sha256(db, DBLEN, sm, HLEN);
        dest[0] = 0;
        for (size_t i = 0; i < HLEN; ++i) dest[1 + i] = seed[i] ^ sm[i];
        std::memcpy(dest + 1 + HLEN, db, DBLEN);
    };
    uint8_t lh[HLEN];
    sha::sha256(nullptr, 0, lh);
    build(lh, 10, 0x01, em);
    CHECK(decode(out, &olen, em, noLabel, 0) == 0 && olen == DBLEN - HLEN - 10 - 1,
          "собранный вручную корректный EM (M = нули) декодируется");
    build(lh, 10, 0x02, em);
    CHECK(decode(out, &olen, em, noLabel, 0) == -1, "вместо разделителя 0x01 стоит 0x02 -> отказ");
    {   // разделителя нет вообще: DB = lHash || 00 00 ... 00
        uint8_t db[DBLEN], dbm[DBLEN], sm[HLEN];
        std::memcpy(db, lh, HLEN);
        std::memset(db + HLEN, 0, DBLEN - HLEN);
        mgf1_sha256(seed, HLEN, dbm, DBLEN);
        for (size_t i = 0; i < DBLEN; ++i) db[i] ^= dbm[i];
        mgf1_sha256(db, DBLEN, sm, HLEN);
        em[0] = 0;
        for (size_t i = 0; i < HLEN; ++i) em[1 + i] = seed[i] ^ sm[i];
        std::memcpy(em + 1 + HLEN, db, DBLEN);
        CHECK(decode(out, &olen, em, noLabel, 0) == -1, "разделителя 0x01 нет -> отказ");
    }
    uint8_t badh[HLEN];
    std::memcpy(badh, lh, HLEN); badh[HLEN - 1] ^= 1;  // отличие только в последнем байте lHash
    build(badh, 10, 0x01, em);
    CHECK(decode(out, &olen, em, noLabel, 0) == -1, "lHash отличается в ПОСЛЕДНЕМ байте -> отказ");
}

int main() {
    std::printf("Лабораторная №2, вариант 8: RSA-3072, SHA-256, Joye-Tun\n");
    test_sha256();
    test_numtheory();
    test_crt_small();
    test_rsa();
    test_oaep();
    std::printf("\nИтого: %d проверок, провалено: %d\n", g_total, g_fail);
    return g_fail ? 1 : 0;
}
