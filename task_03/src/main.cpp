#include <cstdio>
#include <cstring>
#include <chrono>
#include "ec_algebra.h"
#include "ct_secure.h"
#include "protocols.h"

static int g_failed = 0;

static void check(const char* name, bool ok) {
    std::printf("%-78s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_failed;
}

static void hexToBytes(const char* hex, uint8_t* out, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned v = 0;
        std::sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void printHex(const char* label, const uint8_t* d, size_t n) {
    std::printf("%s: ", label);
    for (size_t i = 0; i < n; ++i) std::printf("%02x", d[i]);
    std::printf("\n");
}

static void printFe(const char* label, const Fe& f) {
    uint8_t le[32];
    feToBytes(f, le);
    std::printf("%s: ", label);
    for (int i = 31; i >= 0; --i) std::printf("%02x", le[i]);   // big-endian hex
    std::printf("\n");
}

static void printPoint(const char* label, const Point& P) {
    Fe x, y;
    pointToAffine(P, &x, &y);
    std::printf("%s\n", label);
    printFe("  x", x);
    printFe("  y", y);
}

static void scalarFromU64(uint64_t v, uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = i < 8 ? (uint8_t)(v >> (8 * i)) : 0;
}

struct Vector {
    const char* name;
    const char* seed;
    const char* pub;
    const char* msgHex;
    const char* sig;
};

int main() {
    std::printf("=== Модуль 1: поле и кривая ===\n");
    const Point G = pointBase();
    printPoint("Базовая точка G (hex, big-endian):", G);
    check("G лежит на кривой -x^2 + y^2 = 1 + d x^2 y^2", pointOnCurve(G));

    {   // инверсия в поле
        Fe a = feFromU64(123456789);
        check("a * a^(-1) = 1 в GF(p)", feEqual(feMul(a, feInvert(a)), feOne()) == 1);
        Fe m1 = feNeg(feOne());
        check("(-1)^2 = 1 в GF(p)", feEqual(feSquare(m1), feOne()) == 1);
    }

    std::printf("\n=== Единая формула сложения и удвоения (вариант 8) ===\n");
    {
        // Полнота формулы: a = -1 - квадрат, d - квадратичный невычет в GF(p)
        static const uint64_t HALF[4] = {0xfffffffffffffff6ULL, 0xffffffffffffffffULL,
                                         0xffffffffffffffffULL, 0x3fffffffffffffffULL};  // (p - 1) / 2
        static const uint64_t QUARTER[4] = {0xfffffffffffffffbULL, 0xffffffffffffffffULL,
                                            0xffffffffffffffffULL, 0x1fffffffffffffffULL}; // (p - 1) / 4
        Fe minusOne = feNeg(feOne());
        check("d - квадратичный невычет: d^((p-1)/2) = -1", feEqual(fePow(curve().d, HALF), minusOne) == 1);
        Fe i = fePow(feFromU64(2), QUARTER);
        check("a = -1 - квадрат: существует i, i^2 = -1", feEqual(feSquare(i), minusOne) == 1);
        Point G2a = pointDouble(G);                       // удвоение той же функцией pointAdd(G, G)
        Point G2b = pointAdd(G, G);
        check("Double(G) == Add(G, G): одна формула без ветвления P == Q", pointEqual(G2a, G2b) == 1);
        // независимая проверка удвоения аффинной формулой: x3 = 2xy / (y^2 - x^2), y3 = (y^2 + x^2) / (2 - y^2 + x^2)
        Fe x = curve().Gx, y = curve().Gy;
        Fe x2 = feSquare(x), y2 = feSquare(y);
        Fe x3 = feMul(feAdd(feMul(x, y), feMul(x, y)), feInvert(feSub(y2, x2)));
        Fe y3 = feMul(feAdd(y2, x2), feInvert(feAdd(feSub(feFromU64(2), y2), x2)));
        check("Add(G, G) совпадает с аффинной формулой удвоения кривой Эдвардса",
              pointEqual(G2a, pointFromAffine(x3, y3)) == 1);
        check("2G лежит на кривой", pointOnCurve(G2a));
        check("Add(G, O) == G (нейтральный элемент без особого случая)", pointEqual(pointAdd(G, pointIdentity()), G) == 1);
        check("Add(O, O) == O", pointEqual(pointAdd(pointIdentity(), pointIdentity()), pointIdentity()) == 1);
        check("Add(G, -G) == O (взаимно обратные точки без особого случая)",
              pointEqual(pointAdd(G, pointNeg(G)), pointIdentity()) == 1);
        Point G3a = pointAdd(G2a, G), G3b = pointAdd(G, G2a);
        check("Add коммутативно: 2G + G == G + 2G", pointEqual(G3a, G3b) == 1);
        check("Add ассоциативно: (G + 2G) + G == G + (2G + G)",
              pointEqual(pointAdd(G3a, G), pointAdd(G, G3a)) == 1);
    }

    std::printf("\n=== Скалярное умножение ===\n");
    {
        uint8_t k5[32], k7[32];
        scalarFromU64(5, k5);
        scalarFromU64(7, k7);
        Point g5 = SecureMultiply(k5, G);
        Point manual = pointAdd(pointDouble(pointDouble(G)), G);
        check("SecureMultiply(5, G) == 4G + G", pointEqual(g5, manual) == 1);
        check("SecureMultiply == классический Double-and-Add для k = 5, 7",
              pointEqual(g5, pointMulDoubleAndAdd(k5, G)) == 1 &&
              pointEqual(SecureMultiply(k7, G), pointMulDoubleAndAdd(k7, G)) == 1);

        const uint8_t* q = curve().q;
        check("q * G == O (порядок подгруппы)", pointEqual(SecureMultiply(q, G), pointIdentity()) == 1);
        uint8_t q1[32];
        std::memcpy(q1, q, 32);
        q1[0] += 1;                                       // младший байт q = 0xed, переноса нет
        check("(q + 1) * G == G", pointEqual(SecureMultiply(q1, G), G) == 1);
        uint8_t zero[32] = {0};
        check("0 * G == O", pointEqual(SecureMultiply(zero, G), pointIdentity()) == 1);

        uint8_t enc[32];
        pointEncode(g5, enc);
        Point back;
        bool dec = pointDecode(enc, &back);
        check("Кодирование и декодирование точки 5G", dec && pointEqual(back, g5) == 1);
        enc[31] ^= 0x80;
        Point neg;
        bool dec2 = pointDecode(enc, &neg);
        check("Инвертированный бит знака x даёт точку -5G", dec2 && pointEqual(neg, pointNeg(g5)) == 1);
    }

    std::printf("\n=== SHA-512 (собственная реализация) ===\n");
    {
        uint8_t out[64], exp[64];
        sha512((const uint8_t*)"abc", 3, out);
        hexToBytes("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", exp, 64);
        check("SHA-512(\"abc\")", std::memcmp(out, exp, 64) == 0);
        sha512((const uint8_t*)"", 0, out);
        hexToBytes("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", exp, 64);
        check("SHA-512(\"\")", std::memcmp(out, exp, 64) == 0);
        uint8_t long_msg[200];
        for (int i = 0; i < 200; ++i) long_msg[i] = (uint8_t)i;
        sha512(long_msg, 200, out);
        printHex("SHA-512(00..c7), 200 байт, 2 блока", out, 64);
    }

    std::printf("\n=== EdDSA Ed25519: тестовые векторы ===\n");
    const Vector vectors[] = {
        {"RFC 8032, TEST 1 (пустое сообщение)",
         "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
        {"RFC 8032, TEST 2 (1 байт: 72)",
         "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
        {"Эталон OpenSSL 3.6.3 (pkeyutl -sign -rawin)",
         "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
         "712651f450ba05b63898b99ef5f7ba45632e8e2527f7f715cd671ec4024cc51e",
         "4b4d5a49206c6162332076617269616e742038",
         "93378adbdc01af68e3ee113b125e1641e2a81c46941eb1977bb533b9ae9cb62c80939dd730ee99b09a74943eb903f5e3d8dfed97d48ba531433a5935d7ba3509"}};
    for (const Vector& v : vectors) {
        uint8_t seed[32], pub[32], sig[64], msg[64], got[64];
        size_t mlen = std::strlen(v.msgHex) / 2;
        hexToBytes(v.seed, seed, 32);
        hexToBytes(v.pub, pub, 32);
        hexToBytes(v.sig, sig, 64);
        hexToBytes(v.msgHex, msg, mlen);
        KeyPair kp;
        eddsaKeyFromSeed(seed, &kp);
        std::printf("%s\n", v.name);
        printHex("  публичный ключ ", kp.publicKey, 32);
        eddsaSign(kp, msg, mlen, got);
        printHex("  подпись (R||S) ", got, 64);
        check("  публичный ключ совпадает с эталоном", std::memcmp(kp.publicKey, pub, 32) == 0);
        check("  подпись совпадает с эталоном (EdDSA детерминирован)", std::memcmp(got, sig, 64) == 0);
        check("  проверка подписи успешна", eddsaVerify(kp.publicKey, msg, mlen, got));
    }

    std::printf("\n=== ECDH на кривой Эдвардса ===\n");
    {
        uint8_t seedA[32], seedB[32], sharedA[32], sharedB[32];
        for (int i = 0; i < 32; ++i) { seedA[i] = (uint8_t)(i + 1); seedB[i] = (uint8_t)(0xA0 ^ (i * 7)); }
        KeyPair alice, bob;
        eddsaKeyFromSeed(seedA, &alice);
        eddsaKeyFromSeed(seedB, &bob);
        printHex("Alice, открытый ключ Q_A", alice.publicKey, 32);
        printHex("Bob,   открытый ключ Q_B", bob.publicKey, 32);
        bool okA = ecdhSharedSecret(alice.scalar, bob.publicKey, sharedA);
        bool okB = ecdhSharedSecret(bob.scalar, alice.publicKey, sharedB);
        printHex("Shared Secret у Alice (d_A * Q_B)", sharedA, 32);
        printHex("Shared Secret у Bob   (d_B * Q_A)", sharedB, 32);
        check("Alice и Bob получили одинаковый Shared Secret", okA && okB && ctCompareBytes(sharedA, sharedB, 32) == 1);
        uint8_t other[32];
        KeyPair eve;
        uint8_t seedE[32];
        for (int i = 0; i < 32; ++i) seedE[i] = (uint8_t)(0x55 + i);
        eddsaKeyFromSeed(seedE, &eve);
        ecdhSharedSecret(eve.scalar, bob.publicKey, other);
        check("Третья сторона (Eve) получает другой секрет", ctCompareBytes(sharedA, other, 32) == 0);
        uint8_t identity[32] = {1};                       // y = 1, x = 0: нейтральный элемент
        uint8_t dummy[32];
        check("Публичный ключ - нейтральный элемент отвергается", !ecdhSharedSecret(alice.scalar, identity, dummy));
    }

    std::printf("\n=== Подпись - проверка и отбраковка искажений ===\n");
    {
        uint8_t seed[32];
        for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)(0xC3 + 5 * i);
        KeyPair kp;
        eddsaKeyFromSeed(seed, &kp);
        const char* texts[] = {"KMZI", "Variant 8: Ed25519, unified addition", "The quick brown fox jumps over the lazy dog"};
        for (const char* t : texts) {
            const uint8_t* m = (const uint8_t*)t;
            size_t n = std::strlen(t);
            uint8_t sig[64];
            eddsaSign(kp, m, n, sig);
            printHex("  подпись", sig, 64);
            check("  сообщение подписано и проверено", eddsaVerify(kp.publicKey, m, n, sig));
            uint8_t badS[64];
            std::memcpy(badS, sig, 64);
            badS[40] ^= 0x01;                             // один бит в параметре S
            check("  искажение одного байта в S отвергнуто", !eddsaVerify(kp.publicKey, m, n, badS));
            uint8_t badR[64];
            std::memcpy(badR, sig, 64);
            badR[5] ^= 0x01;
            check("  искажение одного байта в R отвергнуто", !eddsaVerify(kp.publicKey, m, n, badR));
            uint8_t badM[64];
            std::memcpy(badM, t, n);
            badM[0] ^= 0x01;
            check("  искажение сообщения отвергнуто", !eddsaVerify(kp.publicKey, badM, n, sig));
            uint8_t badQ[32];
            std::memcpy(badQ, kp.publicKey, 32);
            badQ[0] ^= 0x01;
            check("  чужой открытый ключ отвергнут", !eddsaVerify(badQ, m, n, sig));
            uint8_t big[64];                              // S + q: должен отбрасываться проверкой S < q
            std::memcpy(big, sig, 64);
            check("  S >= q отвергается (неоднозначность подписи)", [&] {
                const uint8_t* q = curve().q;
                unsigned carry = 0;
                for (int i = 0; i < 32; ++i) { unsigned s = big[32 + i] + q[i] + carry; big[32 + i] = (uint8_t)s; carry = s >> 8; }
                return !eddsaVerify(kp.publicKey, m, n, big);
            }());
        }
    }

    std::printf("\n=== Индикативный замер времени (лучший из 7 раундов по 100 вызовов; не доказательство) ===\n");
    {
        uint8_t kLow[32] = {0}, kHigh[32], kMix[32];
        kLow[0] = 1;                                      // вес Хэмминга 1
        for (int i = 0; i < 32; ++i) { kHigh[i] = 0xFF; kMix[i] = (uint8_t)(0xA5 + i * 13); }
        const uint8_t* ks[3] = {kLow, kHigh, kMix};
        const char* names[3] = {"k = 1 (вес Хэмминга 1)", "k = 2^256-1 (вес 256)  ", "k = смешанный          "};
        auto bench = [&](bool secure, const uint8_t* k) {
            double best = 1e18;
            for (int round = 0; round < 7; ++round) {
                auto t0 = std::chrono::steady_clock::now();
                for (int it = 0; it < 100; ++it) {
                    Point R = secure ? SecureMultiply(k, G) : pointMulDoubleAndAdd(k, G);
                    asm volatile("" : : "r"(&R) : "memory");
                }
                auto t1 = std::chrono::steady_clock::now();
                double us = std::chrono::duration<double, std::micro>(t1 - t0).count() / 100.0;
                if (us < best) best = us;
            }
            return best;
        };
        bench(true, kMix); bench(false, kMix);            // прогрев
        double sec[3], naive[3];
        for (int t = 0; t < 3; ++t) { sec[t] = bench(true, ks[t]); naive[t] = bench(false, ks[t]); }
        for (int t = 0; t < 3; ++t)
            std::printf("  SecureMultiply          %s: %7.1f мкс (%+.1f%% к k=1)\n", names[t], sec[t], 100.0 * (sec[t] - sec[0]) / sec[0]);
        for (int t = 0; t < 3; ++t)
            std::printf("  Классический Double-Add %s: %7.1f мкс (%+.1f%% к k=1)\n", names[t], naive[t], 100.0 * (naive[t] - naive[0]) / naive[0]);
    }

    std::printf("\nИтог: %s\n", g_failed == 0 ? "все тесты пройдены" : "ЕСТЬ ОШИБКИ");
    return g_failed == 0 ? 0 : 1;
}
