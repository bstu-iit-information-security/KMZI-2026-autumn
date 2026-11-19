
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "gcm.hpp"

static int g_fail = 0, g_total = 0;

static void check(bool cond, const char* name) {
    ++g_total;
    if (!cond) ++g_fail;
    std::printf("[%s] %s\n", cond ? " OK " : "FAIL", name);
}

static std::vector<uint8_t> hex(const std::string& s) {
    std::vector<uint8_t> r;
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        r.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    return r;
}

static std::string to_hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}

static constexpr uint16_t kVariantPoly = 0x12D;  // вариант 5

static void test_field(uint16_t p) {
    std::printf("\n--- Поле GF(2^8), p(x) = 0x%03X ---\n", p);
    check(gf::GF256::is_irreducible(p), "p(x) неприводим");
    gf::GF256 f(p);

    check(f.inverse(0) == 0, "inverse(0) == 0 (без деления на ноль)");
    bool inv_ok = true, euclid_ok = true;
    for (int a = 1; a < 256; ++a) {
        const uint8_t x = static_cast<uint8_t>(a);
        inv_ok &= (f.multiply(x, f.inverse(x)) == 1);
        euclid_ok &= (f.inverse(x) == gf::GF256::inverse_euclid(x, p));
    }
    check(inv_ok, "a * a^-1 == 1 для всех a != 0");
    check(euclid_ok, "a^254 совпадает с расширенным алгоритмом Евклида");

    // Переполнение при редукции: старший бит = 1 на каждом шаге
    check(f.multiply(0x80, 0x02) == static_cast<uint8_t>(p & 0xFF), "x^7 * x = x^8 = p_byte (редукция)");
    check(f.multiply(0xFF, 0xFF) == f.multiply(0xFF, 0xFF) && f.multiply(0xFF, 0x01) == 0xFF, "умножение на 1 и 0xFF*0xFF");
    bool comm = true, distr = true;
    for (int a = 0; a < 256; a += 7)
        for (int b = 0; b < 256; b += 5) {
            comm &= f.multiply((uint8_t)a, (uint8_t)b) == f.multiply((uint8_t)b, (uint8_t)a);
            distr &= f.multiply((uint8_t)a, (uint8_t)(b ^ 0x5A)) ==
                     (uint8_t)(f.multiply((uint8_t)a, (uint8_t)b) ^ f.multiply((uint8_t)a, 0x5A));
        }
    check(comm && distr, "коммутативность и дистрибутивность умножения");

    std::array<uint8_t, 256> s, is;
    f.generate_sbox(s, is);
    bool perm = true;
    for (int i = 0; i < 256; ++i) perm &= (is[s[i]] == i);
    check(perm, "S-box — перестановка, inv_sbox её обращает");
    check(gf::GF256::inv_affine(gf::GF256::affine(0xA7)) == 0xA7, "inv_affine(affine(x)) == x");
}

static void test_standard_aes() {
    std::printf("\n--- Контроль на стандартном AES (p = 0x11B) ---\n");
    gf::GF256 f(0x11B);
    std::array<uint8_t, 256> s, is;
    f.generate_sbox(s, is);
    check(s[0x00] == 0x63 && s[0x01] == 0x7C && s[0x53] == 0xED && s[0xFF] == 0x16, "S-box: 63 7C ... ED ... 16");

    auto key = hex("000102030405060708090a0b0c0d0e0f");
    auto pt = hex("00112233445566778899aabbccddeeff");
    Aes128 aes(key.data(), 0x11B);
    check(aes.inv_mix_matrix()[0] == 0x0E && aes.inv_mix_matrix()[1] == 0x0B &&
          aes.inv_mix_matrix()[2] == 0x0D && aes.inv_mix_matrix()[3] == 0x09,
          "обратная матрица MixColumns: 0E 0B 0D 09");
    uint8_t ct[16], back[16];
    aes.encrypt_block(pt.data(), ct);
    check(to_hex(ct, 16) == "69c4e0d86a7b0430d8cdb78070b4c55a", "FIPS-197 C.1: зашифрование");
    aes.decrypt_block(ct, back);
    check(std::memcmp(back, pt.data(), 16) == 0, "FIPS-197 C.1: расшифрование");

    // Контрольные векторы GCM (McGrew & Viega / NIST)
    {
        auto k = hex("00000000000000000000000000000000");
        auto iv = hex("000000000000000000000000");
        Aes128 a(k.data(), 0x11B);
        gcm::Gcm g(a);
        uint8_t tag[16];
        g.encrypt(iv.data(), nullptr, 0, nullptr, 0, nullptr, tag);
        check(to_hex(tag, 16) == "58e2fccefa7e3061367f1d57a4e7455a", "GCM Test Case 1 (пустые данные): тег");

        auto p = hex("00000000000000000000000000000000");
        uint8_t c[16];
        g.encrypt(iv.data(), nullptr, 0, p.data(), 16, c, tag);
        check(to_hex(c, 16) == "0388dace60b6a392f328c2b971b2fe78" &&
              to_hex(tag, 16) == "ab6e47d42cec13bdf53a67b21257bddf", "GCM Test Case 2: шифротекст и тег");
    }
    {
        auto k = hex("feffe9928665731c6d6a8f9467308308");
        auto iv = hex("cafebabefacedbaddecaf888");
        auto p = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                     "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        auto aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        Aes128 a(k.data(), 0x11B);
        gcm::Gcm g(a);
        std::vector<uint8_t> c(p.size()), d(p.size());
        uint8_t tag[16];
        g.encrypt(iv.data(), aad.data(), aad.size(), p.data(), p.size(), c.data(), tag);
        check(to_hex(c.data(), c.size()) ==
              "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
              "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091" &&
              to_hex(tag, 16) == "5bc94fbc3221a5db94fae95ae7121a47",
              "GCM Test Case 4 (с AAD, неполный блок): шифротекст и тег");
        check(g.decrypt(iv.data(), aad.data(), aad.size(), c.data(), c.size(), tag, d.data()) && d == p,
              "GCM Test Case 4: расшифрование");
    }
}

static void test_variant() {
    std::printf("\n--- Вариант 5: AES-128, p(x) = 0x%03X ---\n", kVariantPoly);
    auto key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    Aes128 aes(key.data(), kVariantPoly);

    // MixColumns / InvMixColumns
    bool mix_ok = true, prod_ok = true;
    gf::GF256 f(kVariantPoly);
    for (int t = 0; t < 64; ++t) {
        uint8_t s[16], o[16];
        for (int i = 0; i < 16; ++i) s[i] = o[i] = static_cast<uint8_t>(t * 37 + i * 91 + (t * i) % 251);
        aes.mix_columns_public(s);
        aes.inv_mix_columns_public(s);
        mix_ok &= std::memcmp(s, o, 16) == 0;
    }
    check(mix_ok, "InvMixColumns(MixColumns(x)) == x");
    // M * M^-1 == I
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j) {
            uint8_t acc = 0;
            for (int k = 0; k < 4; ++k)
                acc ^= f.multiply(aes.mix_matrix()[4 * i + k], aes.inv_mix_matrix()[4 * k + j]);
            prod_ok &= acc == (i == j ? 1 : 0);
        }
    check(prod_ok, "M * M^-1 == E (обратная матрица над GF(2^8) по 0x12D)");

    // Шифр: обратимость на нескольких блоках
    bool rt = true;
    for (int t = 0; t < 32; ++t) {
        uint8_t p[16], c[16], d[16];
        for (int i = 0; i < 16; ++i) p[i] = static_cast<uint8_t>(t * 13 + i * 29);
        aes.encrypt_block(p, c);
        aes.decrypt_block(c, d);
        rt &= std::memcmp(p, d, 16) == 0 && std::memcmp(p, c, 16) != 0;
    }
    check(rt, "Decrypt(Encrypt(x)) == x для p = 0x12D");

    // GCM
    auto iv = hex("cafebabefacedbaddecaf888");
    auto aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    std::vector<uint8_t> p(61), c(61), d(61);
    for (size_t i = 0; i < p.size(); ++i) p[i] = static_cast<uint8_t>(i * 7 + 3);
    gcm::Gcm g(aes);
    uint8_t tag[16];
    g.encrypt(iv.data(), aad.data(), aad.size(), p.data(), p.size(), c.data(), tag);
    check(g.decrypt(iv.data(), aad.data(), aad.size(), c.data(), c.size(), tag, d.data()) && d == p,
          "GCM: расшифрование корректного сообщения");

    // Нарушение целостности: шифротекст, AAD, тег
    std::vector<uint8_t> c2 = c;
    c2[10] ^= 1;
    check(!g.decrypt(iv.data(), aad.data(), aad.size(), c2.data(), c2.size(), tag, d.data()),
          "GCM: изменённый шифротекст отвергнут");
    bool wiped = true;
    for (uint8_t b : d) wiped &= (b == 0);
    check(wiped, "GCM: при ошибке тега открытый текст занулён");
    auto aad2 = aad; aad2[0] ^= 0x80;
    check(!g.decrypt(iv.data(), aad2.data(), aad2.size(), c.data(), c.size(), tag, d.data()),
          "GCM: изменённый AAD отвергнут");
    // Атака ранним выходом: ошибка в первом и в последнем байте тега даёт одинаковый результат
    uint8_t t1[16], t2[16];
    std::memcpy(t1, tag, 16); std::memcpy(t2, tag, 16);
    t1[0] ^= 1; t2[15] ^= 1;
    check(!gcm::ct_equal(t1, tag, 16) && !gcm::ct_equal(t2, tag, 16) && gcm::ct_equal(tag, tag, 16),
          "ct_equal: ошибка в 1-м и в 16-м байте обнаруживается (все 16 байт обрабатываются)");
    // XOR-аккумулятор из методички обнуляется при двух одинаковых разностях; OR-аккумулятор — нет
    uint8_t a[16] = {0}, b[16] = {0};
    b[3] = 0x55; b[9] = 0x55;
    check(!gcm::ct_equal(a, b, 16), "ct_equal: две одинаковые разности байтов не гасят друг друга");

    // Демонстрация
    std::printf("\nОбратная матрица MixColumns (p = 0x%03X):\n", kVariantPoly);
    for (int i = 0; i < 4; ++i)
        std::printf("  %02X %02X %02X %02X\n", aes.inv_mix_matrix()[4 * i], aes.inv_mix_matrix()[4 * i + 1],
                    aes.inv_mix_matrix()[4 * i + 2], aes.inv_mix_matrix()[4 * i + 3]);
    std::printf("S-box[00..07]: ");
    for (int i = 0; i < 8; ++i) std::printf("%02X ", aes.sbox()[i]);
    std::printf("\nGCM: ciphertext = %s\n     tag        = %s\n", to_hex(c.data(), c.size()).c_str(),
                to_hex(tag, 16).c_str());
}

int main() {
    test_field(0x11B);
    test_field(kVariantPoly);
    test_standard_aes();
    test_variant();
    std::printf("\nИтого: %d/%d проверок пройдено\n", g_total - g_fail, g_total);
    return g_fail == 0 ? 0 : 1;
}
