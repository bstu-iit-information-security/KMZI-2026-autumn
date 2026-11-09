#include "aes128.hpp"
#include "gcm.hpp"
#include "gf8.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

int g_failed = 0;

void print_hex(const uint8_t* data, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        std::printf("%02x", static_cast<unsigned>(data[i]));
    }
}

void check(const char* name, bool ok) {
    if (ok) {
        std::printf("  [OK] %s\n", name);
        return;
    }
    std::printf("  [FAIL] %s\n", name);
    ++g_failed;
}

bool is_hex(const uint8_t* data, std::size_t n, const char* hex) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < n; ++i) {
        const int hi = nibble(hex[2 * i]);
        const int lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0 || data[i] != static_cast<uint8_t>((hi << 4) | lo)) {
            return false;
        }
    }
    return true;
}

void check_hex(const char* name, const uint8_t* data, std::size_t n, const char* want) {
    if (is_hex(data, n, want)) {
        std::printf("  [OK] %s\n", name);
        return;
    }
    std::printf("  [FAIL] %s\n    got  ", name);
    print_hex(data, n);
    std::printf("\n    want %s\n", want);
    ++g_failed;
}

uint8_t schoolbook(uint8_t a, uint8_t b, uint16_t poly) {
    uint8_t result = 0;
    const uint8_t modulus = static_cast<uint8_t>(poly);
    for (int i = 0; i < 8; ++i) {
        if ((b & 1u) != 0) {
            result ^= a;
        }
        const bool high = (a & 0x80u) != 0;
        a = static_cast<uint8_t>(a << 1);
        if (high) {
            a ^= modulus;
        }
        b = static_cast<uint8_t>(b >> 1);
    }
    return result;
}

void test_field() {
    std::printf("\n== GF(2^8), p(x)=0x14D, Карацуба ==\n");
    const Gf8 field;
    const uint8_t sum = Gf8::add(0x57, 0x83);
    check_hex("add(0x57, 0x83)", &sum, 1, "d4");

    int mul_fail = 0;
    int inv_fail = 0;
    for (int a = 0; a < 256; ++a) {
        const uint8_t ua = static_cast<uint8_t>(a);
        const uint8_t inv = field.inverse(ua);
        const uint8_t product = field.multiply(ua, inv);
        if (product != (a == 0 ? 0 : 1)) {
            ++inv_fail;
        }
        for (int b = 0; b < 256; ++b) {
            const uint8_t ub = static_cast<uint8_t>(b);
            if (field.multiply(ua, ub) != schoolbook(ua, ub, Gf8::kPoly)) {
                ++mul_fail;
            }
        }
    }
    check("Карацуба совпадает со shift-and-XOR на 65536 парах", mul_fail == 0);
    check("0^(-1)=0 и a*a^(-1)=1 для остальных", inv_fail == 0);
    const uint8_t doubled = field.xtime(0x80);
    check_hex("xtime(0x80) редуцируется по 0x4D", &doubled, 1, "4d");

    const Gf8 aes_field(0x11B);
    uint8_t aes_product = aes_field.multiply(0x57, 0x83);
    check_hex("в поле AES 0x57*0x83 = 0xC1", &aes_product, 1, "c1");

    uint8_t sbox[256];
    aes_field.fill_sbox(sbox);
    check_hex("S-box AES: S(0x00)=0x63", &sbox[0x00], 1, "63");
    check_hex("S-box AES: S(0x53)=0xED", &sbox[0x53], 1, "ed");

    uint8_t variant_sbox[256];
    field.fill_sbox(variant_sbox);
    check_hex("S-box варианта, первые 16 байт", variant_sbox, 16, "637c4d5774b179ca4904abfc6eefb72d");
    check("S-box варианта отличается от AES: S(0x02)", variant_sbox[2] != sbox[2]);
}

void test_aes() {
    std::printf("\n== AES-128 ==\n");
    const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    const uint8_t plain[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    uint8_t cipher[16];
    uint8_t back[16];
    Aes128 standard(key, 0x11B);
    standard.encrypt_block(plain, cipher);
    standard.decrypt_block(cipher, back);
    check_hex("FIPS-197", cipher, 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
    check("FIPS-197 расшифрование", std::memcmp(back, plain, 16) == 0);

    Aes128 variant(key, Gf8::kPoly);
    variant.encrypt_block(plain, cipher);
    variant.decrypt_block(cipher, back);
    check("вариант 11: расшифрование возвращает блок", std::memcmp(back, plain, 16) == 0);
    check("вариант 11: шифртекст отличается от FIPS-197",
          !is_hex(cipher, 16, "69c4e0d86a7b0430d8cdb78070b4c55a"));
    std::printf("  шифртекст варианта 11: ");
    print_hex(cipher, 16);
    std::printf("\n");
}

void test_gcm() {
    std::printf("\n== AES-GCM ==\n");
    const uint8_t zero_key[16] = {};
    const uint8_t zero_iv[12] = {};
    const uint8_t zero_block[16] = {};
    uint8_t cipher[16];
    uint8_t tag[16];

    AesGcm empty(zero_key, 0x11B);
    empty.encrypt(zero_iv, nullptr, 0, nullptr, 0, nullptr, tag);
    check_hex("NIST GCM, пустой текст, тег", tag, 16, "58e2fccefa7e3061367f1d57a4e7455a");

    AesGcm zeros(zero_key, 0x11B);
    zeros.encrypt(zero_iv, nullptr, 0, zero_block, 16, cipher, tag);
    check_hex("NIST GCM, нулевой блок, шифртекст", cipher, 16, "0388dace60b6a392f328c2b971b2fe78");
    check_hex("NIST GCM, нулевой блок, тег", tag, 16, "ab6e47d42cec13bdf53a67b21257bddf");

    const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    const uint8_t iv[12] = {0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88};
    const uint8_t block_plain[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    const uint8_t block_aad[4] = {0xFE, 0xED, 0xFA, 0xCE};
    uint8_t block_ct[16];
    AesGcm aligned(key, Gf8::kPoly);
    aligned.encrypt(iv, block_aad, sizeof(block_aad), block_plain, sizeof(block_plain), block_ct, tag);
    check_hex("вариант 11, полный блок, шифртекст", block_ct, 16, "2e7ec25d36941f64c24a248e88dadf3c");
    check_hex("вариант 11, полный блок, тег", tag, 16, "369d8a24c7c8e3c8f42ee11f297774e7");

    const uint8_t aad[7] = {0xFE, 0xED, 0xFA, 0xCE, 0x01, 0x02, 0x03};
    const uint8_t plain[20] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                               0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67};
    uint8_t ct[20];
    uint8_t restored[20];
    AesGcm gcm(key, Gf8::kPoly);
    gcm.encrypt(iv, aad, sizeof(aad), plain, sizeof(plain), ct, tag);

    const bool accepted = gcm.decrypt(iv, aad, sizeof(aad), ct, sizeof(ct), tag, restored);
    check("вариант 11: тег принят", accepted);
    check("вариант 11: текст восстановлен", std::memcmp(restored, plain, sizeof(plain)) == 0);

    uint8_t bad[16];
    std::memcpy(bad, tag, 16);
    bad[15] ^= 0x01;
    std::memset(restored, 0xA5, sizeof(restored));
    const bool rejected = !gcm.decrypt(iv, aad, sizeof(aad), ct, sizeof(ct), bad, restored);
    check("испорченный тег отвергнут", rejected);
    bool wiped = true;
    for (uint8_t byte : restored) {
        wiped = wiped && byte == 0;
    }
    check("при неверном теге открытый текст не выдаётся", wiped);

    uint8_t same[16] = {};
    uint8_t other[16] = {};
    check("сравнение тегов: равные", AesGcm::tags_equal(same, other));
    other[0] = 0x01;
    check("сравнение тегов: отличие в первом байте", !AesGcm::tags_equal(same, other));
    other[0] = 0x00;
    other[15] = 0x01;
    check("сравнение тегов: отличие в последнем байте", !AesGcm::tags_equal(same, other));
    other[0] = 0x0F;
    other[1] = 0x0F;
    other[15] = 0x00;
    check("сравнение тегов: ненулевые разности не гасят друг друга", !AesGcm::tags_equal(same, other));
}

}  // namespace

int main() {
    std::printf("ЛР1, вариант 11: AES-128-GCM, p(x)=0x14D, умножение Карацубы\n");
    test_field();
    test_aes();
    test_gcm();
    std::printf("\n%s, ошибок: %d\n", g_failed == 0 ? "проверки пройдены" : "есть ошибки", g_failed);
    return g_failed == 0 ? 0 : 1;
}
