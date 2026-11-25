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
    std::printf("\n== GF(2^8), p(x)=0x11B, S-box = a^254 на лету ==\n");
    const Gf8 field;

    const uint8_t sum = Gf8::add(0x57, 0x83);
    check_hex("add(0x57, 0x83)", &sum, 1, "d4");

    const uint8_t product = field.multiply(0x57, 0x83);
    check_hex("0x57 * 0x83 = 0xC1", &product, 1, "c1");

    const uint8_t doubled = field.xtime(0x80);
    check_hex("xtime(0x80) = 0x1B", &doubled, 1, "1b");

    const uint8_t zero_inv = field.inverse(0x00);
    check_hex("inverse(0x00) = 0x00", &zero_inv, 1, "00");

    int mul_fail = 0;
    int inv_fail = 0;
    int sbox_fail = 0;
    for (int a = 0; a < 256; ++a) {
        const uint8_t ua = static_cast<uint8_t>(a);
        if (field.multiply(ua, field.inverse(ua)) != (a == 0 ? 0 : 1)) {
            ++inv_fail;
        }
        if (field.inv_sub_byte(field.sub_byte(ua)) != ua) {
            ++sbox_fail;
        }
        for (int b = 0; b < 256; ++b) {
            if (field.multiply(ua, static_cast<uint8_t>(b)) != schoolbook(ua, static_cast<uint8_t>(b), Gf8::kPoly)) {
                ++mul_fail;
            }
        }
    }
    check("shift-and-XOR совпадает с пошаговой редукцией на 65536 парах", mul_fail == 0);
    check("0^(-1)=0 и a*a^(-1)=1 для остальных", inv_fail == 0);
    check("обратный SubBytes восстанавливает все 256 байт", sbox_fail == 0);

    uint8_t sbox[256];
    field.fill_sbox(sbox);
    check_hex("S-box AES, первые 16 байт", sbox, 16, "637c777bf26b6fc53001672bfed7ab76");
    check_hex("S(0x53), посчитан на лету", &sbox[0x53], 1, "ed");

    const uint8_t live = field.sub_byte(0x53);
    check("байт, посчитанный на лету, совпадает с ячейкой таблицы", live == sbox[0x53]);

    const uint8_t inv0 = field.inv_sub_byte(0x00);
    check_hex("InvS(0x00) = 0x52", &inv0, 1, "52");
}

void test_aes() {
    std::printf("\n== AES-128, p(x)=0x11B ==\n");
    const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    const uint8_t plain[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t cipher[16];
    uint8_t back[16];
    Aes128 aes(key);
    aes.encrypt_block(plain, cipher);
    aes.decrypt_block(cipher, back);
    check_hex("FIPS-197 C.1", cipher, 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
    check("FIPS-197 C.1 расшифрование", std::memcmp(back, plain, 16) == 0);

    const uint8_t key_b[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                               0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
    const uint8_t plain_b[16] = {0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
                                 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34};
    Aes128 aes_b(key_b);
    aes_b.encrypt_block(plain_b, cipher);
    aes_b.decrypt_block(cipher, back);
    check_hex("FIPS-197 приложение B", cipher, 16, "3925841d02dc09fbdc118597196a0b32");
    check("FIPS-197 приложение B расшифрование", std::memcmp(back, plain_b, 16) == 0);
}

void test_gcm() {
    std::printf("\n== AES-GCM, f(x)=x^128+x^7+x^2+x+1 ==\n");
    const uint8_t zero_key[16] = {};
    const uint8_t zero_iv[12] = {};
    const uint8_t zero_block[16] = {};
    uint8_t cipher[16];
    uint8_t tag[16];

    AesGcm empty(zero_key);
    empty.encrypt(zero_iv, nullptr, 0, nullptr, 0, nullptr, tag);
    check_hex("NIST GCM, пустой текст, тег", tag, 16, "58e2fccefa7e3061367f1d57a4e7455a");

    AesGcm zeros(zero_key);
    zeros.encrypt(zero_iv, nullptr, 0, zero_block, 16, cipher, tag);
    check_hex("NIST GCM, нулевой блок, шифртекст", cipher, 16, "0388dace60b6a392f328c2b971b2fe78");
    check_hex("NIST GCM, нулевой блок, тег", tag, 16, "ab6e47d42cec13bdf53a67b21257bddf");

    const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    const uint8_t iv[12] = {0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88};
    const uint8_t aad[7] = {0xFE, 0xED, 0xFA, 0xCE, 0x01, 0x02, 0x03};
    const uint8_t plain[20] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                               0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67};
    uint8_t ct[20];
    uint8_t restored[20];
    AesGcm gcm(key);
    gcm.encrypt(iv, aad, sizeof(aad), plain, sizeof(plain), ct, tag);
    const bool accepted = gcm.decrypt(iv, aad, sizeof(aad), ct, sizeof(ct), tag, restored);
    check("неполный блок: тег принят", accepted);
    check("неполный блок: текст восстановлен", std::memcmp(restored, plain, sizeof(plain)) == 0);

    uint8_t bad[16];
    std::memcpy(bad, tag, 16);
    bad[0] ^= 0x01;
    std::memset(restored, 0xA5, sizeof(restored));
    check("испорченный тег отвергнут", !gcm.decrypt(iv, aad, sizeof(aad), ct, sizeof(ct), bad, restored));
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
    std::printf("ЛР1, вариант 1: AES-128-GCM, p(x)=0x11B, S-box через a^254 на лету\n");
    test_field();
    test_aes();
    test_gcm();
    std::printf("\n%s, ошибок: %d\n", g_failed == 0 ? "проверки пройдены" : "есть ошибки", g_failed);
    return g_failed == 0 ? 0 : 1;
}
