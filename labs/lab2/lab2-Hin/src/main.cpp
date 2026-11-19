#include "oaep.hpp"
#include "rsa_core.hpp"
#include "rsa_math.hpp"
#include "sha256.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

int g_failed = 0;

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

void check_u64(const char* name, const Bn& value, uint64_t expected) {
    check(name, value.fits_u64() && value.as_u64() == expected && value.is_zero() == (expected == 0));
}

bool same_bytes(const uint8_t* data, std::size_t n, const char* text) {
    return n == std::strlen(text) && std::memcmp(data, text, n) == 0;
}

bool all_zero(const uint8_t* data, std::size_t n) {
    uint8_t acc = 0;
    for (std::size_t i = 0; i < n; ++i) {
        acc |= data[i];
    }
    return acc == 0;
}

void reference_mod_exp(Bn& result, const Bn& base, const Bn& exponent, const Bn& modulus) {
    result.set_u64(1);
    Bn reduced;
    Bn::mod(reduced, base, modulus);
    for (int i = exponent.bit_length() - 1; i >= 0; --i) {
        Bn square;
        Bn::mul(square, result, result);
        Bn::mod(result, square, modulus);
        if (exponent.bit(i)) {
            Bn product;
            Bn::mul(product, result, reduced);
            Bn::mod(result, product, modulus);
        }
    }
}

void test_sha256() {
    std::printf("\n== SHA-256 ==\n");
    uint8_t out[32];
    Sha256::hash(nullptr, 0, out);
    check("пустая строка", is_hex(out, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    const uint8_t abc[] = {'a', 'b', 'c'};
    Sha256::hash(abc, 3, out);
    check("abc", is_hex(out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

void test_math() {
    std::printf("\n== Арифметика ==\n");
    Bn left;
    Bn right;
    Bn quotient;
    Bn remainder;
    left.set_u64(1000);
    right.set_u64(7);
    Bn::divmod(quotient, remainder, left, right);
    check_u64("1000 / 7", quotient, 142);
    check_u64("1000 % 7", remainder, 6);

    Bn base;
    Bn exponent;
    Bn modulus;
    Bn out;
    Bn reference;
    base.set_u64(2);
    exponent.set_u64(10);
    modulus.set_u64(1000);
    check("2^10 mod 1000", RsaMath::mod_exp(out, base, exponent, modulus));
    check_u64("2^10 mod 1000 = 24", out, 24);

    base.set_u64(42);
    exponent.set_u64(7);
    modulus.set_u64(187);
    check("42^7 mod 187", RsaMath::mod_exp(out, base, exponent, modulus));
    check_u64("42^7 mod 187 = 15", out, 15);
    reference_mod_exp(reference, base, exponent, modulus);
    check("Монтгомери совпал с делением", out.cmp(reference) == 0);

    Bn value;
    value.set_u64(7);
    modulus.set_u64(80);
    check("обратный к 7 по модулю 80", RsaMath::mod_inverse(out, value, modulus));
    check_u64("7^(-1) mod 80 = 23", out, 23);
}

void test_small_rsa() {
    std::printf("\n== RSA-CRT: p=11, q=17, e=7 ==\n");
    RsaKey key;
    key.p.set_u64(11);
    key.q.set_u64(17);
    key.e.set_u64(7);
    Bn one;
    one.set_u64(1);
    Bn p1;
    Bn q1;
    Bn::sub(p1, key.p, one);
    Bn::sub(q1, key.q, one);
    Bn gcd;
    Bn ignore_x;
    Bn ignore_y;
    RsaMath::extended_gcd(gcd, ignore_x, ignore_y, p1, q1);
    Bn quotient;
    Bn remainder;
    Bn::divmod(quotient, remainder, p1, gcd);
    Bn lambda;
    Bn::mul(lambda, quotient, q1);
    check("d = e^(-1) mod lambda", RsaMath::mod_inverse(key.d, key.e, lambda));
    Bn::mul(key.n, key.p, key.q);
    Bn::mod(key.dp, key.d, p1);
    Bn::mod(key.dq, key.d, q1);
    check("qinv", RsaMath::mod_inverse(key.qinv, key.q, key.p));
    check_u64("n = 187", key.n, 187);
    check_u64("d = 23", key.d, 23);

    Bn message;
    Bn cipher;
    Bn back;
    message.set_u64(42);
    check("шифрование 42", RsaCore::encrypt(cipher, message, key.e, key.n));
    check_u64("c = 15", cipher, 15);
    check("расшифрование Гарнера", RsaCore::decrypt(back, cipher, key) && back.as_u64() == 42);

    message.set_u64(22);
    check("шифрование 22", RsaCore::encrypt(cipher, message, key.e, key.n));
    check("22 восстановлено", RsaCore::decrypt(back, cipher, key) && back.as_u64() == 22);
}

void test_oaep() {
    std::printf("\n== OAEP-SHA256, k=256, разбор без раннего выхода ==\n");
    const uint8_t message[] = {'K', 'M', 'Z', 'I', '-', '1'};
    uint8_t seed[Oaep::kHashLen];
    for (int i = 0; i < Oaep::kHashLen; ++i) {
        seed[i] = static_cast<uint8_t>(i + 1);
    }
    uint8_t em[Oaep::kModulusBytes];
    check("сборка", Oaep::encode_with_seed(message, sizeof(message), nullptr, 0, seed, em));
    check("ведущий байт 0x00", em[0] == 0x00);

    uint8_t back[Oaep::kMaxMessage];
    std::memset(back, 0xA5, sizeof(back));
    std::size_t back_len = 99;
    check("разбор", Oaep::decode(em, nullptr, 0, back, back_len));
    check("сообщение KMZI-1", back_len == sizeof(message) && std::memcmp(back, message, sizeof(message)) == 0);

    uint8_t bad_first[Oaep::kModulusBytes];
    std::memcpy(bad_first, em, sizeof(em));
    bad_first[0] ^= 0x01;
    std::memset(back, 0xA5, sizeof(back));
    back_len = 99;
    check("битый первый байт отвергнут", !Oaep::decode(bad_first, nullptr, 0, back, back_len));
    check("при ошибке длина 0", back_len == 0);
    check("при ошибке сообщение занулено", all_zero(back, sizeof(back)));

    uint8_t bad_tail[Oaep::kModulusBytes];
    std::memcpy(bad_tail, em, sizeof(em));
    bad_tail[Oaep::kModulusBytes - 1] ^= 0x5A;
    check("битый последний байт отвергнут", !Oaep::decode(bad_tail, nullptr, 0, back, back_len) && back_len == 0);

    check("пустое сообщение", Oaep::encode_with_seed(nullptr, 0, nullptr, 0, seed, em));
    check("пустое разбирается", Oaep::decode(em, nullptr, 0, back, back_len) && back_len == 0);

    uint8_t full[Oaep::kMaxMessage];
    for (int i = 0; i < Oaep::kMaxMessage; ++i) {
        full[i] = static_cast<uint8_t>(i);
    }
    check("максимальная длина 190", Oaep::kMaxMessage == 190);
    check("максимальное сообщение", Oaep::encode_with_seed(full, sizeof(full), nullptr, 0, seed, em));
    check("максимальное разбирается",
          Oaep::decode(em, nullptr, 0, back, back_len) && back_len == sizeof(full) &&
              std::memcmp(back, full, sizeof(full)) == 0);
    check("слишком длинное отвергнуто", !Oaep::encode_with_seed(full, sizeof(full) + 1, nullptr, 0, seed, em));

    const uint8_t marked[] = {0x00, 0x01, 0x02, 0xFF};
    const uint8_t label[] = {'l', 'a', 'b'};
    check("метка и байты 0x00/0x01 внутри текста",
          Oaep::encode_with_seed(marked, sizeof(marked), label, sizeof(label), seed, em));
    check("верная метка",
          Oaep::decode(em, label, sizeof(label), back, back_len) && back_len == sizeof(marked) &&
              std::memcmp(back, marked, sizeof(marked)) == 0);
    check("чужая метка", !Oaep::decode(em, nullptr, 0, back, back_len) && back_len == 0);
}

void test_key() {
    std::printf("\n== Ключ RSA-%d ==\n", RsaMath::kModulusBits);
    RsaKey key;
    check("генерация", RsaMath::generate_key(key));
    check("длина модуля 2048 бит", key.n.bit_length() == RsaMath::kModulusBits);
    Bn product;
    Bn::mul(product, key.p, key.q);
    check("n = p * q", product.cmp(key.n) == 0);
    check("p и q по 1024 бита", key.p.bit_length() == RsaMath::kPrimeBits &&
                                    key.q.bit_length() == RsaMath::kPrimeBits);

    const uint8_t message[] = {'l', 'a', 'b', '2'};
    uint8_t em[Oaep::kModulusBytes];
    uint8_t seed[Oaep::kHashLen] = {};
    seed[0] = 1;
    check("OAEP", Oaep::encode_with_seed(message, sizeof(message), nullptr, 0, seed, em));
    Bn encoded;
    encoded.set_bytes_be(em, Oaep::kModulusBytes);
    Bn cipher;
    check("RSA-шифрование", RsaCore::encrypt(cipher, encoded, key.e, key.n));
    Bn decoded;
    check("RSA-CRT", RsaCore::decrypt(decoded, cipher, key));
    uint8_t raw[Oaep::kModulusBytes];
    decoded.to_bytes_be(raw, Oaep::kModulusBytes);
    uint8_t back[Oaep::kMaxMessage];
    std::size_t back_len = 0;
    check("сообщение восстановлено",
          Oaep::decode(raw, nullptr, 0, back, back_len) && same_bytes(back, back_len, "lab2"));
}

}

int main() {
    std::printf("ЛР2, вариант 1: RSA-2048, OAEP-SHA256, разбор без раннего выхода\n");
    test_sha256();
    test_math();
    test_small_rsa();
    test_oaep();
    test_key();
    std::printf("\n%s, ошибок: %d\n", g_failed == 0 ? "проверки пройдены" : "есть ошибки", g_failed);
    return g_failed == 0 ? 0 : 1;
}
