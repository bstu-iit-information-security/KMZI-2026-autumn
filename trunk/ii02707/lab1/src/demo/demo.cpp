#include <demo.hpp>

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <vector>

namespace crypto {
namespace demo {

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    std::cout << "  " << std::left << std::setw(16) << label << " : ";
    std::cout << std::right << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    std::cout << std::dec << std::setfill(' ') << "\n";
}

static void print_sep(char c = '-', int n = 68) {
    for (int i = 0; i < n; ++i) std::cout.put(c);
    std::cout.put('\n');
}

static void print_banner(const char* title) {
    print_sep('=');
    std::cout << "  " << title << "\n";
    print_sep('=');
}

int run_demo() {
    print_banner("ЛАБОРАТОРНАЯ РАБОТА №1. ВАРИАНТ 4");
    std::cout << "  Алгоритм          : СТБ 34.101.31 (Belt)\n";
    std::cout << "  Неприводимый p(x) : x^8 + x^5 + x^3 + x + 1  (0x12B)\n";
    std::cout << "  Полином GHASH     : x^128 + x^7 + x^2 + x + 1\n";
    std::cout << "  Constant-time     : безопасные ROTL/ROTR\n";
    print_sep();
    std::cout << "\n";

    std::cout << "[1] Инициализация калькулятора Галуа GF(2^8), p(x) = 0x12B\n";
    GF256 gf(0x12B);
    std::cout << std::hex << std::uppercase << std::setfill('0')
              << "    S-box[0x00] = 0x" << std::setw(2) << gf.sbox(0x00)
              << "   S-box[0x53] = 0x" << std::setw(2) << gf.sbox(0x53)
              << "   S-box[0xFF] = 0x" << std::setw(2) << gf.sbox(0xFF)
              << std::dec << std::setfill(' ') << "\n\n";

    std::cout << "[2] Установка 256-битного ключа Belt и развёртка подключей\n";
    const uint8_t key[Belt::kKeyBytes] = {
        0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6,
        0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
        0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37,
        0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6,
    };
    Belt belt(gf);
    print_hex("K", key, sizeof(key));
    std::cout << "\n";

    std::cout << "[3] Инициализация AEAD-режима GCM\n";
    GCM gcm;
    gcm.init(belt, key, gf);
    std::cout << "    Вспомогательный ключ H = E_K(0^128) вычислен\n\n";

    const uint8_t nonce[GCM::kNonceBytes] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE,
        0xDB, 0xAD, 0xDE, 0xAD, 0xBE, 0xEF,
    };
    const uint8_t aad[] = {
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF
    };
    const uint8_t plaintext[] =
        "Belt-GCM test message from variant 4!";

    std::cout << "[4] Входные данные\n";
    print_hex("Nonce (96 бит)", nonce, sizeof(nonce));
    print_hex("AAD", aad, sizeof(aad));
    print_hex("Открытый текст", plaintext, sizeof(plaintext) - 1);
    std::cout << "    Длина PT         : " << (sizeof(plaintext) - 1)
              << " байт\n\n";

    std::cout << "[5] AEAD-шифрование (GCM)\n";

    std::vector<uint8_t> ciphertext(sizeof(plaintext) - 1);
    GCM::Tag tag{};
    gcm.encrypt(aad, sizeof(aad),
                plaintext, sizeof(plaintext) - 1,
                nonce,
                ciphertext.data(),
                tag);

    print_sep();
    std::cout << "  ВЫХОДНЫЕ ДАННЫЕ\n";
    print_sep();
    print_hex("Шифротекст (C)", ciphertext.data(), ciphertext.size());
    print_hex("Тег целостности", tag.data(), tag.size());
    print_sep();
    std::cout << "\n";

    std::cout << "[6] AEAD-расшифрование с корректным тегом\n";
    std::vector<uint8_t> recovered(ciphertext.size());
    const bool ok = gcm.decrypt(aad, sizeof(aad),
                                ciphertext.data(), ciphertext.size(),
                                nonce,
                                tag,
                                recovered.data());

    if (ok) {
        std::cout << "    Верификация тега : ПРОЙДЕНА\n";
        print_hex("Восстановленный PT", recovered.data(), recovered.size());
        const bool equal = std::memcmp(recovered.data(),
                                       plaintext, ciphertext.size()) == 0;
        std::cout << "    Совпадение с PT  : " << (equal ? "ДА" : "НЕТ") << "\n\n";
    } else {
        std::cout << "    Верификация тега : ОШИБКА (не должна происходить)\n\n";
    }

    std::cout << "[7] Демонстрация защиты от подделки\n";
    GCM::Tag forged = tag;
    forged[0] ^= 0x01;
    std::cout << "    Подменённый тег  : ";
    std::cout << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < forged.size(); ++i) {
        std::cout << std::setw(2) << static_cast<unsigned>(forged[i]);
    }
    std::cout << std::dec << std::setfill(' ') << "\n";

    std::vector<uint8_t> dummy(ciphertext.size());
    const bool forged_ok = gcm.decrypt(aad, sizeof(aad),
                                       ciphertext.data(), ciphertext.size(),
                                       nonce,
                                       forged,
                                       dummy.data());
    std::cout << "    Результат проверки : "
              << (forged_ok ? "ОШИБКА — подделка принята"
                            : "OK — подделка отклонена") << "\n";
    std::cout << "    Открытый текст не выдан: "
              << (forged_ok ? "НЕТ" : "ДА") << "\n\n";

    std::cout << "[8] Constant-time сравнение тегов (XOR-аккумулятор)\n";
    std::cout << "    ct_compare(tag, tag)          = "
              << (GCM::ct_compare(tag, tag) ? "true (совпали)" : "false") << "\n";
    std::cout << "    ct_compare(tag, forged_tag)   = "
              << (GCM::ct_compare(tag, forged) ? "true" : "false (отличаются)") << "\n";
    std::cout << "    Early-exit отсутствует: проверяются все "
              << GCM::kTagBytes << " байт\n\n";

    print_sep('=');
    std::cout << "  ДЕМОНСТРАЦИЯ ЗАВЕРШЕНА\n";
    print_sep('=');
    std::cout << "\n";

    return ok && !forged_ok ? 0 : 1;
}

}
}