#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// Модуль 3. OAEP (PKCS#1 v2.2 / RFC 8017) на SHA-256.
// Буферы — статические массивы фиксированной длины k = 384 (модуль 3072 бит).
// Боевая деинкапсуляция собирает ошибки в аккумулятор и не делает early exit.
class Oaep {
public:
    static constexpr int kHashLen = 32;
    static constexpr int kModulusBytes = 384;
    static constexpr int kMaxMessage = kModulusBytes - 2 * kHashLen - 2;  // 318
    static constexpr int kDbLen = kModulusBytes - kHashLen - 1;            // 351

    static_assert(kMaxMessage == 318, "max OAEP message for 3072-bit SHA-256");
    static_assert(1 + kHashLen + kDbLen == kModulusBytes, "EM layout");

    static bool encode(const uint8_t* message, std::size_t message_len,
                       const uint8_t* label, std::size_t label_len,
                       std::array<uint8_t, kModulusBytes>& em);

    static bool encode_with_seed(const uint8_t* message, std::size_t message_len,
                                 const uint8_t* label, std::size_t label_len,
                                 const uint8_t seed[kHashLen],
                                 std::array<uint8_t, kModulusBytes>& em);

    // Constant-time: все проверки и оба вызова MGF1 выполняются всегда.
    static bool decode(const std::array<uint8_t, kModulusBytes>& em,
                       const uint8_t* label, std::size_t label_len,
                       std::array<uint8_t, kMaxMessage>& message,
                       std::size_t& message_len);

    // Намеренно уязвимая распаковка: ранний выход. Только для сравнения времени.
    static bool decode_variable_time(const std::array<uint8_t, kModulusBytes>& em,
                                     const uint8_t* label, std::size_t label_len,
                                     std::array<uint8_t, kMaxMessage>& message,
                                     std::size_t& message_len);
};
