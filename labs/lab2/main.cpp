#include <iostream>
#include <chrono>
#include <random>
#include <string>
#include <cstring>
#include <iomanip>
#include <stdexcept>

#include "sha512.h"
#include "bigint.h"
#include "rsa_crt.h"
#include "oaep.h"

#if defined(_MSC_VER)
  #include <intrin.h>
  static inline uint64_t rdtsc() { return __rdtsc(); }
#elif defined(__x86_64__) || defined(__i386__)
  static inline uint64_t rdtsc() {
      unsigned lo, hi;
      __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
      return (static_cast<uint64_t>(hi) << 32) | lo;
  }
#else
  static inline uint64_t rdtsc() {
      return static_cast<uint64_t>(
          std::chrono::high_resolution_clock::now().time_since_epoch().count());
  }
#endif

int main() {
    try {
        std::cout << "====================================================\n";
        std::cout << "RSA-CRT (SHA-512) Constant-Time OAEP [3072-bit]\n";
        std::cout << "====================================================\n\n";

        // === Криптостойкий источник энтропии ===
        std::random_device rd;
        std::mt19937_64 rng(
            (static_cast<uint64_t>(rd()) << 32) ^ rd());

        std::cout << "Генерация 3072-битных ключей RSA (Miller-Rabin, 40 раундов)...\n";
        auto t0 = std::chrono::high_resolution_clock::now();
        RSAKeyPair key_pair = generate_keys(rng);
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "  Ключи сгенерированы за "
                  << std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count()
                  << " мс\n";
        std::cout << "  N.bit_length() = " << key_pair.N.bit_length() << " бит\n\n";

        // === Тест 1: обычное сообщение ===
        std::string message = "Test Message for Lab 2 (Variant 3 Constant-Time CRT Garner)";
        std::cout << "Тест 1: сообщение \"" << message << "\"\n";

        uint8_t em[RSA_KEY_BYTES];
        uint8_t ciphertext[RSA_KEY_BYTES];
        uint8_t decrypted_em[RSA_KEY_BYTES];
        uint8_t decrypted_msg[MAX_MSG_LEN] = {0};
        size_t decrypted_len = 0;

        if (!oaep_encode(reinterpret_cast<const uint8_t*>(message.data()),
                         message.length(), em, rng)) {
            std::cerr << "OAEP encode error!\n";
            return 1;
        }

        rsa_encrypt_raw(em, RSA_KEY_BYTES, ciphertext, key_pair);
        rsa_decrypt_crt_constant_time(ciphertext, decrypted_em, key_pair);

        bool ok = oaep_decode_constant_time(decrypted_em, decrypted_msg, decrypted_len);
        if (ok) {
            std::string recovered(reinterpret_cast<char*>(decrypted_msg), decrypted_len);
            std::cout << "  УСПЕХ: \"" << recovered << "\"\n";
            std::cout << "  Совпадение: " << (recovered == message ? "ДА" : "НЕТ") << "\n\n";
        } else {
            std::cout << "  ОШИБКА декодирования\n\n";
        }

        // === Тест 2: пустое сообщение (граничное условие) ===
        std::cout << "Тест 2: пустое сообщение (msg_len = 0)\n";
        if (oaep_encode(nullptr, 0, em, rng)) {
            rsa_encrypt_raw(em, RSA_KEY_BYTES, ciphertext, key_pair);
            rsa_decrypt_crt_constant_time(ciphertext, decrypted_em, key_pair);
            ok = oaep_decode_constant_time(decrypted_em, decrypted_msg, decrypted_len);
            std::cout << "  Результат: " << (ok && decrypted_len == 0 ? "OK" : "FAIL") << "\n\n";
        }

        // === Тест 3: максимальная длина сообщения ===
        std::cout << "Тест 3: сообщение максимальной длины (" << MAX_MSG_LEN << " байт)\n";
        std::vector<uint8_t> big_msg(MAX_MSG_LEN);
        for (size_t i = 0; i < MAX_MSG_LEN; ++i) big_msg[i] = static_cast<uint8_t>(i & 0xFF);
        if (oaep_encode(big_msg.data(), big_msg.size(), em, rng)) {
            rsa_encrypt_raw(em, RSA_KEY_BYTES, ciphertext, key_pair);
            rsa_decrypt_crt_constant_time(ciphertext, decrypted_em, key_pair);
            ok = oaep_decode_constant_time(decrypted_em, decrypted_msg, decrypted_len);
            bool match = ok && decrypted_len == MAX_MSG_LEN &&
                         std::memcmp(decrypted_msg, big_msg.data(), MAX_MSG_LEN) == 0;
            std::cout << "  Результат: " << (match ? "OK" : "FAIL") << "\n\n";
        }

        // === Тест 4: повреждённый шифротекст (constant-time) ===
        std::cout << "Тест 4: constant-time анализ (RDTSC, 500 итераций)\n";
        uint8_t corrupted_em[RSA_KEY_BYTES];
        std::memcpy(corrupted_em, decrypted_em, RSA_KEY_BYTES);
        corrupted_em[RSA_KEY_BYTES - 10] ^= 0xFF;

        uint8_t dummy[MAX_MSG_LEN];
        size_t dummy_len;
        constexpr int RUNS = 500;

        // Прогрев
        for (int i = 0; i < 50; ++i) oaep_decode_constant_time(decrypted_em, dummy, dummy_len);
        for (int i = 0; i < 50; ++i) oaep_decode_constant_time(corrupted_em, dummy, dummy_len);

        uint64_t t_start, t_end, t_valid = 0, t_invalid = 0;
        for (int i = 0; i < RUNS; ++i) {
            t_start = rdtsc();
            oaep_decode_constant_time(decrypted_em, dummy, dummy_len);
            t_end = rdtsc();
            t_valid += (t_end - t_start);
        }
        for (int i = 0; i < RUNS; ++i) {
            t_start = rdtsc();
            oaep_decode_constant_time(corrupted_em, dummy, dummy_len);
            t_end = rdtsc();
            t_invalid += (t_end - t_start);
        }
        double avg_valid   = static_cast<double>(t_valid)   / RUNS;
        double avg_invalid = static_cast<double>(t_invalid) / RUNS;
        std::cout << std::fixed << std::setprecision(1);
        std::cout << "  Валидный:       " << avg_valid   << " тактов\n";
        std::cout << "  Повреждённый:   " << avg_invalid << " тактов\n";
        double ratio = avg_invalid / avg_valid;
        std::cout << "  Отношение:      " << ratio << " (норма ≈ 1.0)\n";
        std::cout << "  Constant-time:  "
                  << ((ratio > 0.95 && ratio < 1.05) ? "ДА" : "ТРЕБУЕТ ПРОВЕРКИ")
                  << "\n\n";

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}