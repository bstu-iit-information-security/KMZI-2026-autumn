#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint>

const size_t RSA_KEY_BITS = 2048;
const size_t RSA_KEY_BYTES = RSA_KEY_BITS / 8;
const size_t HASH_LEN = 32;
const size_t MAX_MSG_LEN = RSA_KEY_BYTES - 2 * HASH_LEN - 2;

namespace SHA256_Standalone {
    const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90bbefffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    void transform(uint32_t* state, const uint8_t* data) {
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        uint32_t w[64];

        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
                ((uint32_t)data[i * 4 + 2] << 8) | ((uint32_t)data[i * 4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    void hash(const uint8_t* data, size_t len, uint8_t* digest) {
        uint32_t state[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        uint64_t bit_len = len * 8;
        std::vector<uint8_t> buffer(data, data + len);
        buffer.push_back(0x80);

        while (buffer.size() % 64 != 56) {
            buffer.push_back(0x00);
        }

        for (int i = 7; i >= 0; i--) {
            buffer.push_back((uint8_t)(bit_len >> (i * 8)));
        }

        for (size_t i = 0; i < buffer.size(); i += 64) {
            transform(state, &buffer[i]);
        }

        for (int i = 0; i < 8; i++) {
            digest[i * 4] = (state[i] >> 24) & 0xFF;
            digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
            digest[i * 4 + 3] = state[i] & 0xFF;
        }
    }
}

void MGF1(const uint8_t* seed, size_t seedLen, uint8_t* mask, size_t maskLen) {
    uint8_t counter[4];
    uint8_t hashBuf[HASH_LEN];
    size_t generated = 0;
    uint32_t counter_val = 0;

    std::vector<uint8_t> temp(seedLen + 4);
    std::memcpy(temp.data(), seed, seedLen);

    while (generated < maskLen) {
        counter[0] = (counter_val >> 24) & 0xFF;
        counter[1] = (counter_val >> 16) & 0xFF;
        counter[2] = (counter_val >> 8) & 0xFF;
        counter[3] = counter_val & 0xFF;

        std::memcpy(temp.data() + seedLen, counter, 4);
        SHA256_Standalone::hash(temp.data(), temp.size(), hashBuf);

        size_t chunk = (maskLen - generated) < HASH_LEN ? (maskLen - generated) : HASH_LEN;
        std::memcpy(mask + generated, hashBuf, chunk);

        generated += chunk;
        counter_val++;
    }
}

uint8_t CT_IsNonZero(uint8_t val) {
    uint16_t v = val;
    return (uint8_t)((((v | (256 - v)) >> 8) & 1) * 0xFF);
}

uint8_t CT_Select(uint8_t a, uint8_t b, uint8_t mask) {
    return (a & ~mask) | (b & mask);
}

bool OAEP_Encode(const uint8_t* msg, size_t msgLen, const uint8_t* seed,
    uint8_t* em, size_t emLen) {
    if (msgLen > MAX_MSG_LEN || emLen != RSA_KEY_BYTES) return false;

    uint8_t lHash[HASH_LEN];
    SHA256_Standalone::hash((const uint8_t*)"", 0, lHash);

    size_t psLen = emLen - msgLen - 2 * HASH_LEN - 2;
    uint8_t db[RSA_KEY_BYTES - HASH_LEN - 1];

    std::memcpy(db, lHash, HASH_LEN);
    std::memset(db + HASH_LEN, 0x00, psLen);
    db[HASH_LEN + psLen] = 0x01;
    std::memcpy(db + HASH_LEN + psLen + 1, msg, msgLen);

    size_t dbMaskLen = emLen - HASH_LEN - 1;
    std::vector<uint8_t> dbMask(dbMaskLen);
    MGF1(seed, HASH_LEN, dbMask.data(), dbMaskLen);

    for (size_t i = 0; i < dbMaskLen; ++i) {
        db[i] ^= dbMask[i];
    }

    uint8_t seedMask[HASH_LEN];
    MGF1(db, dbMaskLen, seedMask, HASH_LEN);

    uint8_t maskedSeed[HASH_LEN];
    for (size_t i = 0; i < HASH_LEN; ++i) {
        maskedSeed[i] = seed[i] ^ seedMask[i];
    }

    em[0] = 0x00;
    std::memcpy(em + 1, maskedSeed, HASH_LEN);
    std::memcpy(em + 1 + HASH_LEN, db, dbMaskLen);

    return true;
}

bool OAEP_Decode(const uint8_t* em, size_t emLen, uint8_t* msg, size_t& msgLen) {
    if (emLen != RSA_KEY_BYTES) return false;

    uint8_t lHash[HASH_LEN];
    SHA256_Standalone::hash((const uint8_t*)"", 0, lHash);

    uint8_t errorMask = 0x00;
    errorMask |= CT_IsNonZero(em[0]);

    const uint8_t* maskedSeed = em + 1;
    const uint8_t* maskedDB = em + 1 + HASH_LEN;
    size_t dbLen = emLen - HASH_LEN - 1;

    uint8_t seedMask[HASH_LEN];
    MGF1(maskedDB, dbLen, seedMask, HASH_LEN);
    uint8_t seed[HASH_LEN];
    for (size_t i = 0; i < HASH_LEN; ++i) {
        seed[i] = maskedSeed[i] ^ seedMask[i];
    }

    uint8_t dbMask[RSA_KEY_BYTES - HASH_LEN - 1];
    MGF1(seed, HASH_LEN, dbMask, dbLen);

    std::vector<uint8_t> db(dbLen);
    for (size_t i = 0; i < dbLen; ++i) {
        db[i] = maskedDB[i] ^ dbMask[i];
    }

    for (size_t i = 0; i < HASH_LEN; ++i) {
        errorMask |= (db[i] ^ lHash[i]);
    }
    errorMask = CT_IsNonZero(errorMask);

    size_t delimIndex = 0;
    uint8_t found01 = 0x00;

    for (size_t i = HASH_LEN; i < dbLen; ++i) {
        uint8_t is01 = (db[i] == 0x01) ? 0xFF : 0x00;
        uint8_t takeThis = is01 & ~found01;
        delimIndex = (size_t)CT_Select((uint8_t)delimIndex, (uint8_t)i, takeThis);
        found01 |= takeThis;
    }

    errorMask |= ~found01;

    msgLen = dbLen - (delimIndex + 1);
    for (size_t i = 0; i < MAX_MSG_LEN; ++i) {
        size_t srcIdx = delimIndex + 1 + i;
        uint8_t b = (srcIdx < dbLen) ? db[srcIdx] : 0;
        msg[i] = CT_Select(b, 0, errorMask);
    }

    return (errorMask == 0x00);
}

int main() {
    setlocale(LC_ALL, "Russian");

    std::cout << "=== RSA-OAEP модуль с защитой по времени выполнения (Вариант 1) ===" << std::endl;

    const char* originalText = "Привет, системы информационной безопасности!";
    size_t origLen = std::strlen(originalText);

    std::cout << "Исходное сообщение: " << originalText << " (Длина: " << origLen << ")" << std::endl;

    uint8_t em[RSA_KEY_BYTES];
    uint8_t seed[HASH_LEN] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    if (!OAEP_Encode((const uint8_t*)originalText, origLen, seed, em, RSA_KEY_BYTES)) {
        std::cerr << "Ошибка упаковки OAEP!" << std::endl;
        return 1;
    }
    std::cout << "Упаковка OAEP выполнена успешно. Размер EM: " << RSA_KEY_BYTES << " байт." << std::endl;

    uint8_t decodedMsg[MAX_MSG_LEN];
    size_t decodedLen = 0;

    bool success = OAEP_Decode(em, RSA_KEY_BYTES, decodedMsg, decodedLen);

    if (success) {
        std::cout << "Распаковка OAEP выполнена успешно!" << std::endl;
        std::cout << "Декодированное сообщение: ";
        for (size_t i = 0; i < decodedLen; ++i) {
            std::cout << (char)decodedMsg[i];
        }
        std::cout << std::endl;
    }
    else {
        std::cout << "Ошибка распаковки OAEP при проверке целостности." << std::endl;
    }

    std::cout << "\n--- Тестирование поврежденного шифротекста (защита Блейхенбахера) ---" << std::endl;
    em[5] ^= 0xFF;

    bool successCorrupted = OAEP_Decode(em, RSA_KEY_BYTES, decodedMsg, decodedLen);
    if (!successCorrupted) {
        std::cout << "Поврежденный шифротекст корректно отклонен в режиме Constant-Time (без раннего выхода)." << std::endl;
    }

    return 0;
}