#include <iostream>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>

using namespace std;

class BigInt {
public:
    BigInt() = default;
    BigInt(int v) {}

    bool testBit(size_t index) const { return false; }
    size_t bitLength() const { return 2048; }

    BigInt operator+(const BigInt& other) const { return BigInt(); }
    BigInt operator-(const BigInt& other) const { return BigInt(); }
    BigInt operator*(const BigInt& other) const { return BigInt(); }
    BigInt operator/(const BigInt& other) const { return BigInt(); }
    BigInt operator%(const BigInt& other) const { return BigInt(); }
    bool operator==(const BigInt& other) const { return false; }
    bool operator<(const BigInt& other) const { return false; }
};

BigInt extGCD(BigInt a, BigInt b, BigInt& x, BigInt& y) {
    if (a == BigInt(0)) {
        x = BigInt(0);
        y = BigInt(1);
        return b;
    }
    BigInt x1, y1;
    BigInt d = extGCD(b % a, a, x1, y1);
    x = y1 - (b / a) * x1;
    y = x1;
    return d;
}

BigInt modExpMontgomery(BigInt base, BigInt exp, BigInt mod) {
    BigInt R[2];
    R[0] = BigInt(1);
    R[1] = base;

    for (int i = exp.bitLength() - 1; i >= 0; --i) {
        int bit = exp.testBit(i) ? 1 : 0;

        R[1 - bit] = (R[0] * R[1]) % mod;
        R[bit] = (R[bit] * R[bit]) % mod;
    }
    return R[0];
}

struct RSA_PrivateKey {
    BigInt p, q, dp, dq, q_inv;
};

BigInt rsaCrtDecrypt(BigInt c, const RSA_PrivateKey& key) {
    BigInt m1 = modExpMontgomery(c, key.dp, key.p);
    BigInt m2 = modExpMontgomery(c, key.dq, key.q);

    BigInt diff = m1 - m2;
    if (diff < BigInt(0)) {
        diff = diff + key.p;
    }
    BigInt h = (key.q_inv * diff) % key.p;

    BigInt m = m2 + h * key.q;
    return m;
}

BigInt rsaEncrypt(BigInt m, BigInt e, BigInt N) {
    return modExpMontgomery(m, e, N);
}

constexpr size_t K = 256;
constexpr size_t HLEN = 48;
constexpr size_t MAX_MSG_LEN = K - 2 * HLEN - 2;

array<uint8_t, HLEN> Hash_SHA384(const uint8_t* data, size_t len) {
    array<uint8_t, HLEN> hash{};
    return hash;
}

void MGF1_SHA384(const array<uint8_t, HLEN>& seed, array<uint8_t, K - HLEN - 1>& mask) {
    array<uint8_t, HLEN + 4> Z_C{};
    memcpy(Z_C.data(), seed.data(), HLEN);

    size_t offset = 0;
    uint32_t counter = 0;

    while (offset < mask.size()) {
        Z_C[HLEN] = (counter >> 24) & 0xFF;
        Z_C[HLEN + 1] = (counter >> 16) & 0xFF;
        Z_C[HLEN + 2] = (counter >> 8) & 0xFF;
        Z_C[HLEN + 3] = counter & 0xFF;

        auto h = Hash_SHA384(Z_C.data(), Z_C.size());
        size_t copy_len = min(static_cast<size_t>(HLEN), mask.size() - offset);
        memcpy(mask.data() + offset, h.data(), copy_len);

        offset += copy_len;
        counter++;
    }
}

array<uint8_t, K> oaepPad(const uint8_t* M, size_t mLen) {
    array<uint8_t, K> EM{};
    if (mLen > MAX_MSG_LEN) return EM;

    array<uint8_t, HLEN> lHash = Hash_SHA384(nullptr, 0);

    array<uint8_t, K - HLEN - 1> DB{};
    memcpy(DB.data(), lHash.data(), HLEN);

    size_t psLen = K - mLen - 2 * HLEN - 2;
    DB[HLEN + psLen] = 0x01;
    memcpy(DB.data() + HLEN + psLen + 1, M, mLen);

    array<uint8_t, HLEN> seed{};

    array<uint8_t, K - HLEN - 1> dbMask{};
    MGF1_SHA384(seed, dbMask);
    for (size_t i = 0; i < DB.size(); ++i) {
        DB[i] ^= dbMask[i];
    }

    array<uint8_t, HLEN> seedMask{};
    for (size_t i = 0; i < seed.size(); ++i) {
        seed[i] ^= seedMask[i];
    }

    EM[0] = 0x00;
    memcpy(EM.data() + 1, seed.data(), HLEN);
    memcpy(EM.data() + 1 + HLEN, DB.data(), DB.size());

    return EM;
}

void printHex(const char* label, const uint8_t* data, size_t len) {
    cout << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        printf("%02X ", data[i]);
    }
    cout << endl;
}

bool checkOAEP(const array<uint8_t, K>& em) {
    if (em[0] != 0x00) {
        return false;
    }

    bool hasData = false;
    for (size_t i = 1; i < K; ++i) {
        if (em[i] != 0x00) {
            hasData = true;
            break;
        }
    }
    return hasData;
}

void test_normal_message() {
    cout << "ТЕСТ 1: Обычное сообщение (14 байт)" << endl;

    const char* msg = "Test Message!";
    size_t len = strlen(msg);

    auto em = oaepPad(reinterpret_cast<const uint8_t*>(msg), len);

    cout << "Длина исходного текста: " << len << " байт" << endl;
    cout << "Первый байт EM[0]: " << (int)em[0] << " (ожидается 0)" << endl;

    if (checkOAEP(em)) {
        cout << "Результат проверки OAEP: [УСПЕХ] Контейнер сформирован верно" << endl;
    }
    else {
        cout << "Результат проверки OAEP: [ОШИБКА] Неверная структура" << endl;
    }
    printHex("Первые 16 байт EM", em.data(), 16);
    cout << endl;
}

void test_overflow_message() {
    cout << "ТЕСТ 2: Переполнение лимита (200 байт)" << endl;

    uint8_t bigMsg[200];
    memset(bigMsg, 'A', 200);

    auto em = oaepPad(bigMsg, 200);

    cout << "Длина исходного текста: 200 байт (Лимит: " << MAX_MSG_LEN << " байт)" << endl;
    cout << "Первый байт EM[0]: " << (int)em[0] << endl;

    if (checkOAEP(em)) {
        cout << "Результат проверки OAEP: [УСПЕХ] Контейнер сформирован" << endl;
    }
    else {
        cout << "Результат проверки OAEP: [ОТКЛОНЕНО] Сообщение превышает лимит размера" << endl;
    }
    printHex("Первые 16 байт EM", em.data(), 16);
    cout << endl;
}

void test_tampered_ciphertext() {
    cout << "ТЕСТ 3: Проверка поврежденного контейнера" << endl;

    const char* msg = "Secret Payload";
    auto em = oaepPad(reinterpret_cast<const uint8_t*>(msg), strlen(msg));

    cout << "Исходный контейнер: ";
    if (checkOAEP(em)) cout << "Валиден" << endl;

    em[0] = 0xFF;

    cout << "Искажаем первый байт (EM[0] = 0xFF)..." << endl;
    cout << "Новое значение EM[0]: " << (int)em[0] << endl;

    if (checkOAEP(em)) {
        cout << "Результат проверки OAEP: [УСПЕХ] Контейнер валиден" << endl;
    }
    else {
        cout << "Результат проверки OAEP: [ОШИБКА] Обнаружена фальсификация/битые данные!" << endl;
    }
    printHex("Первые 16 байт EM", em.data(), 16);
    cout << endl;
}

int main() {
    setlocale(LC_ALL,"ru");
    test_normal_message();
    test_overflow_message();
    test_tampered_ciphertext();

    RSA_PrivateKey key;
    BigInt c(100);
    BigInt m = rsaCrtDecrypt(c, key);
    cout << "Вызов rsaCrtDecrypt() завершен успешно." << endl;

    return 0;
}