#include <iostream>
#include <cstdint>
#include <cstring>
#include <string>
#include <algorithm>
#include <stdexcept>
#include <random>
#include <iomanip>
#include <limits>
#include <clocale>
#include <cstdlib>



class Galua {
private:
    uint8_t poly_;   // фиксированный неприводимый многочлен 0x12B
public:
    explicit Galua(uint32_t p_x) {
        poly_ = static_cast<uint8_t>(p_x & 0xFF);
    }

    uint8_t add(uint8_t a, uint8_t b) const { return a ^ b; }


    uint8_t xtime(uint8_t a) const {
        uint8_t mask = static_cast<uint8_t>(-(a >> 7));
        return static_cast<uint8_t>((a << 1) ^ (mask & poly_));
    }


    uint8_t mult(uint8_t a, uint8_t b) const {
        uint8_t result = 0;
        uint8_t x = a;
        for (int i = 0; i < 8; ++i) {
            uint8_t mask = static_cast<uint8_t>(-((b >> i) & 1));
            result ^= x & mask;
            x = xtime(x);
        }
        return result;
    }

    uint8_t inverse(uint8_t a) const {
        uint8_t a2 = mult(a, a);
        uint8_t a4 = mult(a2, a2);
        uint8_t a8 = mult(a4, a4);
        uint8_t a16 = mult(a8, a8);
        uint8_t a32 = mult(a16, a16);
        uint8_t a64 = mult(a32, a32);
        uint8_t a128 = mult(a64, a64);
        uint8_t r = mult(a2, a4);
        r = mult(r, a8);
        r = mult(r, a16);
        r = mult(r, a32);
        r = mult(r, a64);
        r = mult(r, a128);
        return r;
    }

    void generateInverseTable(uint8_t table[256]) const {
        for (int i = 0; i < 256; ++i) {
            table[i] = inverse(static_cast<uint8_t>(i));
        }
    }
};

class BelT {
private:
    static const uint8_t H_TABLE[256];
    uint32_t roundKeys[57];

    void keySchedule(const std::string& keyStr);

    static uint32_t loadBE32(const uint8_t* p) {
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
            | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
    }
    static void storeBE32(uint8_t* p, uint32_t v) {
        p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16);
        p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
    }

    void cryptBlock(const uint8_t in[16], uint8_t out[16]) const;

public:
    BelT() { std::memset(roundKeys, 0, sizeof(roundKeys)); }


    uint32_t rotl(uint32_t x, int r) const {
        return (x << r) | (x >> (32 - r));
    }


    uint32_t G(uint32_t x, int r) const {
        uint8_t u0 = H_TABLE[(x >> 24) & 0xFF];
        uint8_t u1 = H_TABLE[(x >> 16) & 0xFF];
        uint8_t u2 = H_TABLE[(x >> 8) & 0xFF];
        uint8_t u3 = H_TABLE[(x) & 0xFF];
        uint32_t v = (uint32_t(u0) << 24) | (uint32_t(u1) << 16)
            | (uint32_t(u2) << 8) | uint32_t(u3);
        return rotl(v, r);
    }

    void setKey(const std::string& key) { keySchedule(key); }

    void crypt(const uint8_t in[16], uint8_t out[16]) const {
        cryptBlock(in, out);
    }
};

const uint8_t BelT::H_TABLE[256] = {
    0xB1,0x94,0xBA,0xC8,0x0A,0x08,0xF5,0x3B,0x36,0x6D,0x00,0x8E,0x58,0x4A,0x5D,0xE4,
    0x85,0x04,0xFA,0x9D,0x1B,0xB6,0xC7,0xAC,0x25,0x2E,0x72,0xC2,0x02,0xFD,0xCE,0x0D,
    0x5B,0xE3,0xD6,0x12,0x17,0xB9,0x61,0x81,0xFE,0x67,0x86,0xAD,0x71,0x6B,0x89,0x0B,
    0x5C,0xB0,0xC0,0xFF,0x33,0xC3,0x56,0xB8,0x35,0xC4,0x05,0xAE,0xD8,0xE0,0x7F,0x99,
    0xE1,0x2B,0xDC,0x1A,0xE2,0x82,0x57,0xEC,0x70,0x3F,0xCC,0xF0,0x95,0xEE,0x8D,0xF1,
    0xC1,0xAB,0x76,0x38,0x9F,0xE6,0x78,0xCA,0xF7,0xC6,0xF8,0x60,0xD5,0xBB,0x9C,0x4F,
    0xF3,0x3C,0x65,0x7B,0x63,0x7C,0x30,0x6A,0xDD,0x4E,0xA7,0x79,0x9E,0xB2,0x3D,0x31,
    0x3E,0x98,0xB5,0x6E,0x27,0xD3,0xBC,0xCF,0x59,0x1E,0x18,0x1F,0x4C,0x5A,0xB7,0x93,
    0xE9,0xDE,0xE7,0x2C,0x8F,0x0C,0x0F,0xA6,0x2D,0xDB,0x49,0xF4,0x6F,0x73,0x96,0x47,
    0x06,0x07,0x53,0x16,0xED,0x24,0x7A,0x37,0x39,0xCB,0xA3,0x83,0x03,0xA9,0x8B,0xF6,
    0x92,0xBD,0x9B,0x1C,0xE5,0xD1,0x41,0x01,0x54,0x45,0xFB,0xC9,0x5E,0x4D,0x0E,0xF2,
    0x68,0x20,0x80,0xAA,0x22,0x7D,0x64,0x2F,0x26,0x87,0xF9,0x34,0x90,0x40,0x55,0x11,
    0xBE,0x32,0x97,0x13,0x43,0xFC,0x9A,0x48,0xA0,0x2A,0x88,0x5F,0x19,0x4B,0x09,0xA1,
    0x7E,0xCD,0xA4,0xD0,0x15,0x44,0xAF,0x8C,0xA5,0x84,0x50,0xBF,0x66,0xD2,0xE8,0x8A,
    0xA2,0xD7,0x46,0x52,0x42,0xA8,0xDF,0xB3,0x69,0x74,0xC5,0x51,0xEB,0x23,0x29,0x21,
    0xD4,0xEF,0xD9,0xB4,0x3A,0x62,0x28,0x75,0x91,0x14,0x10,0xEA,0x77,0x6C,0xDA,0x1D
};

void BelT::keySchedule(const std::string& keyStr) {
    if (keyStr.size() != 32) return;
    const uint8_t* kb = reinterpret_cast<const uint8_t*>(keyStr.data());
    uint32_t k_t[8];
    for (int i = 0; i < 8; ++i) k_t[i] = loadBE32(kb + 4 * i);
    for (int i = 1; i <= 56; ++i) roundKeys[i] = k_t[(i - 1) % 8];
}

void BelT::cryptBlock(const uint8_t in[16], uint8_t out[16]) const {
    uint32_t a = loadBE32(in + 0);
    uint32_t b = loadBE32(in + 4);
    uint32_t c = loadBE32(in + 8);
    uint32_t d = loadBE32(in + 12);

    for (int r = 1; r <= 8; ++r) {
        b = b ^ G(a + roundKeys[7 * r - 6], 5);
        c = c ^ G(d + roundKeys[7 * r - 5], 21);
        a = a - G(b + roundKeys[7 * r - 4], 13);

        uint32_t e = G(b + c + roundKeys[7 * r - 3], 21) ^ uint32_t(r);
        b = b + e;
        c = c - e;

        d = d + G(c + roundKeys[7 * r - 2], 13);
        b = b ^ G(a + roundKeys[7 * r - 1], 21);
        c = c ^ G(d + roundKeys[7 * r], 5);

        std::swap(a, b);
        std::swap(c, d);
        std::swap(b, c);
    }

    storeBE32(out + 0, b);
    storeBE32(out + 4, d);
    storeBE32(out + 8, a);
    storeBE32(out + 12, c);
}

struct GF128 {
    uint64_t hi;
    uint64_t lo;

    static GF128 fromBytes(const uint8_t b[16]) {
        GF128 r;
        r.hi = (uint64_t(b[0]) << 56) | (uint64_t(b[1]) << 48)
            | (uint64_t(b[2]) << 40) | (uint64_t(b[3]) << 32)
            | (uint64_t(b[4]) << 24) | (uint64_t(b[5]) << 16)
            | (uint64_t(b[6]) << 8) | uint64_t(b[7]);
        r.lo = (uint64_t(b[8]) << 56) | (uint64_t(b[9]) << 48)
            | (uint64_t(b[10]) << 40) | (uint64_t(b[11]) << 32)
            | (uint64_t(b[12]) << 24) | (uint64_t(b[13]) << 16)
            | (uint64_t(b[14]) << 8) | uint64_t(b[15]);
        return r;
    }
    void toBytes(uint8_t b[16]) const {
        for (int i = 0; i < 8; ++i) {
            b[i] = uint8_t(hi >> (56 - 8 * i));
            b[8 + i] = uint8_t(lo >> (56 - 8 * i));
        }
    }
    GF128 operator^(const GF128& o) const { return { hi ^ o.hi, lo ^ o.lo }; }
};

static GF128 gf128Mul(GF128 X, GF128 H) {
    GF128 Z{ 0, 0 };
    GF128 V = H;
    for (int i = 0; i < 128; ++i) {
        uint64_t bit;
        if (i < 64) bit = (X.hi >> (63 - i)) & 1ULL;
        else        bit = (X.lo >> (127 - i)) & 1ULL;

        uint64_t mask = 0ULL - bit;

        Z.hi ^= V.hi & mask;
        Z.lo ^= V.lo & mask;

        uint64_t msb = V.hi >> 63;
        uint64_t rmask = 0ULL - msb;
        V.hi = (V.hi << 1) | (V.lo >> 63);
        V.lo = (V.lo << 1) ^ (rmask & 0x87ULL);
    }
    return Z;
}

class GHASH {
private:
    GF128 H_;
public:
    void setKey(const uint8_t H_bytes[16]) { H_ = GF128::fromBytes(H_bytes); }

    void updateBlocks(const uint8_t* data, size_t len, uint8_t Y[16]) const {
        GF128 y = GF128::fromBytes(Y);
        size_t blocks = (len + 15) / 16;
        for (size_t i = 0; i < blocks; ++i) {
            uint8_t buf[16] = { 0 };
            size_t chunk = (len - i * 16 < 16) ? (len - i * 16) : 16;
            std::memcpy(buf, data + i * 16, chunk);

            GF128 x = GF128::fromBytes(buf);
            y = y ^ x;
            y = gf128Mul(y, H_);
        }
        y.toBytes(Y);
    }
};

class GCM {
private:
    BelT belt_;
    uint8_t H_bytes_[16];

public:
    explicit GCM(const std::string& key) {
        belt_.setKey(key);
        uint8_t zero[16] = { 0 };
        belt_.crypt(zero, H_bytes_);
    }

    void encrypt(const std::string& plain,
        const std::string& aad,
        const uint8_t IV[12],
        std::string& cipher_out,
        uint8_t tag[16]) const {
        cipher_out.assign(plain.size(), '\0');
        if (!plain.empty()) {
            ctrCrypt(reinterpret_cast<const uint8_t*>(plain.data()),
                plain.size(),
                IV,
                reinterpret_cast<uint8_t*>(&cipher_out[0]));
        }

        GHASH gh;
        gh.setKey(H_bytes_);

        uint8_t Y[16] = { 0 };
        gh.updateBlocks(reinterpret_cast<const uint8_t*>(aad.data()), aad.size(), Y);
        gh.updateBlocks(reinterpret_cast<const uint8_t*>(cipher_out.data()),
            cipher_out.size(), Y);

        uint8_t L[16] = { 0 };
        uint64_t aad_bits = uint64_t(aad.size()) * 8;
        uint64_t c_bits = uint64_t(cipher_out.size()) * 8;
        for (int i = 0; i < 8; ++i) {
            L[i] = uint8_t(aad_bits >> (56 - 8 * i));
            L[8 + i] = uint8_t(c_bits >> (56 - 8 * i));
        }
        gh.updateBlocks(L, 16, Y);

        uint8_t CB0[16] = { 0 };
        std::memcpy(CB0, IV, 12);
        uint8_t S0[16];
        belt_.crypt(CB0, S0);

        for (int i = 0; i < 16; ++i) tag[i] = Y[i] ^ S0[i];
    }

    static bool tagEqual(const uint8_t a[16], const uint8_t b[16]) {
        uint8_t diff = 0;
        for (int i = 0; i < 16; ++i) diff |= a[i] ^ b[i];
        return diff == 0;
    }

private:
    void ctrCrypt(const uint8_t* in, size_t len,
        const uint8_t IV[12], uint8_t* out) const {
        constexpr size_t BLOCK = 16;
        for (size_t off = 0; off < len; off += BLOCK) {
            uint32_t counter = uint32_t(off / BLOCK + 1);

            uint8_t CB[BLOCK];
            std::memcpy(CB, IV, 12);
            CB[12] = uint8_t(counter >> 24);
            CB[13] = uint8_t(counter >> 16);
            CB[14] = uint8_t(counter >> 8);
            CB[15] = uint8_t(counter);

            uint8_t S[BLOCK];
            belt_.crypt(CB, S);

            size_t chunk = (len - off < BLOCK) ? (len - off) : BLOCK;
            for (size_t k = 0; k < chunk; ++k) out[off + k] = in[off + k] ^ S[k];
        }
    }
};


static std::string generateKey() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    std::string k(32, '\0');
    for (int i = 0; i < 32; ++i) k[i] = static_cast<char>(dist(gen));
    return k;
}

static void printHexBytes(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << int(p[i]) << " ";
    }
    std::cout << std::dec << std::setfill(' ');
}

static void printHexString(const std::string& s) {
    printHexBytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

static bool parseHexBytes(const std::string& s, uint8_t* out, size_t n) {
    if (s.size() != n * 2) return false;
    for (size_t i = 0; i < n; ++i) {
        auto hv = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
            };
        int h1 = hv(s[2 * i]);
        int h2 = hv(s[2 * i + 1]);
        if (h1 < 0 || h2 < 0) return false;
        out[i] = uint8_t((h1 << 4) | h2);
    }
    return true;
}

static void pauseAndClear() {
    std::cout << "\nНажмите Enter, чтобы продолжить...";
    std::cin.get();
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}


int main() {
    setlocale(LC_ALL, "ru");

    std::string key = generateKey();
    std::string text = "Hello, AEAD-GCM!";
    std::string aad = "Additional data";
    uint8_t iv[12];
    for (int i = 0; i < 12; ++i) iv[i] = uint8_t(i);

    int choice = -1;
    while (choice != 0) {
        std::cout << "\nМЕНЮ \n";
        std::cout << " 1. Сгенерировать новый ключ\n";
        std::cout << " 2. Задать ключ вручную (hex, 64 символа)\n";
        std::cout << " 3. Изменить открытый текст\n";
        std::cout << " 4. Изменить дополнительные данные (AAD)\n";
        std::cout << " 5. Изменить вектор инициализации (IV)\n";
        std::cout << " 6. Показать текущие данные и результаты шифрования\n";
        std::cout << " 0. Выход\n";
        std::cout << "Выберите пункт: ";

        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Некорректный ввод. Попробуйте снова.\n";
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
        case 1: {
            key = generateKey();
            std::cout << "Ключ сгенерирован (hex, 32 байта):\n  ";
            printHexString(key);
            std::cout << "\n";
            pauseAndClear();
            break;
        }
        case 2: {
            std::cout << "Введите 32 байта ключа в hex (64 символа):\n> ";
            std::string line;
            std::getline(std::cin, line);
            std::string tmp(32, '\0');
            if (parseHexBytes(line, reinterpret_cast<uint8_t*>(&tmp[0]), 32)) {
                key = tmp;
                std::cout << "Ключ принят.\n";
            }
            else {
                std::cout << "Ошибка: некорректная hex-строка (нужно 64 символа).\n";
            }
            pauseAndClear();
            break;
        }
        case 3: {
            std::cout << "Введите открытый текст: ";
            std::getline(std::cin, text);
            std::cout << "Сохранено, размер: " << text.size() << " байт.\n";
            pauseAndClear();
            break;
        }
        case 4: {
            std::cout << "Введите AAD (доп. аутентифицируемые данные): ";
            std::getline(std::cin, aad);
            std::cout << "Сохранено, размер: " << aad.size() << " байт.\n";
            pauseAndClear();
            break;
        }
        case 5: {
            std::cout << "Введите IV: 12 байт hex (24 символа):\n> ";
            std::string line;
            std::getline(std::cin, line);
            uint8_t tmp[12];
            if (parseHexBytes(line, tmp, 12)) {
                std::memcpy(iv, tmp, 12);
                std::cout << "IV сохранён.\n";
            }
            else {
                std::cout << "Ошибка: некорректная hex-строка (нужно 24 символа).\n";
            }
            pauseAndClear();
            break;
        }
        case 6: {
            std::cout << "ТЕКУЩИЕ ДАННЫЕ\n";
            std::cout << "Ключ (hex, 32 байта):\n  ";
            printHexString(key);
            std::cout << "\n";

            std::cout << "Открытый текст (" << text.size() << " байт):\n  \""
                << text << "\"\n";

            std::cout << "AAD (" << aad.size() << " байт):\n  \""
                << aad << "\"\n";

            std::cout << "IV (hex, 12 байт):\n  ";
            printHexBytes(iv, 12);
            std::cout << "\n";

            std::cout << "\nРезультаты шифрования\n";

            {
                BelT belt;
                belt.setKey(key);
                uint8_t in[16] = { 0 };
                std::memcpy(in, text.data(), std::min<size_t>(16, text.size()));
                uint8_t out[16];
                belt.crypt(in, out);
                std::cout << "[Belt, один блок 16 байт]\n";
                std::cout << "  Вход  (hex): "; printHexBytes(in, 16); std::cout << "\n";
                std::cout << "  Выход (hex): "; printHexBytes(out, 16); std::cout << "\n";
            }

            {
                GCM gcm(key);
                std::string cipher;
                uint8_t tag[16];
                gcm.encrypt(text, aad, iv, cipher, tag);
                std::cout << "\n[GCM AEAD]\n";
                std::cout << "  Шифротекст (hex): ";
                printHexBytes(reinterpret_cast<const uint8_t*>(cipher.data()),
                    cipher.size());
                std::cout << "\n  Тег (hex, 16 байт): ";
                printHexBytes(tag, 16);
                std::cout << "\n";

                uint8_t tagCopy[16];
                std::memcpy(tagCopy, tag, 16);
                std::cout << "  Тег (не изменён):       "
                    << (GCM::tagEqual(tag, tagCopy) ? "совпадает" : "не совпадает")
                    << "\n";
                tagCopy[15] ^= 0x01;
                std::cout << "  Тег (изменён младший):  "
                    << (GCM::tagEqual(tag, tagCopy) ? "совпадает" : "не совпадает")
                    << "\n";
            }

            std::cout << "\n[Справка] Константы:\n"
                << "  p(x) = 0x12B (x^8+x^5+x^3+x+1) — неприводим в GF(2)[x]\n"
                << "  f(x) = x^128+x^7+x^2+x+1 — полином GHASH\n";

            pauseAndClear();
            break;
        }
        case 0:
            std::cout << "Выход из программы.\n";
            break;
        default:
            std::cout << "Неверный пункт меню.\n";
            pauseAndClear();
            break;
        }
    }
    return 0;
}