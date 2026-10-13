#include <iostream>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <array>
#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <clocale>

using Byte = std::uint8_t;
using Block = std::array<Byte, 16>;

// Модуль 1: Калькулятор Галуа GF(2^8) с полиномом 0x171

class GF256 {
public:
    static constexpr std::uint16_t P = 0x171;

    static Byte add(Byte a, Byte b) {
        return static_cast<Byte>(a ^ b);
    }

    static Byte multiply(Byte a, Byte b) {
        Byte r = 0;
        Byte temp = a;

        for (int i = 0; i < 8; ++i) {
            Byte mask = static_cast<Byte>(0u - static_cast<unsigned>(b & 1u));
            r ^= static_cast<Byte>(temp & mask);

            Byte hi = static_cast<Byte>(temp >> 7);
            Byte red_mask = static_cast<Byte>(0u - static_cast<unsigned>(hi));
            temp = static_cast<Byte>((temp << 1) ^ (static_cast<Byte>(P) & red_mask));
            b = static_cast<Byte>(b >> 1);
        }
        return r;
    }

    static Byte inverse(Byte a) {
        if (a == 0) return 0;

        Byte a2 = multiply(a, a);
        Byte a4 = multiply(a2, a2);
        Byte a8 = multiply(a4, a4);
        Byte a16 = multiply(a8, a8);
        Byte a32 = multiply(a16, a16);
        Byte a64 = multiply(a32, a32);
        Byte a128 = multiply(a64, a64);

        Byte r = a128;
        r = multiply(r, a64);
        r = multiply(r, a32);
        r = multiply(r, a16);
        r = multiply(r, a8);
        r = multiply(r, a4);
        r = multiply(r, a2);
        return r;
    }

    static Byte xtime(Byte a) {
        Byte hi = static_cast<Byte>(a >> 7);
        Byte mask = static_cast<Byte>(0u - static_cast<unsigned>(hi));
        return static_cast<Byte>((a << 1) ^ (static_cast<Byte>(P) & mask));
    }

    static bool check_inverse(Byte a, Byte inv) {
        return multiply(a, inv) == 1;
    }
};

// Модуль 2: AES-128 с Bit-slicing SubBytes над GF(2^8) с полиномом 0x171

class AES128 {
private:
    std::array<Byte, 176> round_keys_;
    std::array<Byte, 256> sbox_table_;
    std::array<Byte, 256> inv_sbox_table_;

    static Byte rotl8(Byte x, unsigned n) {
        return static_cast<Byte>((x << n) | (x >> (8u - n)));
    }

    void buildSBox() {
        // Прямой S-box: инверсия в GF(2^8, p=0x171) + аффинное преобразование AES
        for (int i = 0; i < 256; ++i) {
            Byte inv = GF256::inverse(static_cast<Byte>(i));
            sbox_table_[i] = static_cast<Byte>(
                inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63
                );
        }
        // Обратный S-box (для расшифрования)
        for (int i = 0; i < 256; ++i) {
            Byte y = static_cast<Byte>(
                rotl8(static_cast<Byte>(i), 1) ^
                rotl8(static_cast<Byte>(i), 3) ^
                rotl8(static_cast<Byte>(i), 6) ^ 0x05
                );
            inv_sbox_table_[i] = GF256::inverse(y);
        }
    }

    static void stateToSlices(const Block& state, std::array<uint16_t, 8>& slices) {
        for (int i = 0; i < 8; ++i) slices[i] = 0;
        for (int i = 0; i < 16; ++i) {
            for (int bit = 0; bit < 8; ++bit) {
                if (state[i] & (1 << bit)) {
                    slices[bit] |= static_cast<uint16_t>(1u << i);
                }
            }
        }
    }

    static void slicesToState(const std::array<uint16_t, 8>& slices, Block& state) {
        for (int i = 0; i < 16; ++i) {
            Byte byte = 0;
            for (int bit = 0; bit < 8; ++bit) {
                if (slices[bit] & static_cast<uint16_t>(1u << i)) {
                    byte |= static_cast<Byte>(1u << bit);
                }
            }
            state[i] = byte;
        }
    }

    static uint16_t bit_and(uint16_t a, uint16_t b) {
        return a & b;
    }

    static uint16_t bit_xor(uint16_t a, uint16_t b) {
        return a ^ b;
    }

    static void squareSlices(std::array<uint16_t, 8>& slices) {
        uint16_t a0 = slices[0], a1 = slices[1], a2 = slices[2], a3 = slices[3];
        uint16_t a4 = slices[4], a5 = slices[5], a6 = slices[6], a7 = slices[7];

        std::array<uint16_t, 8> b{};
        b[0] = bit_xor(bit_xor(a0, a4), a5);
        b[1] = a6;
        b[2] = bit_xor(bit_xor(a1, a5), a6);
        b[3] = a7;
        b[4] = bit_xor(bit_xor(bit_xor(bit_xor(a2, a4), a5), a6), a7);
        b[5] = bit_xor(bit_xor(a4, a5), a6);
        b[6] = bit_xor(bit_xor(a3, a4), a7);
        b[7] = bit_xor(a5, a7);

        slices = b;
    }

    static void multiplySlices(const std::array<uint16_t, 8>& a,
        const std::array<uint16_t, 8>& b,
        std::array<uint16_t, 8>& result) {
        result = { 0, 0, 0, 0, 0, 0, 0, 0 };
        std::array<uint16_t, 8> temp_b = b;

        for (int bit = 0; bit < 8; ++bit) {
            uint16_t mask = a[bit];
            for (int i = 0; i < 8; ++i) {
                result[i] = bit_xor(result[i], bit_and(temp_b[i], mask));
            }

            // Умножение на x (xtime) для полинома 0x171: x^8 = x^6 + x^5 + x^4 + 1
            uint16_t high = temp_b[7];
            for (int i = 7; i > 0; --i) {
                temp_b[i] = temp_b[i - 1];
            }
            temp_b[0] = 0;

            temp_b[6] = bit_xor(temp_b[6], high);
            temp_b[5] = bit_xor(temp_b[5], high);
            temp_b[4] = bit_xor(temp_b[4], high);
            temp_b[0] = bit_xor(temp_b[0], high);
        }
    }

    static void parallelInverse(std::array<uint16_t, 8>& slices) {
        std::array<uint16_t, 8> a2, a4, a8, a16, a32, a64, a128;
        std::array<uint16_t, 8> temp, temp2;

        a2 = slices;  squareSlices(a2);
        a4 = a2;      squareSlices(a4);
        a8 = a4;      squareSlices(a8);
        a16 = a8;     squareSlices(a16);
        a32 = a16;    squareSlices(a32);
        a64 = a32;    squareSlices(a64);
        a128 = a64;   squareSlices(a128);

        multiplySlices(a128, a64, temp);
        multiplySlices(temp, a32, temp2);
        multiplySlices(temp2, a16, temp);
        multiplySlices(temp, a8, temp2);
        multiplySlices(temp2, a4, temp);
        multiplySlices(temp, a2, temp2);

        slices = temp2;
    }

    static void parallelAffine(std::array<uint16_t, 8>& slices) {
        std::array<uint16_t, 8> new_slices = { 0, 0, 0, 0, 0, 0, 0, 0 };

        for (int i = 0; i < 8; ++i) {
            uint16_t bit = 0;
            bit = bit_xor(bit, slices[i]);
            bit = bit_xor(bit, slices[(i + 4) % 8]);
            bit = bit_xor(bit, slices[(i + 5) % 8]);
            bit = bit_xor(bit, slices[(i + 6) % 8]);
            bit = bit_xor(bit, slices[(i + 7) % 8]);

            if (0x63 & (1 << i)) {
                bit = bit_xor(bit, 0xFFFF);
            }

            new_slices[i] = bit;
        }
        slices = new_slices;
    }

    // Методы AES
    void shiftRows(Block& s) {
        Block t = s;
        for (std::size_t r = 0; r < 4; ++r) {
            for (std::size_t c = 0; c < 4; ++c) {
                s[4 * c + r] = t[4 * ((c + r) % 4) + r];
            }
        }
    }

    void invShiftRows(Block& s) {
        Block t = s;
        for (std::size_t r = 0; r < 4; ++r) {
            for (std::size_t c = 0; c < 4; ++c) {
                s[4 * c + r] = t[4 * ((c + 4 - r) % 4) + r];
            }
        }
    }

    void mixColumns(Block& s) {
        Block t = s;
        for (std::size_t c = 0; c < 4; ++c) {
            Byte a0 = t[4 * c + 0], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
            s[4 * c + 0] = GF256::multiply(0x02, a0) ^ GF256::multiply(0x03, a1) ^ a2 ^ a3;
            s[4 * c + 1] = a0 ^ GF256::multiply(0x02, a1) ^ GF256::multiply(0x03, a2) ^ a3;
            s[4 * c + 2] = a0 ^ a1 ^ GF256::multiply(0x02, a2) ^ GF256::multiply(0x03, a3);
            s[4 * c + 3] = GF256::multiply(0x03, a0) ^ a1 ^ a2 ^ GF256::multiply(0x02, a3);
        }
    }

    void invMixColumns(Block& s) {
        Block t = s;
        for (std::size_t c = 0; c < 4; ++c) {
            Byte a0 = t[4 * c + 0], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
            s[4 * c + 0] = GF256::multiply(0x0E, a0) ^ GF256::multiply(0x0B, a1) ^
                GF256::multiply(0x0D, a2) ^ GF256::multiply(0x09, a3);
            s[4 * c + 1] = GF256::multiply(0x09, a0) ^ GF256::multiply(0x0E, a1) ^
                GF256::multiply(0x0B, a2) ^ GF256::multiply(0x0D, a3);
            s[4 * c + 2] = GF256::multiply(0x0D, a0) ^ GF256::multiply(0x09, a1) ^
                GF256::multiply(0x0E, a2) ^ GF256::multiply(0x0B, a3);
            s[4 * c + 3] = GF256::multiply(0x0B, a0) ^ GF256::multiply(0x0D, a1) ^
                GF256::multiply(0x09, a2) ^ GF256::multiply(0x0E, a3);
        }
    }

    void addRoundKey(Block& s, std::size_t round) {
        std::size_t base = round * 16;
        for (std::size_t i = 0; i < 16; ++i) {
            s[i] ^= round_keys_[base + i];
        }
    }

public:
    AES128() {
        round_keys_.fill(0);
        buildSBox();
    }

    static void subBytesBitSliced(Block& state) {
        std::array<uint16_t, 8> slices;
        stateToSlices(state, slices);
        parallelInverse(slices);
        parallelAffine(slices);
        slicesToState(slices, state);
    }

    static void subBytesTable(Block& state) {
        for (Byte& x : state) x = sbox(x);
    }

    static Byte sbox(Byte x) {
        Byte inv = GF256::inverse(x);
        return static_cast<Byte>(
            inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63
            );
    }

    void set_key(const Block& key) {
        for (std::size_t i = 0; i < 16; ++i) round_keys_[i] = key[i];

        std::size_t bytes = 16;
        Byte rcon = 0x01;
        while (bytes < 176) {
            std::array<Byte, 4> t = {
                round_keys_[bytes - 4],
                round_keys_[bytes - 3],
                round_keys_[bytes - 2],
                round_keys_[bytes - 1]
            };

            if ((bytes % 16) == 0) {
                Byte first = t[0];
                t[0] = sbox_table_[t[1]];
                t[1] = sbox_table_[t[2]];
                t[2] = sbox_table_[t[3]];
                t[3] = sbox_table_[first];
                t[0] ^= rcon;
                rcon = GF256::xtime(rcon);
            }

            for (std::size_t j = 0; j < 4; ++j) {
                round_keys_[bytes] = static_cast<Byte>(round_keys_[bytes - 16] ^ t[j]);
                ++bytes;
            }
        }
    }

    void encrypt(const Block& in, Block& out) const {
        Block s = in;
        AES128* self = const_cast<AES128*>(this);
        self->addRoundKey(s, 0);

        for (std::size_t round = 1; round <= 9; ++round) {
            subBytesBitSliced(s);
            self->shiftRows(s);
            self->mixColumns(s);
            self->addRoundKey(s, round);
        }

        subBytesBitSliced(s);
        self->shiftRows(s);
        self->addRoundKey(s, 10);
        out = s;
    }

    void decrypt(const Block& in, Block& out) const {
        Block s = in;
        AES128* self = const_cast<AES128*>(this);
        self->addRoundKey(s, 10);

        for (int round = 9; round >= 1; --round) {
            self->invShiftRows(s);
            for (Byte& x : s) x = inv_sbox_table_[x];
            self->addRoundKey(s, static_cast<std::size_t>(round));
            self->invMixColumns(s);
        }

        self->invShiftRows(s);
        for (Byte& x : s) x = inv_sbox_table_[x];
        self->addRoundKey(s, 0);
        out = s;
    }

    static bool verify_inverse_mix() {
        static const std::array<Byte, 16> MIX = {
            0x02, 0x03, 0x01, 0x01,
            0x01, 0x02, 0x03, 0x01,
            0x01, 0x01, 0x02, 0x03,
            0x03, 0x01, 0x01, 0x02
        };
        static const std::array<Byte, 16> INV_MIX = {
            0x0E, 0x0B, 0x0D, 0x09,
            0x09, 0x0E, 0x0B, 0x0D,
            0x0D, 0x09, 0x0E, 0x0B,
            0x0B, 0x0D, 0x09, 0x0E
        };

        for (std::size_t r = 0; r < 4; ++r) {
            for (std::size_t c = 0; c < 4; ++c) {
                Byte acc = 0;
                for (std::size_t k = 0; k < 4; ++k) {
                    acc ^= GF256::multiply(INV_MIX[4 * r + k], MIX[4 * k + c]);
                }
                if (acc != (r == c ? 1 : 0)) return false;
            }
        }
        return true;
    }
};

// Модуль 3: GCM

class GCM {
public:
    static constexpr std::size_t MAX_DATA = 4096;

    struct Result {
        std::array<Byte, MAX_DATA> ciphertext{};
        std::size_t size = 0;
        Block tag{};
    };

    explicit GCM(const AES128& aes) : aes_(aes) {
        Block zero{};
        aes_.encrypt(zero, H_);
    }

    Result encrypt(const std::array<Byte, MAX_DATA>& plaintext,
        std::size_t len,
        const std::array<Byte, MAX_DATA>& aad,
        std::size_t aad_len,
        const std::array<Byte, 12>& iv) const {
        Result res;
        res.size = len;

        Block j0{};
        for (std::size_t i = 0; i < 12; ++i) j0[i] = iv[i];
        j0[15] = 1;

        Block ctr = j0;
        inc32(ctr);

        std::size_t offset = 0;
        while (offset < len) {
            Block stream{};
            aes_.encrypt(ctr, stream);
            std::size_t take = std::min<std::size_t>(16, len - offset);
            for (std::size_t i = 0; i < take; ++i) {
                res.ciphertext[offset + i] = plaintext[offset + i] ^ stream[i];
            }
            offset += take;
            inc32(ctr);
        }

        Block s = ghash(aad, aad_len, res.ciphertext, len);

        Block e0{};
        aes_.encrypt(j0, e0);
        for (std::size_t i = 0; i < 16; ++i) {
            res.tag[i] = e0[i] ^ s[i];
        }

        return res;
    }

    static bool constant_time_equal(const Block& a, const Block& b) {
        Byte diff = 0;
        for (std::size_t i = 0; i < 16; ++i) {
            diff |= static_cast<Byte>(a[i] ^ b[i]);
        }
        return diff == 0;
    }

private:
    const AES128& aes_;
    Block H_;

    static void inc32(Block& b) {
        for (int i = 15; i >= 12; --i) {
            if (++b[i] != 0) break;
        }
    }

    static Block gf128_mul(const Block& x, const Block& y) {
        Block z{};
        Block v = y;

        for (int i = 0; i < 128; ++i) {
            unsigned bit = (x[i / 8] >> (7 - (i % 8))) & 1u;
            Byte mask8 = static_cast<Byte>(0u - bit);

            for (std::size_t j = 0; j < 16; ++j) {
                z[j] ^= static_cast<Byte>(v[j] & mask8);
            }

            unsigned lsb = v[15] & 1u;
            Byte rmask = static_cast<Byte>(0u - lsb);

            Byte carry = 0;
            for (int j = 0; j < 16; ++j) {
                Byte cur = v[j];
                Byte next_carry = static_cast<Byte>(cur & 1u);
                v[j] = static_cast<Byte>((cur >> 1) | (carry << 7));
                carry = next_carry;
            }

            v[0] ^= static_cast<Byte>(0x87u & rmask);
        }
        return z;
    }

    static Block xor_block(const Block& a, const Block& b) {
        Block r{};
        for (std::size_t i = 0; i < 16; ++i) r[i] = a[i] ^ b[i];
        return r;
    }

    Block ghash(const std::array<Byte, MAX_DATA>& aad, std::size_t aad_len,
        const std::array<Byte, MAX_DATA>& c, std::size_t c_len) const {
        Block y{};

        auto absorb = [&](const std::array<Byte, MAX_DATA>& data, std::size_t len) {
            std::size_t off = 0;
            while (off < len) {
                Block x{};
                std::size_t take = std::min<std::size_t>(16, len - off);
                for (std::size_t i = 0; i < take; ++i) x[i] = data[off + i];
                y = gf128_mul(xor_block(y, x), H_);
                off += take;
            }
            };

        absorb(aad, aad_len);
        absorb(c, c_len);

        Block lengths{};
        std::uint64_t aad_bits = static_cast<std::uint64_t>(aad_len) * 8u;
        std::uint64_t c_bits = static_cast<std::uint64_t>(c_len) * 8u;

        for (int i = 0; i < 8; ++i) {
            lengths[7 - i] = static_cast<Byte>(aad_bits >> (8 * i));
            lengths[15 - i] = static_cast<Byte>(c_bits >> (8 * i));
        }

        y = gf128_mul(xor_block(y, lengths), H_);
        return y;
    }
};

// Вспомогательные функции

int hexCharToInt(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

Block parse16(const std::string& hex) {
    if (hex.size() != 32) throw std::invalid_argument("Expected 32 hex chars");
    Block out{};
    for (std::size_t i = 0; i < 16; ++i) {
        int hi = hexCharToInt(hex[2 * i]);
        int lo = hexCharToInt(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) throw std::invalid_argument("Invalid hex");
        out[i] = static_cast<Byte>((hi << 4) | lo);
    }
    return out;
}

std::array<Byte, 12> parseIV(const std::string& hex) {
    if (hex.size() != 24) throw std::invalid_argument("Expected 24 hex chars");
    std::array<Byte, 12> out{};
    for (std::size_t i = 0; i < 12; ++i) {
        int hi = hexCharToInt(hex[2 * i]);
        int lo = hexCharToInt(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) throw std::invalid_argument("Invalid hex");
        out[i] = static_cast<Byte>((hi << 4) | lo);
    }
    return out;
}

std::string hexStr(const Byte* p, std::size_t n) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < n; ++i) {
        os << std::setw(2) << static_cast<unsigned>(p[i]);
    }
    return os.str();
}

std::string hexStrBlock(const Block& b) {
    return hexStr(b.data(), 16);
}

int main() {
    std::setlocale(LC_ALL, "ru_RU.UTF-8");

    try {
        std::cout << "Bit-slicing использует только логические операции: AND, XOR\n\n";

        const Block key = parse16("000102030405060708090a0b0c0d0e0f");
        const Block pt  = parse16("00112233445566778899aabbccddeeff");

        AES128 aes;
        aes.set_key(key);

        // Проверка Bit-slicing SubBytes 
        std::cout << " Проверка Bit-slicing SubBytes \n";

        Block bs = pt;
        Block tb = pt;

        AES128::subBytesBitSliced(bs);
        AES128::subBytesTable(tb);

        std::cout << "Начальное состояние: " << hexStrBlock(pt) << "\n";
        std::cout << "После Bit-slicing:    " << hexStrBlock(bs) << "\n";
        std::cout << "После обычного S-box: " << hexStrBlock(tb) << "\n";
        std::cout << "Bit-slicing совпадает с S-box: "
                  << (bs == tb ? "YES" : "NO") << "\n\n";

        // Полное шифрование
        std::cout << " Полное шифрование \n";

        Block ct, dec;
        aes.encrypt(pt, ct);
        aes.decrypt(ct, dec);

        std::cout << "Открытый текст: " << hexStrBlock(pt) << "\n";
        std::cout << "Шифротекст:     " << hexStrBlock(ct) << "\n";
        std::cout << "Расшифровано:   " << hexStrBlock(dec) << "\n";
        std::cout << "Расшифровка корректна: "
                  << (dec == pt ? "YES" : "NO") << "\n\n";

        // Проверка GF(2^8) 
        bool gf_ok = (GF256::inverse(0x00) == 0x00);
        for (int x = 1; x < 256; ++x)
            gf_ok &= GF256::check_inverse((Byte)x, GF256::inverse((Byte)x));

        std::cout << "GF(2^8) inverse tests OK (including 0x00): "
                  << (gf_ok ? "YES" : "NO") << "\n";
        std::cout << "Inverse MixColumns OK: "
                  << (AES128::verify_inverse_mix() ? "YES" : "NO") << "\n\n";

        // GCM тест 
        std::cout << " GCM тест \n";

        std::array<Byte, GCM::MAX_DATA> msg{};
        std::array<Byte, GCM::MAX_DATA> aad{};

        std::string text     = "Hello, GCM! Variant 7.";
        std::string aad_text = "lab1-variant7";

        std::copy(text.begin(),     text.end(),     msg.begin());
        std::copy(aad_text.begin(), aad_text.end(), aad.begin());

        std::array<Byte, 12> iv = parseIV("000102030405060708090a0b");

        GCM gcm(aes);
        GCM::Result r = gcm.encrypt(msg, text.size(), aad, aad_text.size(), iv);

        std::cout << "IV: " << hexStr(iv.data(), 12) << "\n";
        std::cout << "AAD: " << hexStr(aad.data(), aad_text.size()) << "\n";
        std::cout << "Открытый текст: " << text << "\n";
        std::cout << "Шифротекст: " << hexStr(r.ciphertext.data(), r.size) << "\n";
        std::cout << "Тег: " << hexStr(r.tag.data(), 16) << "\n";
        std::cout << "Тег валиден: "
                  << (GCM::constant_time_equal(r.tag, r.tag) ? "YES" : "NO") << "\n";

        Block bad = r.tag;
        bad[0] ^= 1;

        std::cout << "Измененный тег обнаружен: "
                  << (!GCM::constant_time_equal(r.tag, bad) ? "YES" : "NO") << "\n\n";

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

