#include <iostream>
#include <iomanip>
#include <cstdint>
#include <windows.h>

using namespace std;

class GaloisCalculator {
private:
    uint16_t poly;
    uint8_t sbox[256];

    uint8_t affineTransform(uint8_t s) {
        return s ^ (rotl8(s, 1)) ^ (rotl8(s, 2)) ^ (rotl8(s, 3)) ^ (rotl8(s, 4)) ^ 0x63;
    }

    uint8_t rotl8(uint8_t val, int shift) {
        return (val << shift) | (val >> (8 - shift));
    }

public:
    GaloisCalculator(uint16_t ipoly) : poly(ipoly) {
        generateSBox();
    }

    uint8_t add(uint8_t a, uint8_t b) {
        return a ^ b;
    }

    uint8_t multiply(uint8_t a, uint8_t b) {
        uint8_t result = 0;
        for (int i = 0; i < 8; i++) {
            uint8_t mask_b = -(b & 1);
            result ^= (a & mask_b);
            uint8_t mask_a = -(a >> 7);
            a = (a << 1) ^ ((poly & 0xFF) & mask_a);
            b >>= 1;
        }
        return result;
    }

    uint8_t inverse(uint8_t a) {
        uint8_t b2 = multiply(a, a);
        uint8_t b4 = multiply(b2, b2);
        uint8_t b8 = multiply(b4, b4);
        uint8_t b16 = multiply(b8, b8);
        uint8_t b32 = multiply(b16, b16);
        uint8_t b64 = multiply(b32, b32);
        uint8_t b128 = multiply(b64, b64);
        
        uint8_t res = multiply(b128, b64);
        res = multiply(res, b32);
        res = multiply(res, b16);
        res = multiply(res, b8);
        res = multiply(res, b4);
        res = multiply(res, b2);
        return res;
    }

    void generateSBox() {
        for (int i = 0; i < 256; i++) {
            sbox[i] = affineTransform(inverse((uint8_t)i));
        }
    }

    uint8_t getSBoxValue(uint8_t val) {
        return sbox[val];
    }
};

class AES128 {
private:
    GaloisCalculator& calc;
    uint8_t roundKeys[176];

    uint8_t rcon(uint8_t i) {
        uint8_t res = 1;
        for (uint8_t j = 1; j < i; j++) res = calc.multiply(res, 0x02);
        return res;
    }

    void subBytes(uint8_t* state) {
        for (int i = 0; i < 16; i++) {
            state[i] = calc.getSBoxValue(state[i]);
        }
    }

    void shiftRows(uint8_t* state) {
        uint8_t temp;
        temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
        
        temp = state[2]; state[2] = state[10]; state[10] = temp;
        temp = state[6]; state[6] = state[14]; state[14] = temp;
        
        temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
    }

    void mixColumns(uint8_t* state) {
        uint8_t tmp[4];
        for (int i = 0; i < 4; i++) {
            int c = i * 4;
            tmp[0] = state[c]; tmp[1] = state[c+1]; tmp[2] = state[c+2]; tmp[3] = state[c+3];
            
            state[c]   = calc.multiply(tmp[0], 0x02) ^ calc.multiply(tmp[1], 0x03) ^ tmp[2] ^ tmp[3];
            state[c+1] = tmp[0] ^ calc.multiply(tmp[1], 0x02) ^ calc.multiply(tmp[2], 0x03) ^ tmp[3];
            state[c+2] = tmp[0] ^ tmp[1] ^ calc.multiply(tmp[2], 0x02) ^ calc.multiply(tmp[3], 0x03);
            state[c+3] = calc.multiply(tmp[0], 0x03) ^ tmp[1] ^ tmp[2] ^ calc.multiply(tmp[3], 0x02);
        }
    }

    void addRoundKey(uint8_t* state, int round) {
        for (int i = 0; i < 16; i++) {
            state[i] ^= roundKeys[round * 16 + i];
        }
    }

public:
    AES128(GaloisCalculator& calculator) : calc(calculator) {}

    void keyExpansion(const uint8_t* key) {
        for (int i = 0; i < 16; i++) {
            roundKeys[i] = key[i];
        }
        for (int i = 16; i < 176; i += 4) {
            uint8_t temp[4] = { roundKeys[i - 4], roundKeys[i - 3], roundKeys[i - 2], roundKeys[i - 1] };
            if (i % 16 == 0) {
                uint8_t t = temp[0];
                temp[0] = calc.getSBoxValue(temp[1]) ^ rcon(i / 16);
                temp[1] = calc.getSBoxValue(temp[2]);
                temp[2] = calc.getSBoxValue(temp[3]);
                temp[3] = calc.getSBoxValue(t);
            }
            for (int j = 0; j < 4; j++) {
                roundKeys[i + j] = roundKeys[i - 16 + j] ^ temp[j];
            }
        }
    }

    void encryptBlock(uint8_t* state) {
        addRoundKey(state, 0);
        for (int round = 1; round < 10; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, round);
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, 10);
    }
};

class GCM_SWAR {
private:
    AES128& aes;
    uint64_t H_high;
    uint64_t H_low;

    void multiplyGF128_SWAR(uint64_t& X_high, uint64_t& X_low) {
        uint64_t Z_high = 0, Z_low = 0;
        uint64_t V_high = H_high, V_low = H_low;

        for (int i = 0; i < 128; i++) {
            uint64_t bit = (X_high >> 63);
            uint64_t mask = -(bit & 1);
            
            Z_high ^= (V_high & mask);
            Z_low ^= (V_low & mask);

            uint64_t v_lsb = V_low & 1;
            uint64_t v_mask = -(v_lsb);
            
            V_low = (V_low >> 1) | (V_high << 63);
            V_high = (V_high >> 1);
            
            V_high ^= (0xE100000000000000ULL & v_mask);

            X_high = (X_high << 1) | (X_low >> 63);
            X_low = (X_low << 1);
        }
        X_high = Z_high;
        X_low = Z_low;
    }

public:
    GCM_SWAR(AES128& cipher) : aes(cipher), H_high(0), H_low(0) {}

    void initHashKey() {
        uint8_t zeroBlock[16] = {0};
        aes.encryptBlock(zeroBlock);
    }

    void incrementCounter(uint8_t* cb) {
        uint16_t carry = 1;
        for (int i = 15; i >= 12; i--) {
            uint16_t sum = cb[i] + carry;
            cb[i] = (uint8_t)sum;
            carry = sum >> 8;
        }
    }

    bool constantTimeTagCompare(const uint8_t* tag1, const uint8_t* tag2) {
        uint8_t diff = 0;
        for (int i = 0; i < 16; i++) {
            diff |= (tag1[i] ^ tag2[i]);
        }
        return (diff == 0);
    }
};

int main() {
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);

    uint16_t poly = 0x1F5;
    GaloisCalculator calc(poly);
    AES128 cipher(calc);
    GCM_SWAR gcm(cipher);

    uint8_t key[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 
                       0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
    cipher.keyExpansion(key);

    int choice;
    while (true) {
        cout << "\n=== AES-128 GCM (Полином: 0x1F5) ===\n";
        cout << "1. Зашифровать блок\n";
        cout << "0. Выход\n";
        cout << "Выбери действие: ";
        
        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(10000, '\n');
            continue;
        }

        if (choice == 0) break;

        if (choice == 1) {
            cout << "Введи текст (до 16 символов): ";
            string input;
            cin.ignore(); 
            getline(cin, input);

            uint8_t block[16] = {0}; 
            for(size_t i = 0; i < input.length() && i < 16; i++) {
                block[i] = static_cast<uint8_t>(input[i]);
            }

            cout << "\n[*] Открытый текст (hex): ";
            for(int i = 0; i < 16; i++) cout << hex << uppercase << setfill('0') << setw(2) << (int)block[i] << " ";

            cipher.encryptBlock(block);

            cout << "\n[*] Шифротекст (hex):     ";
            for(int i = 0; i < 16; i++) cout << hex << uppercase << setfill('0') << setw(2) << (int)block[i] << " ";
            cout << dec << "\n";
        }
    }
    return 0;
}