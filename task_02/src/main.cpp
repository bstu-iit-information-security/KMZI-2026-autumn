#include <iostream>
#include <vector>
#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <boost/multiprecision/cpp_int.hpp>

using BigInt = boost::multiprecision::cpp_int;

class RSAArithmetic {
public:
    static BigInt modPow(BigInt base, BigInt exp, BigInt mod) {
        BigInt res = 1;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2 == 1) res = (res * base) % mod;
            base = (base * base) % mod;
            exp /= 2;
        }
        return res;
    }

    static BigInt modInverse(BigInt a, BigInt m) {
        BigInt m0 = m, t, q;
        BigInt x0 = 0, x1 = 1;
        if (m == 1) return 0;
        while (a > 1) {
            q = a / m;
            t = m;
            m = a % m;
            a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0) x1 += m0;
        return x1;
    }
};


class RSACoreCRT {
public:
    struct PrivateKeyCRT {
        BigInt p, q, d, dp, dq, q_inv;
    };

    struct PublicKey {
        BigInt N, e;
    };

    static BigInt encrypt(const BigInt& m, const PublicKey& pub) {
        return RSAArithmetic::modPow(m, pub.e, pub.N);
    }

    static BigInt decryptCRT(const BigInt& c, const PrivateKeyCRT& priv) {
        BigInt m1 = RSAArithmetic::modPow(c, priv.dp, priv.p);
        BigInt m2 = RSAArithmetic::modPow(c, priv.dq, priv.q);

        BigInt diff = (m1 - m2) % priv.p;
        if (diff < 0) {
            diff += priv.p;
        }
        BigInt h = (diff * priv.q_inv) % priv.p;
        BigInt m = m2 + h * priv.q;

        return m;
    }
};

class RSA_OAEP {
private:
    static constexpr size_t k = 384;
    static constexpr size_t hLen = 32;
    static constexpr size_t maxMsgLen = k - 2 * hLen - 2;

    static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
        return std::vector<uint8_t>(hLen, 0xAA);
    }

    static std::vector<uint8_t> MGF1(const std::vector<uint8_t>& seed, size_t maskLen) {
        std::vector<uint8_t> mask;
        mask.reserve(maskLen + hLen);
        uint32_t counter = 0;

        while (mask.size() < maskLen) {
            std::vector<uint8_t> C(4);
            C[0] = (counter >> 24) & 0xFF;
            C[1] = (counter >> 16) & 0xFF;
            C[2] = (counter >> 8) & 0xFF;
            C[3] = counter & 0xFF;

            std::vector<uint8_t> Z = seed;
            Z.insert(Z.end(), C.begin(), C.end());

            std::vector<uint8_t> hash = sha256(Z);
            mask.insert(mask.end(), hash.begin(), hash.end());
            counter++;
        }
        mask.resize(maskLen);
        return mask;
    }

    static void xorArrays(std::vector<uint8_t>& dest, const std::vector<uint8_t>& src) {
        for (size_t i = 0; i < dest.size(); ++i) dest[i] ^= src[i];
    }

public:
    static std::vector<uint8_t> encodeOAEP(const std::vector<uint8_t>& M) {
        if (M.size() > maxMsgLen) throw std::runtime_error("Message too long");

        std::vector<uint8_t> lHash = sha256({});
        size_t psLen = k - M.size() - 2 * hLen - 2;

        std::vector<uint8_t> DB = lHash;
        DB.insert(DB.end(), psLen, 0x00);
        DB.push_back(0x01);
        DB.insert(DB.end(), M.begin(), M.end());

        std::vector<uint8_t> seed(hLen, 0xBB);

        std::vector<uint8_t> dbMask = MGF1(seed, k - hLen - 1);
        std::vector<uint8_t> maskedDB = DB;
        xorArrays(maskedDB, dbMask);

        std::vector<uint8_t> seedMask = MGF1(maskedDB, hLen);
        std::vector<uint8_t> maskedSeed = seed;
        xorArrays(maskedSeed, seedMask);

        std::vector<uint8_t> EM;
        EM.reserve(k);
        EM.push_back(0x00);
        EM.insert(EM.end(), maskedSeed.begin(), maskedSeed.end());
        EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());

        return EM;
    }

    static std::vector<uint8_t> decodeOAEP(const std::vector<uint8_t>& EM) {
        if (EM.size() != k || EM[0] != 0x00) {
            throw std::runtime_error("Ошибка деинкапсуляции: неверный размер контейнера или первый байт");
        }

        std::vector<uint8_t> maskedSeed(EM.begin() + 1, EM.begin() + 1 + hLen);
        std::vector<uint8_t> maskedDB(EM.begin() + 1 + hLen, EM.end());

        std::vector<uint8_t> seedMask = MGF1(maskedDB, hLen);
        std::vector<uint8_t> seed = maskedSeed;
        xorArrays(seed, seedMask);

        std::vector<uint8_t> dbMask = MGF1(seed, k - hLen - 1);
        std::vector<uint8_t> DB = maskedDB;
        xorArrays(DB, dbMask);

        std::vector<uint8_t> expectedHash = sha256({});
        uint8_t hash_error = 0;
        for (size_t i = 0; i < hLen; ++i) {
            hash_error |= (DB[i] ^ expectedHash[i]);
        }

        size_t separator_index = 0;
        uint8_t found_separator = 0;

        for (size_t i = hLen; i < DB.size(); ++i) {
            uint8_t is_one = (DB[i] == 0x01) ? 1 : 0;
            if (is_one && !found_separator) {
                separator_index = i;
                found_separator = 1;
            }
        }

        if (!found_separator || hash_error != 0) {
            throw std::runtime_error("Разделитель 0x01 не найден или неверный lHash");
        }

        return std::vector<uint8_t>(DB.begin() + separator_index + 1, DB.end());
    }
};


BigInt bytesToBigInt(const std::vector<uint8_t>& bytes) {
    BigInt res = 0;
    for (uint8_t b : bytes) res = (res << 8) | b;
    return res;
}

std::vector<uint8_t> bigIntToBytes(const BigInt& num, size_t fixed_length) {
    std::vector<uint8_t> bytes;
    BigInt temp = num;
    while (temp > 0) {
        bytes.push_back(static_cast<uint8_t>(temp & 0xFF));
        temp >>= 8;
    }
    std::reverse(bytes.begin(), bytes.end());
    if (bytes.size() < fixed_length) {
        bytes.insert(bytes.begin(), fixed_length - bytes.size(), 0x00);
    }
    return bytes;
}

void generateRSAKeys(RSACoreCRT::PublicKey& pub, RSACoreCRT::PrivateKeyCRT& priv) {
    BigInt p("0xC1C3D6A126A45F3637FA0197E50334889DF96EBBA1F6216B4D6EE6C95420367E0F8B26A0E23E282A7C3A04AA54668A1D3BF32B70AD15F3C8A0FEF50D7D76BFF27D6FE38EE3D2D35A344FA0E22FE034449830589BB5262B57B2F8651F0D53051C333EC71A690B812F4FE24B66E04BFA73DCEBCE95D1A4076CDE41E1C55353CE62F8B60064C72B9F4C2369260799738A5F");
    BigInt q("0xE3A9326F9E131C618A979A0300B4C72EA5FF309BD1216B1FA3DF3815D4D5417B8097AC24D4122C39B87F0D0D14F3C6415B5C1B846665FA0DEFF1BFA6E8387F0B46CD958F8D69A6BD10B74EF39BA6E2B1A6EF8164EB7D2BA03C5C6B1C98B6F7A9651515286598379B87B576304C1C6C0F1240C93699A6E2BB7DFB31006E8813C8D00C21B2F2A8ACD2F02506F46C6BD81B");

    pub.N = p * q;
    BigInt phi = (p - 1) * (q - 1);
    pub.e = 65537;

    BigInt d = RSAArithmetic::modInverse(pub.e, phi);

    priv.p = p;
    priv.q = q;
    priv.d = d;
    priv.dp = d % (p - 1);
    priv.dq = d % (q - 1);
    priv.q_inv = RSAArithmetic::modInverse(q, p);
}


void testRSA_Pipeline(const std::vector<uint8_t>& message,
                      const RSACoreCRT::PublicKey& pub,
                      const RSACoreCRT::PrivateKeyCRT& priv) {

    std::cout << "Размер сообщения: " << message.size() << " байт\n";
    auto start_time = std::chrono::high_resolution_clock::now();

    try {
        std::vector<uint8_t> em = RSA_OAEP::encodeOAEP(message);
        BigInt m_int = bytesToBigInt(em);

        BigInt c_int = RSACoreCRT::encrypt(m_int, pub);
        BigInt decrypted_int = RSACoreCRT::decryptCRT(c_int, priv);

        std::vector<uint8_t> decrypted_em = bigIntToBytes(decrypted_int, 384);
        std::vector<uint8_t> original_message = RSA_OAEP::decodeOAEP(decrypted_em);

    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << "\n";
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    std::cout << "Время (шифрование + расшифрование): " << duration.count() << " мкс\n\n";
}

int main() {
    std::cout << "=== Лабораторная работа №2 (Вариант 11) ===\n\n";

    RSACoreCRT::PublicKey pubKey;
    RSACoreCRT::PrivateKeyCRT privKey;
    generateRSAKeys(pubKey, privKey);

    std::vector<uint8_t> empty_msg = {};
    testRSA_Pipeline(empty_msg, pubKey, privKey);

    std::vector<uint8_t> max_msg(318, 0xFF);
    testRSA_Pipeline(max_msg, pubKey, privKey);

    std::string text = "Hello, Constant-Time RSA!";
    std::vector<uint8_t> normal_msg(text.begin(), text.end());
    testRSA_Pipeline(normal_msg, pubKey, privKey);

    return 0;
}