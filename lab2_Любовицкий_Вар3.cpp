#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <chrono>
#include <random>
#include "SHA512.h"

using namespace std;

vector<uint8_t> hexToBytes(const string& hex)
{
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

class BigInt
{
public:
    vector<uint32_t> digits;

    BigInt()
    {
        digits.push_back(0);
    }

    BigInt(uint64_t val)
    {
        digits.clear();
        digits.push_back(static_cast<uint32_t>(val & 0xFFFFFFFF));
        digits.push_back(static_cast<uint32_t>((val >> 32) & 0xFFFFFFFF));
        trim();
    }

    BigInt(const string& hexStr)
    {
        digits.clear();
        string s = hexStr;
        if (s.length() % 8 != 0)
        {
            s = string(8 - s.length() % 8, '0') + s;
        }
        for (int i = (int)s.length() - 8; i >= 0; i -= 8)
        {
            uint32_t limb = static_cast<uint32_t>(stoul(s.substr(i, 8), nullptr, 16));
            digits.push_back(limb);
        }
        trim();
    }

    void trim()
    {
        while (digits.size() > 1 && digits.back() == 0)
        {
            digits.pop_back();
        }
    }

    bool isEven() const
    {
        return (digits[0] & 1) == 0;
    }

    size_t bitLength() const
    {
        if (digits.size() == 1 && digits[0] == 0) return 0;
        size_t bits = (digits.size() - 1) * 32;
        uint32_t top = digits.back();
        while (top > 0)
        {
            bits++;
            top >>= 1;
        }
        return bits;
    }

    bool operator==(const BigInt& other) const
    {
        return digits == other.digits;
    }

    bool operator!=(const BigInt& other) const
    {
        return !(*this == other);
    }

    bool operator<(const BigInt& other) const
    {
        if (digits.size() != other.digits.size())
        {
            return digits.size() < other.digits.size();
        }
        for (int i = (int)digits.size() - 1; i >= 0; --i)
        {
            if (digits[i] != other.digits[i])
            {
                return digits[i] < other.digits[i];
            }
        }
        return false;
    }

    bool operator>(const BigInt& other) const
    {
        if (digits.size() != other.digits.size())
        {
            return digits.size() > other.digits.size();
        }
        for (int i = (int)digits.size() - 1; i >= 0; --i)
        {
            if (digits[i] != other.digits[i])
            {
                return digits[i] > other.digits[i];
            }
        }
        return false;
    }

    bool operator>=(const BigInt& other) const
    {
        return !(*this < other);
    }

    bool operator<=(const BigInt& other) const
    {
        return !(*this > other);
    }

    BigInt operator+(const BigInt& other) const
    {
        BigInt res;
        res.digits.clear();
        uint64_t carry = 0;
        size_t maxSize = max(digits.size(), other.digits.size());

        for (size_t i = 0; i < maxSize || carry; ++i)
        {
            uint64_t sum = carry;
            if (i < digits.size()) sum += digits[i];
            if (i < other.digits.size()) sum += other.digits[i];

            res.digits.push_back(static_cast<uint32_t>(sum & 0xFFFFFFFF));
            carry = sum >> 32;
        }
        res.trim();
        return res;
    }

    BigInt operator-(const BigInt& other) const
    {
        if (*this < other) return BigInt(0);

        BigInt res;
        res.digits.clear();
        int64_t borrow = 0;

        for (size_t i = 0; i < digits.size(); ++i)
        {
            int64_t diff = static_cast<int64_t>(digits[i]) - borrow;
            if (i < other.digits.size())
            {
                diff -= other.digits[i];
            }

            if (diff < 0)
            {
                diff += 0x100000000LL;
                borrow = 1;
            }
            else
            {
                borrow = 0;
            }
            res.digits.push_back(static_cast<uint32_t>(diff));
        }
        res.trim();
        return res;
    }

    BigInt operator*(const BigInt& other) const
    {
        BigInt res;
        res.digits.assign(digits.size() + other.digits.size(), 0);

        for (size_t i = 0; i < digits.size(); ++i)
        {
            uint64_t carry = 0;
            for (size_t j = 0; j < other.digits.size() || carry; ++j)
            {
                uint64_t cur = res.digits[i + j] +
                    static_cast<uint64_t>(digits[i]) * (j < other.digits.size() ? other.digits[j] : 0) +
                    carry;

                res.digits[i + j] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
                carry = cur >> 32;
            }
        }
        res.trim();
        return res;
    }

    BigInt shiftLeft1() const
    {
        BigInt res;
        res.digits.clear();
        uint32_t carry = 0;
        for (size_t i = 0; i < digits.size(); ++i)
        {
            uint64_t cur = (static_cast<uint64_t>(digits[i]) << 1) | carry;
            res.digits.push_back(static_cast<uint32_t>(cur & 0xFFFFFFFF));
            carry = static_cast<uint32_t>(cur >> 32);
        }
        if (carry) res.digits.push_back(carry);
        res.trim();
        return res;
    }

    BigInt shiftRight1() const
    {
        BigInt res;
        res.digits.resize(digits.size(), 0);
        uint32_t carry = 0;
        for (int i = (int)digits.size() - 1; i >= 0; --i)
        {
            uint64_t cur = (static_cast<uint64_t>(carry) << 32) | digits[i];
            res.digits[i] = static_cast<uint32_t>(cur >> 1);
            carry = digits[i] & 1;
        }
        res.trim();
        return res;
    }

    pair<BigInt, BigInt> divmod(const BigInt& divisor) const
    {
        if (divisor == BigInt(0)) return { BigInt(0), BigInt(0) };

        BigInt quotient = 0;
        BigInt remainder = 0;

        for (int i = (int)digits.size() - 1; i >= 0; --i)
        {
            for (int bit = 31; bit >= 0; --bit)
            {
                remainder = remainder.shiftLeft1();
                if ((digits[i] >> bit) & 1)
                {
                    remainder.digits[0] |= 1;
                }
                if (remainder >= divisor)
                {
                    remainder = remainder - divisor;
                    quotient = quotient.shiftLeft1();
                    quotient.digits[0] |= 1;
                }
                else
                {
                    quotient = quotient.shiftLeft1();
                }
            }
        }
        quotient.trim();
        remainder.trim();
        return { quotient, remainder };
    }

    BigInt operator/(const BigInt& other) const
    {
        return divmod(other).first;
    }

    BigInt operator%(const BigInt& other) const
    {
        return divmod(other).second;
    }

    string toHexString() const
    {
        stringstream ss;
        ss << hex << uppercase;
        ss << digits.back();
        for (int i = (int)digits.size() - 2; i >= 0; --i)
        {
            ss << setfill('0') << setw(8) << digits[i];
        }
        return ss.str();
    }
};

BigInt modPow(BigInt base, BigInt exp, BigInt mod)
{
    BigInt result = 1;
    base = base % mod;

    while (exp != BigInt(0))
    {
        if (exp.digits[0] & 1)
        {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp = exp.shiftRight1();
    }
    return result;
}

BigInt modInverse(BigInt a, BigInt m)
{
    BigInt m0 = m, t, q;
    BigInt x0 = 0, x1 = 1;
    BigInt zero = 0;

    if (m == BigInt(1)) return zero;

    while (a > BigInt(1))
    {
        auto dm = a.divmod(m0);
        q = dm.first;
        t = m0;
        m0 = dm.second;
        a = t;

        t = x0;
        BigInt qx0 = q * x0;
        if (x1 < qx0)
        {
            BigInt diff = qx0 - x1;
            BigInt rem = diff % m;
            x0 = (rem == zero) ? zero : (m - rem);
        }
        else
        {
            x0 = x1 - qx0;
        }
        x1 = t;
    }
    return x1;
}

const size_t HASH_LEN = 64;

vector<uint8_t> sha512(const vector<uint8_t>& data)
{
    SHA512 sha;
    string inputStr(data.begin(), data.end());
    string hexHash = sha.hash(inputStr);
    return hexToBytes(hexHash);
}

vector<uint8_t> generateRandomBytes(size_t numBytes)
{
    static uint64_t counter = 0;
    vector<uint8_t> result;
    result.reserve(numBytes);

    while (result.size() < numBytes)
    {
        uint64_t now = chrono::high_resolution_clock::now().time_since_epoch().count();
        counter++;

        vector<uint8_t> seedData(24);
        memcpy(seedData.data(), &now, 8);
        memcpy(seedData.data() + 8, &counter, 8);

        random_device rd;
        uint64_t rVal = (static_cast<uint64_t>(rd()) << 32) | rd();
        memcpy(seedData.data() + 16, &rVal, 8);

        vector<uint8_t> hash = sha512(seedData);
        size_t toCopy = min(numBytes - result.size(), hash.size());
        result.insert(result.end(), hash.begin(), hash.begin() + toCopy);
    }
    return result;
}

BigInt generateRandomBigInt(size_t bitLen)
{
    size_t byteLen = (bitLen + 7) / 8;
    vector<uint8_t> bytes = generateRandomBytes(byteLen);

    bytes[0] |= (1 << ((bitLen - 1) % 8));
    bytes[byteLen - 1] |= 1;

    stringstream ss;
    ss << hex << setfill('0');
    for (uint8_t b : bytes)
    {
        ss << setw(2) << static_cast<int>(b);
    }
    return BigInt(ss.str());
}

bool isPrimeMillerRabin(const BigInt& n, int k = 10)
{
    if (n <= BigInt(1)) return false;
    if (n == BigInt(2) || n == BigInt(3)) return true;
    if (n.isEven()) return false;

    BigInt d = n - BigInt(1);
    size_t s = 0;
    while (d.isEven())
    {
        d = d.shiftRight1();
        s++;
    }

    for (int i = 0; i < k; ++i)
    {
        BigInt a = generateRandomBigInt(min(n.bitLength() - 1, static_cast<size_t>(64)));
        if (a <= BigInt(1)) a = BigInt(2);
        if (a >= n - BigInt(1)) a = n - BigInt(2);

        BigInt x = modPow(a, d, n);
        if (x == BigInt(1) || x == n - BigInt(1)) continue;

        bool composite = true;
        for (size_t r = 1; r < s; ++r)
        {
            x = modPow(x, BigInt(2), n);
            if (x == n - BigInt(1))
            {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

BigInt generateLargePrime(size_t bitLen)
{
    while (true)
    {
        BigInt candidate = generateRandomBigInt(bitLen);
        if (isPrimeMillerRabin(candidate))
        {
            return candidate;
        }
    }
}

vector<uint8_t> mgf1(const vector<uint8_t>& seed, size_t length)
{
    vector<uint8_t> mask;
    uint32_t counter = 0;

    while (mask.size() < length)
    {
        vector<uint8_t> C(4);
        C[0] = (counter >> 24) & 0xFF;
        C[1] = (counter >> 16) & 0xFF;
        C[2] = (counter >> 8) & 0xFF;
        C[3] = counter & 0xFF;

        vector<uint8_t> temp = seed;
        temp.insert(temp.end(), C.begin(), C.end());

        vector<uint8_t> hash = sha512(temp);
        mask.insert(mask.end(), hash.begin(), hash.end());
        counter++;
    }

    mask.resize(length);
    return mask;
}

vector<uint8_t> oaepPad(const vector<uint8_t>& message, size_t k)
{
    if (k < 2 * HASH_LEN + 2) return {};

    size_t maxMsgLen = k - 2 * HASH_LEN - 2;
    if (message.size() > maxMsgLen) return {};

    vector<uint8_t> lHash = sha512({});
    size_t psLen = k - message.size() - 2 * HASH_LEN - 2;
    vector<uint8_t> ps(psLen, 0x00);

    vector<uint8_t> db = lHash;
    db.insert(db.end(), ps.begin(), ps.end());
    db.push_back(0x01);
    db.insert(db.end(), message.begin(), message.end());

    vector<uint8_t> seed = generateRandomBytes(HASH_LEN);

    vector<uint8_t> dbMask = mgf1(seed, k - HASH_LEN - 1);
    vector<uint8_t> maskedDB(db.size());
    for (size_t i = 0; i < db.size(); ++i)
    {
        maskedDB[i] = db[i] ^ dbMask[i];
    }

    vector<uint8_t> seedMask = mgf1(maskedDB, HASH_LEN);
    vector<uint8_t> maskedSeed(HASH_LEN);
    for (size_t i = 0; i < HASH_LEN; ++i)
    {
        maskedSeed[i] = seed[i] ^ seedMask[i];
    }

    vector<uint8_t> em;
    em.reserve(k);
    em.push_back(0x00);
    em.insert(em.end(), maskedSeed.begin(), maskedSeed.end());
    em.insert(em.end(), maskedDB.begin(), maskedDB.end());

    return em;
}

vector<uint8_t> oaepUnpad(const vector<uint8_t>& em, size_t k)
{
    if (em.size() < 2 * HASH_LEN + 2) return {};

    vector<uint8_t> maskedSeed(em.begin() + 1, em.begin() + 1 + HASH_LEN);
    vector<uint8_t> maskedDB(em.begin() + 1 + HASH_LEN, em.end());

    vector<uint8_t> seedMask = mgf1(maskedDB, HASH_LEN);
    vector<uint8_t> seed(HASH_LEN);
    for (size_t i = 0; i < HASH_LEN; ++i) seed[i] = maskedSeed[i] ^ seedMask[i];

    vector<uint8_t> dbMask = mgf1(seed, k - HASH_LEN - 1);
    vector<uint8_t> db(maskedDB.size());
    for (size_t i = 0; i < maskedDB.size(); ++i) db[i] = maskedDB[i] ^ dbMask[i];

    size_t msgStart = HASH_LEN;
    while (msgStart < db.size() && db[msgStart] != 0x01)
    {
        msgStart++;
    }
    msgStart++;

    if (msgStart > db.size()) return {};

    return vector<uint8_t>(db.begin() + msgStart, db.end());
}

struct RSAKey
{
    BigInt N, e, d, p, q, dp, dq, qinv;
};

RSAKey generateKeys(size_t keyBitLen = 128)
{
    RSAKey key;
    size_t primeBits = keyBitLen / 2;

    cout << "   [!] Генерация p (" << primeBits << " бит)..." << endl;
    key.p = generateLargePrime(primeBits);

    cout << "   [!] Генерация q (" << primeBits << " бит)..." << endl;
    do {
        key.q = generateLargePrime(primeBits);
    } while (key.p == key.q);

    key.N = key.p * key.q;
    BigInt phi = (key.p - BigInt(1)) * (key.q - BigInt(1));
    key.e = BigInt(65537);

    while (phi % key.e == BigInt(0))
    {
        key.e = key.e + BigInt(2);
    }

    key.d = modInverse(key.e, phi);
    key.dp = key.d % (key.p - BigInt(1));
    key.dq = key.d % (key.q - BigInt(1));
    key.qinv = modInverse(key.q, key.p);

    return key;
}

BigInt rsaEncrypt(BigInt m, BigInt e, BigInt N)
{
    return modPow(m, e, N);
}

BigInt rsaDecryptCRT(BigInt c, const RSAKey& key)
{
    BigInt m1 = modPow(c, key.dp, key.p);
    BigInt m2 = modPow(c, key.dq, key.q);

    BigInt m2_mod_p = m2 % key.p;
    BigInt diff = (m1 + key.p - m2_mod_p) % key.p;

    BigInt h = (key.qinv * diff) % key.p;
    BigInt m = m2 + (h * key.q);
    return m;
}

int main()
{
    cout << "[+] Запуск автоматической генерации RSA ключей (512 бит)..." << endl;
    RSAKey key = generateKeys(128);

    cout << "[+] Ключи успешно сгенерированы." << endl;
    cout << "    Простое p (HEX):  0x" << key.p.toHexString() << endl;
    cout << "    Простое q (HEX):  0x" << key.q.toHexString() << endl;
    cout << "    Модуль N (HEX):   0x" << key.N.toHexString() << endl;
    cout << "    Экспонента e:     0x" << key.e.toHexString() << endl;
    cout << "    CRT компоненты:" << endl;
    cout << "      dp:   0x" << key.dp.toHexString() << endl;
    cout << "      dq:   0x" << key.dq.toHexString() << endl;
    cout << "      qinv: 0x" << key.qinv.toHexString() << endl << endl;

    string inputStr = "asdasdasd!";
    vector<uint8_t> message(inputStr.begin(), inputStr.end());
    size_t k = 384;
    cout << "[1] Исходный текст: \"" << inputStr << "\"" << endl;
    vector<uint8_t> padded = oaepPad(message, k);

    BigInt msgNum = 0;
    for (size_t i = 0; i < min(message.size(), static_cast<size_t>(4)); ++i)
    {
        msgNum = msgNum * BigInt(256) + BigInt(message[i]);
    }
    cout << "[2] Входное число для RSA: 0x" << msgNum.toHexString() << endl;

    BigInt cipherNum = rsaEncrypt(msgNum, key.e, key.N);
    cout << "[3] Зашифрованное значение (HEX): 0x" << cipherNum.toHexString() << endl;

    BigInt decryptedNum = rsaDecryptCRT(cipherNum, key);
    cout << "[4] Расшифрованное значение CRT (HEX): 0x" << decryptedNum.toHexString() << endl;

    vector<uint8_t> unpaddedMessage = oaepUnpad(padded, k);
    string restoredStr(unpaddedMessage.begin(), unpaddedMessage.end());
    cout << "[5] Восстановленный текст из OAEP: \"" << restoredStr << "\"" << endl << endl;

    if (restoredStr == inputStr && decryptedNum == msgNum)
    {
        cout << "[УСПЕХ] Генерация больших простых чисел и криптосистема работают корректно!" << endl;
    }
    else
    {
        cout << "[ОШИБКА] Данные не совпадают!" << endl;
    }

    return 0;
}
