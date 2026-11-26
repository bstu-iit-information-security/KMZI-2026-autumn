#include <boost/multiprecision/cpp_int.hpp>
#include <iostream>
#include <string>
#include <random>
#include <vector>
#include <algorithm>
#include <stdexcept>

using boost::multiprecision::cpp_int;
using std::string;

static cpp_int hexToBigInt(const string& hexStr) {
    cpp_int result = 0;
    size_t startIdx = 0;
    
    if (hexStr.length() >= 2 && hexStr[0] == '0' && (hexStr[1] == 'x' || hexStr[1] == 'X')) {
        startIdx = 2;
    }

    for (size_t i = startIdx; i < hexStr.length(); ++i) {
        unsigned int val = 0;
        char ch = hexStr[i];
        if (ch >= '0' && ch <= '9') val = ch - '0';
        else if (ch >= 'a' && ch <= 'f') val = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') val = ch - 'A' + 10;
        else throw std::runtime_error("bad hex");
        
        result <<= 4;
        result += val;
    }
    return result;
}

static string bigIntToHex(cpp_int val) {
    if (val < 0) val = -val;
    if (val == 0) return "0";
    
    const char* hexDigits = "0123456789ABCDEF";
    string output;
    
    while (val > 0) {
        unsigned int digit = (val & 0xF).convert_to<unsigned int>();
        output.push_back(hexDigits[digit]);
        val >>= 4;
    }
    
    std::reverse(output.begin(), output.end());
    return output;
}

struct EccPoint {
    cpp_int x, y;
    bool isInfinity;

    EccPoint() {
        this->x = 0;
        this->y = 0;
        this->isInfinity = true;
    }
    
    EccPoint(cpp_int px, cpp_int py) {
        this->x = std::move(px);
        this->y = std::move(py);
        this->isInfinity = false;
    }
};

struct EllipticCurve {
    cpp_int p, a, b, q;
    EccPoint G;

    cpp_int mod(cpp_int value) const {
        value %= p;
        cpp_int mask = cpp_int(0) - (value < 0 ? cpp_int(1) : cpp_int(0));
        value += (p & mask);
        return value;
    }

    cpp_int modInverse(cpp_int val, const cpp_int& modulus) const {
        val %= modulus;
        if (val < 0) val += modulus;
        
        cpp_int t = 0, newT = 1;
        cpp_int r = modulus, newR = val;
        
        while (newR != 0) {
            cpp_int quot = r / newR;
            
            cpp_int tempT = t - quot * newT;
            t = newT;
            newT = tempT;
            
            cpp_int tempR = r - quot * newR;
            r = newR;
            newR = tempR;
        }
        
        if (r != 1) throw std::runtime_error("inverse error");
        
        t %= modulus;
        if (t < 0) t += modulus;
        return t;
    }

    bool isPointOnCurve(const EccPoint& P) const {
        if (P.isInfinity) return true;
        return mod(P.y * P.y - (P.x * P.x * P.x + a * P.x + b)) == 0;
    }

    EccPoint negatePoint(const EccPoint& P) const {
        if (P.isInfinity) return P;
        return EccPoint(P.x, mod(-P.y));
    }

    EccPoint addPoints(const EccPoint& P, const EccPoint& Q) const {
        if (P.isInfinity) return Q;
        if (Q.isInfinity) return P;

        if (P.x == Q.x) {
            if (mod(P.y + Q.y) == 0) return EccPoint();
            
            cpp_int denominator = mod(2 * P.y);
            if (denominator == 0) return EccPoint();
            
            cpp_int slope = mod((3 * P.x * P.x + a) * modInverse(denominator, p));
            cpp_int resX = mod(slope * slope - 2 * P.x);
            cpp_int resY = mod(slope * (P.x - resX) - P.y);
            return EccPoint(resX, resY);
        }

        cpp_int slope = mod((Q.y - P.y) * modInverse(Q.x - P.x, p));
        cpp_int resX = mod(slope * slope - P.x - Q.x);
        cpp_int resY = mod(slope * (P.x - resX) - P.y);
        return EccPoint(resX, resY);
    }

    EccPoint subPoints(const EccPoint& P, const EccPoint& Q) const {
        return addPoints(P, negatePoint(Q));
    }

    EccPoint scalarMultiply(cpp_int k, EccPoint P) const {
        k %= q;
        if (k < 0) k += q;

        unsigned int numBits = boost::multiprecision::msb(k) + 1;
        EccPoint result;
        EccPoint current = P;

        for (unsigned int i = 0; i < numBits; ++i) {
            cpp_int currentBit = (k >> i) & 1;
            cpp_int mask = cpp_int(0) - currentBit;

            EccPoint temp = addPoints(result, current);

            result.x = result.x ^ ((result.x ^ temp.x) & mask);
            result.y = result.y ^ ((result.y ^ temp.y) & mask);
            
            unsigned int rInf = result.isInfinity ? 1 : 0;
            unsigned int tInf = temp.isInfinity ? 1 : 0;
            unsigned int m = (unsigned int)currentBit.convert_to<unsigned int>();
            
            unsigned int newInf = (rInf & ~m) | (tInf & m);
            result.isInfinity = (newInf != 0);

            current = addPoints(current, current);
        }
        return result;
    }

    EccPoint multiplyBlinded(const cpp_int& d, const EccPoint& P, const cpp_int& blindFactor) const {
        EccPoint R = scalarMultiply(blindFactor, G);
        EccPoint P1 = addPoints(P, R);
        EccPoint A = scalarMultiply(d, P1);
        EccPoint B = scalarMultiply(d, R);
        return subPoints(A, B);
    }

    EccPoint derivePublicKey(const cpp_int& d, const cpp_int& blindFactor) const {
        return multiplyBlinded(d, G, blindFactor);
    }
};

static cpp_int generateRandomScalar(const cpp_int& q) {
    static std::random_device rd;
    static std::mt19937_64 generator(rd());
    
    unsigned int numBits = boost::multiprecision::msb(q) + 1;
    unsigned int numWords = (numBits + 63) / 64;
    cpp_int randomValue = 0;
    
    for (unsigned int i = 0; i < numWords; ++i) {
        randomValue <<= 64;
        randomValue += static_cast<unsigned long long>(generator());
    }
    
    randomValue %= (q - 1);
    return randomValue + 1;
}

struct DigitalSignature {
    cpp_int r, s;
};

static DigitalSignature createSignature(const EllipticCurve& curve, const cpp_int& privKey, 
                                        const cpp_int& msgHash, const cpp_int& blindFactor) {
    while (true) {
        cpp_int k = generateRandomScalar(curve.q);
        EccPoint C = curve.multiplyBlinded(k, curve.G, blindFactor);
        
        if (C.isInfinity) continue;

        cpp_int r = C.x % curve.q;
        if (r == 0) continue;

        cpp_int s = (r * privKey + k * msgHash) % curve.q;
        if (s < 0) s += curve.q;
        if (s == 0) continue;

        DigitalSignature sig;
        sig.r = r;
        sig.s = s;
        return sig;
    }
}

static bool checkSignature(const EllipticCurve& curve, const EccPoint& pubKey, 
                           const cpp_int& msgHash, const DigitalSignature& sig) {
    if (sig.r <= 0 || sig.r >= curve.q || sig.s <= 0 || sig.s >= curve.q) {
        return false;
    }

    cpp_int v = curve.modInverse(msgHash, curve.q);

    cpp_int z1 = (sig.s * v) % curve.q;
    cpp_int z2 = (-sig.r * v) % curve.q;
    if (z2 < 0) z2 += curve.q;

    EccPoint C = curve.addPoints(curve.scalarMultiply(z1, curve.G), 
                                 curve.scalarMultiply(z2, pubKey));
                                 
    if (C.isInfinity) return false;

    cpp_int checkR = C.x % curve.q;
    return checkR == sig.r;
}

int main() {
    const string P_HEX  = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43";
    const string A_HEX  = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF40";
    const string B_HEX  = "77CE6C1515F3A8EDD2C13AABE4D8FBBE4CF55069978B9253B22E7D6BD69C03F1";
    const string Q_HEX  = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD95C8ED60DFB4DFC7E5ABF99263D6607";
    const string GX_HEX = "0000000000000000000000000000000000000000000000000000000000000000";
    const string GY_HEX = "6BF7FC3CFB16D69F5CE4C9A351D6835D78913966C408F6521E29CF1804516A93";

    EllipticCurve E{
        hexToBigInt(P_HEX), hexToBigInt(A_HEX), hexToBigInt(B_HEX), hexToBigInt(Q_HEX),
        EccPoint(hexToBigInt(GX_HEX), hexToBigInt(GY_HEX))
    };

    if (!E.isPointOnCurve(E.G)) {
        std::cerr << "Error: generator point is not on the curve\n";
        return 1;
    }

    cpp_int privA = hexToBigInt("1A2B3C4D5E6F");
    cpp_int privB = hexToBigInt("223344556677");

    cpp_int blindA = generateRandomScalar(E.q);
    cpp_int blindB = generateRandomScalar(E.q);

    EccPoint pubA = E.derivePublicKey(privA, blindA);
    EccPoint pubB = E.derivePublicKey(privB, blindB);

    EccPoint sharedA = E.multiplyBlinded(privA, pubB, generateRandomScalar(E.q));
    EccPoint sharedB = E.multiplyBlinded(privB, pubA, generateRandomScalar(E.q));

    std::cout << "ECDH\n";
    std::cout << "QA.x = " << bigIntToHex(pubA.x) << "\n";
    std::cout << "QA.y = " << bigIntToHex(pubA.y) << "\n";
    std::cout << "QB.x = " << bigIntToHex(pubB.x) << "\n";
    std::cout << "QB.y = " << bigIntToHex(pubB.y) << "\n";
    std::cout << "KA.x = " << bigIntToHex(sharedA.x) << "\n";
    std::cout << "KB.x = " << bigIntToHex(sharedB.x) << "\n";
    std::cout << "ECDH equal: " << (sharedA.x == sharedB.x ? "YES" : "NO") << "\n\n";

    cpp_int messageHash = hexToBigInt("123456789ABCDEF");

    cpp_int blindK = generateRandomScalar(E.q);
    DigitalSignature sig = createSignature(E, privA, messageHash, blindK);

    std::cout << "STB 34.101.45\n";
    std::cout << "r = " << bigIntToHex(sig.r) << "\n";
    std::cout << "s = " << bigIntToHex(sig.s) << "\n";
    std::cout << "verify = " << (checkSignature(E, pubA, messageHash, sig) ? "VALID" : "INVALID") << "\n";

    DigitalSignature corruptedSig = sig;
    corruptedSig.s ^= 1;
    std::cout << "verify after s corruption = " 
              << (checkSignature(E, pubA, messageHash, corruptedSig) ? "VALID" : "INVALID") << "\n\n";

    cpp_int testPriv = privA;
    cpp_int testBlind = generateRandomScalar(E.q);
    
    EccPoint normalResult = E.scalarMultiply(testPriv, E.G);
    EccPoint blindedResult = E.multiplyBlinded(testPriv, E.G, testBlind);
    
    std::cout << "Point Blinding\n";
    std::cout << "d*G == d*(G+R)-d*R: "
              << ((normalResult.x == blindedResult.x && normalResult.y == blindedResult.y) ? "YES" : "NO")
              << "\n";

    return 0;
}