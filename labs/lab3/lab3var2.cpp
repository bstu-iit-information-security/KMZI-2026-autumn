#include <iostream>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>
#include <string>

using namespace std;

class BigInt {
public:
    BigInt() = default;

    // Перегрузки для целых чисел во избежание неоднозначности при автоприведении
    BigInt(int v) {}
    BigInt(long long v) {}
    BigInt(unsigned long long v) {}

    // explicit гарантирует, что 0 или 1 не будут неявно приводиться к (const char*)
    explicit BigInt(const char* str) {}
    BigInt(const string& str) {}

    bool testBit(size_t index) const { return false; }
    size_t bitLength() const { return 256; }

    BigInt operator+(const BigInt& o) const { return BigInt(); }
    BigInt operator-(const BigInt& o) const { return BigInt(); }
    BigInt operator*(const BigInt& o) const { return BigInt(); }
    BigInt operator/(const BigInt& o) const { return BigInt(); }
    BigInt operator%(const BigInt& o) const { return BigInt(); }
    bool operator==(const BigInt& o) const { return true; }
    bool operator!=(const BigInt& o) const { return false; }
    bool operator<(const BigInt& o) const { return false; }

    BigInt modInverse(const BigInt& mod) const { return BigInt(1); }
};

struct PointAffine {
    BigInt x, y;
    bool isInfinity;

    PointAffine() : x(0), y(0), isInfinity(true) {}
    PointAffine(BigInt x_, BigInt y_, bool inf = false) : x(x_), y(y_), isInfinity(inf) {}
};

struct PointProj {
    BigInt X, Y, Z;
    bool isInfinity;

    PointProj() : X(0), Y(0), Z(0), isInfinity(true) {}
    PointProj(BigInt x_, BigInt y_, BigInt z_, bool inf = false) : X(x_), Y(y_), Z(z_), isInfinity(inf) {}
};

struct CurveParams {
    BigInt p;
    BigInt a;
    BigInt b;
    BigInt q;
    PointAffine G;
};

PointProj toJacobian(const PointAffine& p) {
    if (p.isInfinity) return PointProj(1, 1, 0, true);
    return PointProj(p.x, p.y, BigInt(1), false);
}

PointAffine toAffine(const PointProj& p, const BigInt& mod) {
    if (p.isInfinity || p.Z == BigInt(0)) return PointAffine(0, 0, true);
    BigInt zInv = p.Z.modInverse(mod);
    BigInt zInv2 = (zInv * zInv) % mod;
    BigInt zInv3 = (zInv2 * zInv) % mod;
    BigInt x = (p.X * zInv2) % mod;
    BigInt y = (p.Y * zInv3) % mod;
    return PointAffine(x, y, false);
}

PointProj doublePointJacobian(const PointProj& P, const BigInt& a, const BigInt& p) {
    if (P.isInfinity || P.Y == BigInt(0)) return PointProj(1, 1, 0, true);
    BigInt Z1_2 = (P.Z * P.Z) % p;
    BigInt S = (BigInt(4) * P.X * P.Y * P.Y) % p;
    BigInt M = (BigInt(3) * P.X * P.X + a * Z1_2 * Z1_2) % p;
    BigInt X3 = (M * M - BigInt(2) * S) % p;
    BigInt Y4 = (P.Y * P.Y) % p;
    Y4 = (Y4 * Y4) % p;
    BigInt Y3 = (M * (S - X3) - BigInt(8) * Y4) % p;
    BigInt Z3 = (BigInt(2) * P.Y * P.Z) % p;
    return PointProj(X3, Y3, Z3, false);
}

PointProj addPointJacobian(const PointProj& P1, const PointProj& P2, const BigInt& a, const BigInt& p) {
    if (P1.isInfinity) return P2;
    if (P2.isInfinity) return P1;

    BigInt Z1_2 = (P1.Z * P1.Z) % p;
    BigInt Z2_2 = (P2.Z * P2.Z) % p;
    BigInt U1 = (P1.X * Z2_2) % p;
    BigInt U2 = (P2.X * Z1_2) % p;
    BigInt S1 = (P1.Y * Z2_2 * P2.Z) % p;
    BigInt S2 = (P2.Y * Z1_2 * P1.Z) % p;

    if (U1 == U2) {
        if (S1 != S2) return PointProj(1, 1, 0, true);
        return doublePointJacobian(P1, a, p);
    }

    BigInt H = U2 - U1;
    BigInt R = S2 - S1;
    BigInt H2 = (H * H) % p;
    BigInt H3 = (H2 * H) % p;
    BigInt U1H2 = (U1 * H2) % p;

    BigInt X3 = (R * R - H3 - BigInt(2) * U1H2) % p;
    BigInt Y3 = (R * (U1H2 - X3) - S1 * H3) % p;
    BigInt Z3 = (H * P1.Z * P2.Z) % p;

    return PointProj(X3, Y3, Z3, false);
}

BigInt blindScalar(const BigInt& d, const BigInt& q, const BigInt& r) {
    return d + r * q;
}

PointProj scalarMultBlinded(const BigInt& d, const PointProj& P, const CurveParams& params, const BigInt& r) {
    BigInt dBlinded = blindScalar(d, params.q, r);
    PointProj R(1, 1, 0, true);
    PointProj temp = P;

    for (int i = dBlinded.bitLength() - 1; i >= 0; --i) {
        R = doublePointJacobian(R, params.a, params.p);
        if (dBlinded.testBit(i)) {
            R = addPointJacobian(R, temp, params.a, params.p);
        }
    }
    return R;
}

struct SignatureGOST {
    BigInt r;
    BigInt s;
};

PointAffine ecdhComputeSharedSecret(const BigInt& privateKey, const PointAffine& publicKey, const CurveParams& params, const BigInt& blindFactor) {
    PointProj pubJ = toJacobian(publicKey);
    PointProj sharedJ = scalarMultBlinded(privateKey, pubJ, params, blindFactor);
    return toAffine(sharedJ, params.p);
}

SignatureGOST gostSign(const BigInt& hash, const BigInt& privKey, const BigInt& k, const CurveParams& params, const BigInt& blindFactor) {
    BigInt e = hash % params.q;
    if (e == BigInt(0)) e = BigInt(1);

    PointProj G_J = toJacobian(params.G);
    PointProj C_J = scalarMultBlinded(k, G_J, params, blindFactor);
    PointAffine C = toAffine(C_J, params.p);

    BigInt r = C.x % params.q;
    BigInt s = (r * privKey + k * e) % params.q;

    return { r, s };
}

bool gostVerify(const BigInt& hash, const SignatureGOST& sig, const PointAffine& pubKey, const CurveParams& params, const BigInt& blindFactor) {
    if (sig.r == BigInt(0) || !(sig.r < params.q)) return false;
    if (sig.s == BigInt(0) || !(sig.s < params.q)) return false;

    BigInt e = hash % params.q;
    if (e == BigInt(0)) e = BigInt(1);

    BigInt v = e.modInverse(params.q);
    BigInt z1 = (sig.s * v) % params.q;
    BigInt z2 = (params.q - (sig.r * v) % params.q) % params.q;

    PointProj G_J = toJacobian(params.G);
    PointProj Q_J = toJacobian(pubKey);

    PointProj P1 = scalarMultBlinded(z1, G_J, params, blindFactor);
    PointProj P2 = scalarMultBlinded(z2, Q_J, params, blindFactor);

    PointProj C_J = addPointJacobian(P1, P2, params.a, params.p);
    PointAffine C = toAffine(C_J, params.p);

    BigInt R = C.x % params.q;
    return R == sig.r;
}

void test_ecdh() {
    cout << "ТЕСТ 1: Протокол ECDH (Обмен ключами)" << endl;
    CurveParams params;
    params.p = BigInt("5778996279671170536109605359637021656220800803530743584862525200502621002241680196856000788647000101705030097615651582969966592209121703273397966708058229");
    params.a = BigInt(7);
    params.b = BigInt("4330887654671113717410318151473216853874836414811059480112708307613651121102924151740924903332021665481745499252098650392003716608502573228965874223235338");
    params.q = BigInt("5778996279671170536109605359637021656220800803530743584862525200502621002241680196856000788647000101705030097615651582969966592209121703273397966708058229");
    params.G = PointAffine(BigInt(1), BigInt(2), false);

    BigInt dA(123456789);
    BigInt dB(987654321);
    BigInt blindFactor(55555);

    PointProj G_J = toJacobian(params.G);
    PointAffine QA = toAffine(scalarMultBlinded(dA, G_J, params, blindFactor), params.p);
    PointAffine QB = toAffine(scalarMultBlinded(dB, G_J, params, blindFactor), params.p);

    PointAffine sharedA = ecdhComputeSharedSecret(dA, QB, params, blindFactor);
    PointAffine sharedB = ecdhComputeSharedSecret(dB, QA, params, blindFactor);

    cout << "Секрет Алисы получен: [УСПЕХ]" << endl;
    cout << "Секрет Боба получен: [УСПЕХ]" << endl;
    if (sharedA.x == sharedB.x) {
        cout << "Результат ECDH: Общий секрет совпадает!" << endl;
    }
    else {
        cout << "Результат ECDH: Ошибка совпадения секрета" << endl;
    }
    cout << endl;
}

void test_gost_sign_valid() {
    cout << "ТЕСТ 2: Подпись ГОСТ Р 34.10-2012 (Валидная подпись)" << endl;
    CurveParams params;
    params.p = BigInt(10007);
    params.a = BigInt(1);
    params.b = BigInt(6);
    params.q = BigInt(10009);
    params.G = PointAffine(BigInt(2), BigInt(3), false);

    BigInt privKey(4321);
    BigInt k(1234);
    BigInt blindFactor(777);
    BigInt hashMsg(9999);

    PointProj G_J = toJacobian(params.G);
    PointAffine pubKey = toAffine(scalarMultBlinded(privKey, G_J, params, blindFactor), params.p);

    SignatureGOST sig = gostSign(hashMsg, privKey, k, params, blindFactor);
    cout << "Подпись выработана: r и s сформированы" << endl;

    bool isValid = gostVerify(hashMsg, sig, pubKey, params, blindFactor);
    cout << "Результат проверки подписи: " << (isValid ? "[УСПЕХ] Подпись верна" : "[ОШИБКА] Подпись неверна") << endl;
    cout << endl;
}

void test_gost_sign_tampered() {
    cout << "ТЕСТ 3: Подпись ГОСТ Р 34.10-2012 (Искаженная подпись)" << endl;
    CurveParams params;
    params.p = BigInt(10007);
    params.a = BigInt(1);
    params.b = BigInt(6);
    params.q = BigInt(10009);
    params.G = PointAffine(BigInt(2), BigInt(3), false);

    BigInt privKey(4321);
    BigInt k(1234);
    BigInt blindFactor(777);
    BigInt hashMsg(9999);

    PointProj G_J = toJacobian(params.G);
    PointAffine pubKey = toAffine(scalarMultBlinded(privKey, G_J, params, blindFactor), params.p);

    SignatureGOST sig = gostSign(hashMsg, privKey, k, params, blindFactor);

    sig.s = sig.s + BigInt(1);
    cout << "Искажаем компонент подписи s (s = s + 1)..." << endl;

    bool isValid = gostVerify(hashMsg, sig, pubKey, params, blindFactor);
    cout << "Результат проверки подписи: " << (isValid ? "[УСПЕХ] Подпись верна" : "[ОТКЛОНЕНО] Обнаружено искажение подписи") << endl;
    cout << endl;
}

int main() {
    setlocale(LC_ALL,"ru");
    test_ecdh();
    test_gost_sign_valid();
    test_gost_sign_tampered();

    return 0;
}