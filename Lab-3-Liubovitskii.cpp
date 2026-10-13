#include <iostream>
#include <string>
#include <stdexcept>
#include <boost/multiprecision/cpp_int.hpp>

using namespace std;
using BigInt = boost::multiprecision::uint256_t;
using BigInt512 = boost::multiprecision::uint512_t;

struct Point {
    BigInt x;
    BigInt y;
    bool is_inf;

    Point() : x(0), y(0), is_inf(true) {}
    Point(BigInt _x, BigInt _y) : x(_x), y(_y), is_inf(false) {}
};

const BigInt p("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
const BigInt a = p - 3; 
const BigInt b("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
const BigInt q("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
const Point  G(BigInt("0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
    BigInt("0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));

BigInt ModAdd(BigInt x, BigInt y, BigInt m) {

    BigInt512 x_wide = x;
    BigInt512 y_wide = y;
    BigInt512 m_wide = m;

    return BigInt((x_wide + y_wide) % m_wide);
}

BigInt ModSub(BigInt x, BigInt y, BigInt m) {
    if (x >= y) return (x - y) % m;
    return (m - ((y - x) % m)) % m;
}

BigInt ModMul(BigInt x, BigInt y, BigInt m) {
    BigInt512 x_wide = x;
    BigInt512 y_wide = y;
    BigInt512 m_wide = m;

    return BigInt((x_wide * y_wide) % m_wide);
}

BigInt SecureInvert(BigInt base, BigInt m) {
    BigInt result = 1;
    BigInt exp = m - 2;
    BigInt current_base = base % m;

    for (int i = 0; i < 256; i++) {
        BigInt bit = bit_test(exp, i) ? 1 : 0;
        BigInt dummy = ModMul(result, current_base, m);
        result = ModAdd(ModMul(dummy, bit, m), ModMul(result, 1 - bit, m), m);

        current_base = ModMul(current_base, current_base, m);
    }
    return result;
}

Point PointAdd(const Point& P1, const Point& P2) {
    if (P1.is_inf) return P2;
    if (P2.is_inf) return P1;

    if (P1.x == P2.x) {
        if (P1.y == P2.y) {
            if (P1.y == 0) return Point();
            BigInt num = ModAdd(ModMul(3, ModMul(P1.x, P1.x, p), p), a, p);
            BigInt den = SecureInvert(ModMul(2, P1.y, p), p); 
            BigInt s = ModMul(num, den, p);

            BigInt x3 = ModSub(ModSub(ModMul(s, s, p), P1.x, p), P1.x, p);
            BigInt y3 = ModSub(ModMul(s, ModSub(P1.x, x3, p), p), P1.y, p);
            return Point(x3, y3);
        }
        return Point(); // P1 = -P2
    }

    BigInt num = ModSub(P2.y, P1.y, p);
    BigInt den = SecureInvert(ModSub(P2.x, P1.x, p), p);
    BigInt s = ModMul(num, den, p);

    BigInt x3 = ModSub(ModSub(ModMul(s, s, p), P1.x, p), P2.x, p);
    BigInt y3 = ModSub(ModMul(s, ModSub(P1.x, x3, p), p), P1.y, p);
    return Point(x3, y3);
}

Point SecureMultiply(BigInt d, Point P) {
    Point R0;
    Point R1 = P;

    for (int i = 0; i < 256; i++) {
        int bit = bit_test(d, i) ? 1 : 0;

        if (bit) {
            R0 = PointAdd(R0, R1);
        }
        R1 = PointAdd(R1, R1);
    }
    return R0;
}


void GenerateKeys(BigInt private_key, Point& public_key) {
    public_key = SecureMultiply(private_key, G);
}

BigInt ECDH_SharedSecret(BigInt my_private, const Point& other_public) {
    Point shared = SecureMultiply(my_private, other_public);
    return shared.x;
}

struct Signature { BigInt r, s; };

Signature ECDSA_Sign(BigInt hash, BigInt d, BigInt k) {
    Signature sig;
    Point C = SecureMultiply(k, G);

    sig.r = C.x % q;
    if (sig.r == 0) throw runtime_error("Invalid r");

    BigInt k_inv = SecureInvert(k, q);
    BigInt rd = ModMul(sig.r, d, q);
    BigInt e_rd = ModAdd(hash, rd, q);

    sig.s = ModMul(k_inv, e_rd, q);
    if (sig.s == 0) throw runtime_error("Invalid s");

    return sig;
}

bool ECDSA_Verify(BigInt hash, Signature sig, Point Q) {
    if (sig.r <= 0 || sig.r >= q || sig.s <= 0 || sig.s >= q) return false;

    BigInt w = SecureInvert(sig.s, q);
    BigInt u1 = ModMul(hash, w, q);
    BigInt u2 = ModMul(sig.r, w, q);

    Point u1G = SecureMultiply(u1, G);
    Point u2Q = SecureMultiply(u2, Q);
    Point C_prime = PointAdd(u1G, u2Q);

    BigInt R = C_prime.x % q;
    return R == sig.r;
}

int main() {
    cout << hex << uppercase;
    cout << "--- ИНИЦИАЛИЗАЦИЯ И ТЕСТИРОВАНИЕ ПРОТОКОЛОВ ---\n\n";

    BigInt Alice_d("0x1122334455667788990011223344556677889900112233445566778899001122");
    BigInt Bob_d("0xAABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899");

    Point Alice_Q, Bob_Q;
    GenerateKeys(Alice_d, Alice_Q);
    GenerateKeys(Bob_d, Bob_Q);

    cout << "[ECDH] Открытый ключ Алисы Q_A (X): " << Alice_Q.x << "\n";
    cout << "[ECDH] Открытый ключ Боба  Q_B (X): " << Bob_Q.x << "\n";

    BigInt Alice_Secret = ECDH_SharedSecret(Alice_d, Bob_Q);
    BigInt Bob_Secret = ECDH_SharedSecret(Bob_d, Alice_Q);

    cout << "[ECDH] Общий секрет Алисы: " << Alice_Secret << "\n";
    cout << "[ECDH] Общий секрет Боба:  " << Bob_Secret << "\n";
    cout << "[ECDH] Успех: " << (Alice_Secret == Bob_Secret ? "СЕКРЕТЫ СОВПАДАЮТ" : "ОШИБКА") << "\n\n";

    BigInt Hash_Msg("0xBA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"); 
    BigInt k_ephemeral("0x4455667788990011223344556677889900112233445566778899001122334455");

    cout << "[ECDSA] Подписание хэша сообщения...\n";
    Signature sig = ECDSA_Sign(Hash_Msg, Alice_d, k_ephemeral);
    cout << "        r: " << sig.r << "\n";
    cout << "        s: " << sig.s << "\n";

    cout << "[ECDSA] Верификация корректной подписи: ";
    bool is_valid = ECDSA_Verify(Hash_Msg, sig, Alice_Q);
    cout << (is_valid ? "ПОДПИСЬ ВЕРНА" : "ПОДПИСЬ НЕВЕРНА") << "\n";

    cout << "[ECDSA] Внесение искажения в параметр 's'...\n";
    sig.s = sig.s ^ BigInt("0xFF"); 
    cout << "[ECDSA] Верификация искаженной подписи: ";
    bool is_invalid = ECDSA_Verify(Hash_Msg, sig, Alice_Q);
    cout << (is_invalid ? "ПОДПИСЬ ВЕРНА" : "ПОДПИСЬ ОТВЕРГНУТА") << "\n";
}