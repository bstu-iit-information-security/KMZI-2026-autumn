#include "CryptoProtocols.h"
#include <random>

CryptoProtocols::CryptoProtocols(const Curves& curve) : curve_(curve) {}

//  ECDH 
CryptoProtocols::u64 CryptoProtocols::ecdhSharedSecret(u64 d_priv, const Point& Q_peer) const {
    if (!curve_.isOnCurve(Q_peer) || Q_peer.infinity)
        throw std::invalid_argument("ECDH: peer public key is invalid");
    if (!isValidPrivateKey(d_priv))
        throw std::invalid_argument("ECDH: private key out of range");

    Point S = curve_.mulConstantTime(d_priv, Q_peer);
    if (S.infinity)
        throw std::runtime_error("ECDH: shared secret is point at infinity");
    return S.x;
}

// Генерация ключей 
CryptoProtocols::KeyPair CryptoProtocols::generateKeyPair() const {
    if (!curve_.validateInvariants())
        throw std::runtime_error("KeyGen: curve invariants broken");

    KeyPair kp;
    do {
        kp.d = randomScalar();
    } while (kp.d == 0);
    kp.Q = curve_.mulConstantTime(kp.d, curve_.G());

    if (kp.Q.infinity || !curve_.isOnCurve(kp.Q))
        throw std::runtime_error("KeyGen: generated Q is invalid");

    return kp;
}

// Подпись ГОСТ + Fault Injection 
CryptoProtocols::Signature CryptoProtocols::sign(
    u64 d_priv, const Point& Q_pub, u64 hash_e) const
{
    // 1. Инварианты кривой 
    if (!curve_.validateInvariants())
        throw std::runtime_error("FaultInjection: curve invariants broken");

    // 2. Приватный ключ в допустимом диапазоне
    if (!isValidPrivateKey(d_priv))
        throw std::invalid_argument("FaultInjection: invalid private key");

    // 3. Q_pub лежит на кривой: y² == x³ + a·x + b (mod p)
    if (Q_pub.infinity || !curve_.isOnCurve(Q_pub))
        throw std::runtime_error("FaultInjection: Q_pub is not on curve");

    // 4. Перевычисление Q = d·G и constant-time сравнение с Q_pub
    Point Q_check = curve_.mulConstantTime(d_priv, curve_.G());
    if (Q_check.infinity)
        throw std::runtime_error("FaultInjection: d·G is infinity");
    if (!curve_.constantTimeEqual(Q_check, Q_pub))
        throw std::runtime_error("FaultInjection: Q != d·G");

    const u64 q = curve_.q();
    u64 e = hash_e % q;
    u64 r, s;

    do {
        u64 k = randomScalar();
        Point C = curve_.mulConstantTime(k, curve_.G());
        if (C.infinity) continue;

        r = C.x % q;
        if (r == 0) continue;

        u64 rd = mulmodQ(r, d_priv, q);
        u64 ke = mulmodQ(k, e, q);
        s = addmodQ(rd, ke, q);
    } while (s == 0);

    return Signature{ r, s };
}

bool CryptoProtocols::verify(const Point& Q_pub, u64 hash_e,
    const Signature& sig) const
{
    // Fault Injection: валидируем входные данные
    if (!curve_.validateInvariants()) return false;
    if (sig.r == 0 || sig.r >= curve_.q() ||
        sig.s == 0 || sig.s >= curve_.q()) return false;
    if (Q_pub.infinity || !curve_.isOnCurve(Q_pub)) return false;

    const u64 q = curve_.q();
    u64 e = hash_e % q;
    if (e == 0) e = 1;

    u64 v = modInverseQ(e, q);
    u64 z1 = mulmodQ(sig.s, v, q);
    u64 z2 = submodQ(0, mulmodQ(sig.r, v, q), q);

    Point C = curve_.add(curve_.mulConstantTime(z1, curve_.G()),
        curve_.mulConstantTime(z2, Q_pub));
    if (C.infinity) return false;

    return (C.x % q) == sig.r;
}

bool CryptoProtocols::isValidPrivateKey(u64 d) const {
    return d >= 1 && d < curve_.q();
}

CryptoProtocols::u64 CryptoProtocols::randomScalar() const {
    static thread_local std::mt19937_64 rng{ std::random_device{}() };
    std::uniform_int_distribution<u64> dist(1, curve_.q() - 1);
    return dist(rng);
}

CryptoProtocols::u64 CryptoProtocols::mulmodQ(u64 a, u64 b, u64 q) {
    u64 result = 0;
    a %= q;
    while (b) {
        if (b & 1ULL)
            result = (result >= q - a) ? (result - (q - a)) : (result + a);
        a = (a >= q - a) ? (a - (q - a)) : (a + a);
        b >>= 1;
    }
    return result;
}

CryptoProtocols::u64 CryptoProtocols::addmodQ(u64 a, u64 b, u64 q) {
    a %= q; b %= q;
    return (a >= q - b) ? (a - (q - b)) : (a + b);
}

CryptoProtocols::u64 CryptoProtocols::submodQ(u64 a, u64 b, u64 q) {
    a %= q; b %= q;
    return (a >= b) ? (a - b) : (a + q - b);
}

CryptoProtocols::u64 CryptoProtocols::modInverseQ(u64 a, u64 q) {
    long long t = 0, newT = 1;
    long long r = static_cast<long long>(q);
    long long newR = static_cast<long long>(a % q);
    while (newR != 0) {
        long long qt = r / newR;
        long long tmpT = t - qt * newT; t = newT; newT = tmpT;
        long long tmpR = r - qt * newR; r = newR; newR = tmpR;
    }
    if (r != 1) throw std::runtime_error("modInverseQ: not invertible");
    if (t < 0) t += static_cast<long long>(q);
    return static_cast<u64>(t);
}