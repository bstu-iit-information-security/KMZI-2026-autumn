#include "eddsa.hpp"
#include <stdexcept>
#include <cstring>

namespace lab3 {

static const cpp_int P25519 = (cpp_int(1) << 255) - 19;
static const cpp_int Q_ORDER =
    (cpp_int(1) << 252) +
    cpp_int("27742317777372353535851937790883648493");

static cpp_int computeD() {
    cpp_int inv121666 = Field::inv(121666);
    return Field::mul((P25519 - 121665) % P25519, inv121666);
}

static cpp_int fromLE(const uint8_t* buf, size_t len) {
    cpp_int v = 0;
    for (size_t i = 0; i < len; ++i) v |= cpp_int(buf[i]) << (8 * i);
    return v;
}

static void toLE(const cpp_int& v, uint8_t* buf, size_t len) {
    cpp_int t = v;
    for (size_t i = 0; i < len; ++i) {
        buf[i] = static_cast<uint8_t>((t & 0xFF).convert_to<unsigned>());
        t >>= 8;
    }
}

EdDSA::EdDSA(const Ed25519Curve& curve) : curve_(curve) {}

std::array<uint8_t, 32> EdDSA::compress(const EdPoint& P) {
    cpp_int x, y;
    Ed25519Curve::toAffine(P, x, y);
    std::array<uint8_t, 32> out;
    toLE(y, out.data(), 32);

    unsigned xbit = static_cast<unsigned>((x & 1).convert_to<unsigned>());
    out[31] = (out[31] & 0x7F) | (xbit << 7);
    return out;
}

EdPoint EdDSA::decompress(const std::array<uint8_t, 32>& bytes) {
    cpp_int y = fromLE(bytes.data(), 32);
    y &= ((cpp_int(1) << 255) - 1);
    unsigned sign = (bytes[31] >> 7) & 1;

    if (y >= P25519) throw std::runtime_error("bad y");

    cpp_int d = computeD();
    cpp_int y2 = Field::mul(y, y);
    cpp_int num = Field::sub(y2, 1);
    cpp_int den = Field::add(Field::mul(d, y2), 1);
    cpp_int x2 = Field::mul(num, Field::inv(den));

    cpp_int x = Field::pow(x2, (P25519 + 3) / 8);
    if (Field::mul(x, x) != x2) {
        cpp_int sqrtM1 = Field::pow(2, (P25519 - 1) / 4);
        x = Field::mul(x, sqrtM1);
    }
    if (Field::mul(x, x) != x2) throw std::runtime_error("no sqrt");

    unsigned xbit = static_cast<unsigned>((x & 1).convert_to<unsigned>());
    if (xbit != sign) x = Field::sub(0, x);
    return EdPoint(x, y, 1);
}

Ed25519KeyPair EdDSA::keygen(const std::array<uint8_t, 32>& seed) {
    std::vector<uint8_t> seedVec(seed.begin(), seed.end());
    auto h = SHA512::hash(seedVec);

    std::array<uint8_t, 32> a;
    std::memcpy(a.data(), h.data(), 32);
    a[0] &= 248; a[31] &= 127; a[31] |= 64;

    cpp_int d = fromLE(a.data(), 32);

    Ed25519KeyPair kp;
    kp.d = d;
    std::memcpy(kp.hB.data(), h.data() + 32, 32);
    kp.A = Ed25519Curve::scalarMul(d, curve_.G());
    kp.publicBytes = compress(kp.A);
    return kp;
}

cpp_int EdDSA::hashToScalar(const std::array<uint8_t, 64>& h) {
    cpp_int v = 0;
    for (int i = 63; i >= 0; --i) v = (v << 8) | h[i];
    return v % Q_ORDER;
}

Ed25519Signature EdDSA::sign(const Ed25519KeyPair& key,
                             const std::vector<uint8_t>& message) {
    std::vector<uint8_t> buf(key.hB.begin(), key.hB.end());
    buf.insert(buf.end(), message.begin(), message.end());
    auto h = SHA512::hash(buf);
    cpp_int r = hashToScalar(h);

    EdPoint R = Ed25519Curve::scalarMul(r, curve_.G());
    auto RBytes = compress(R);

    std::vector<uint8_t> buf2;
    buf2.insert(buf2.end(), RBytes.begin(), RBytes.end());
    buf2.insert(buf2.end(), key.publicBytes.begin(), key.publicBytes.end());
    buf2.insert(buf2.end(), message.begin(), message.end());
    auto h2 = SHA512::hash(buf2);
    cpp_int k = hashToScalar(h2);

    cpp_int S = (r + k * key.d) % Q_ORDER;

    Ed25519Signature sig;
    sig.R = RBytes;
    sig.S = S;
    return sig;
}

bool EdDSA::verify(const std::array<uint8_t, 32>& publicKey,
                   const std::vector<uint8_t>& message,
                   const Ed25519Signature& sig) {
    if (sig.S < 0 || sig.S >= Q_ORDER) return false;
    try {
        EdPoint A = decompress(publicKey);
        EdPoint R = decompress(sig.R);

        std::vector<uint8_t> buf;
        buf.insert(buf.end(), sig.R.begin(), sig.R.end());
        buf.insert(buf.end(), publicKey.begin(), publicKey.end());
        buf.insert(buf.end(), message.begin(), message.end());
        auto h = SHA512::hash(buf);
        cpp_int k = hashToScalar(h);

        EdPoint lhs = Ed25519Curve::scalarMul(sig.S, curve_.G());
        EdPoint rhs = Ed25519Curve::add(R, Ed25519Curve::scalarMul(k, A));

        cpp_int lx = Field::mul(lhs.X, rhs.Z);
        cpp_int rx = Field::mul(rhs.X, lhs.Z);
        cpp_int ly = Field::mul(lhs.Y, rhs.Z);
        cpp_int ry = Field::mul(rhs.Y, lhs.Z);
        return ctEqual(lx, rx) && ctEqual(ly, ry);
    } catch (...) {
        return false;
    }
}

}