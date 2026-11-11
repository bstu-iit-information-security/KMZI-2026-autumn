#include "edwards.hpp"
#include <stdexcept>

namespace lab3 {

static const char* P_HEX =
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
    
static const char* D_HEX =
    "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3";
static const char* Q_HEX =
    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";

static const char* GX_HEX =
    "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
static const char* GY_HEX =
    "6666666666666666666666666666666666666666666666666666666666666658";

static cpp_int parseHex(const char* hex) {
    cpp_int v = 0;
    while (*hex) {
        char c = *hex++;
        unsigned digit;
        if (c >= '0' && c <= '9') digit = static_cast<unsigned>(c - '0');
        else if (c >= 'a' && c <= 'f') digit = static_cast<unsigned>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') digit = static_cast<unsigned>(c - 'A' + 10);
        else throw std::runtime_error("bad hex");
        v = (v << 4) + digit;
    }
    return v;
}

Ed25519Curve::Ed25519Curve() {
    p_ = parseHex(P_HEX);
    d_ = parseHex(D_HEX);
    q_ = parseHex(Q_HEX);
    Field::setModulus(p_);

    cpp_int gx = parseHex(GX_HEX);
    cpp_int gy = parseHex(GY_HEX);
    G_ = EdPoint(gx, gy, 1);

    if (!isValid(G_)) throw std::runtime_error("bad base point");
}

const cpp_int& Ed25519Curve::dCached() {
    static cpp_int d = [] {
        cpp_int inv121666 = Field::inv(121666);
        return Field::mul((Field::modulus() - 121665) % Field::modulus(), inv121666);
    }();
    return d;
}

EdPoint Ed25519Curve::add(const EdPoint& P, const EdPoint& Q) {
    cpp_int A = Field::mul(P.Z, Q.Z);
    cpp_int B = Field::mul(A, A);
    cpp_int C = Field::mul(P.X, Q.X);
    cpp_int D = Field::mul(P.Y, Q.Y);
    cpp_int E = Field::mul(dCached(), Field::mul(C, D));

    cpp_int F = Field::sub(B, E);
    cpp_int G = Field::add(B, E);

    cpp_int x1py1 = Field::add(P.X, P.Y);
    cpp_int x2py2 = Field::add(Q.X, Q.Y);
    cpp_int t = Field::sub(Field::sub(Field::mul(x1py1, x2py2), C), D);

    cpp_int X3 = Field::mul(Field::mul(A, F), t);
    cpp_int Y3 = Field::mul(Field::mul(A, G), Field::add(D, C));
    cpp_int Z3 = Field::mul(F, G);
    return EdPoint(X3, Y3, Z3);
}

void Ed25519Curve::cswap(EdPoint& a, EdPoint& b, unsigned bit) {
    cpp_int mask = Field::bitMask(bit);
    cpp_int dx = (a.X ^ b.X) & mask;
    cpp_int dy = (a.Y ^ b.Y) & mask;
    cpp_int dz = (a.Z ^ b.Z) & mask;
    a.X ^= dx; b.X ^= dx;
    a.Y ^= dy; b.Y ^= dy;
    a.Z ^= dz; b.Z ^= dz;
}

EdPoint Ed25519Curve::scalarMul(const cpp_int& k, const EdPoint& P) {
    EdPoint R0(0, 1, 1);
    EdPoint R1 = P;
    const int bits = 256;
    for (int i = bits - 1; i >= 0; --i) {
        unsigned b = static_cast<unsigned>(((k >> i) & 1).convert_to<unsigned long long>());
        cswap(R0, R1, b);
        R1 = add(R0, R1);
        R0 = add(R0, R0);
        cswap(R0, R1, b);
    }
    return R0;
}


void Ed25519Curve::toAffine(const EdPoint& P, cpp_int& x, cpp_int& y) {
    cpp_int zinv = Field::inv(P.Z);
    x = Field::mul(P.X, zinv);
    y = Field::mul(P.Y, zinv);
}

bool Ed25519Curve::isValid(const EdPoint& P) {
    if (P.Z == 0) return false;
    cpp_int x, y;
    toAffine(P, x, y);
    cpp_int x2 = Field::mul(x, x);
    cpp_int y2 = Field::mul(y, y);
    cpp_int lhs = Field::sub(y2, x2);
    cpp_int rhs = Field::add(1, Field::mul(dCached(), Field::mul(x2, y2)));
    return lhs == rhs;
}

bool ctEqual(const cpp_int& a, const cpp_int& b) {
    cpp_int x = a ^ b;

    unsigned nonzero = 0;
    for (unsigned i = 0; i < 256; ++i) {
        nonzero |= static_cast<unsigned>(((x >> i) & 1).convert_to<unsigned long long>());
    }
    return nonzero == 0;
}

}