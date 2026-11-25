#pragma once
#include "field.hpp"

namespace lab3 {

struct EdPoint {
    cpp_int X, Y, Z;

    EdPoint() : X(0), Y(1), Z(1) {}
    EdPoint(const cpp_int& x, const cpp_int& y, const cpp_int& z) : X(x), Y(y), Z(z) {}

    bool isIdentity() const { return X == 0 && Y == Z; }
};

class Ed25519Curve {
public:
    Ed25519Curve();

    const cpp_int& p() const { return p_; }
    const cpp_int& d() const { return d_; }
    const cpp_int& q() const { return q_; }
    const EdPoint& G() const { return G_; }

    static const cpp_int& dCached();
    
    static EdPoint add(const EdPoint& P, const EdPoint& Q);

    static EdPoint scalarMul(const cpp_int& k, const EdPoint& P);

    static void cswap(EdPoint& a, EdPoint& b, unsigned bit);

    static void toAffine(const EdPoint& P, cpp_int& x, cpp_int& y);

    static bool isValid(const EdPoint& P);

private:
    cpp_int p_, d_, q_;
    EdPoint G_;
};

bool ctEqual(const cpp_int& a, const cpp_int& b);

}