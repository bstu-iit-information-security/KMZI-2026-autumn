#include "eddsa.hpp"
#include <iostream>
#include <sstream>
#include <string>

using namespace lab3;

static std::vector<uint8_t> unhex(const std::string& s) {
    std::vector<uint8_t> out(s.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned v = 0;
        std::stringstream ss; ss << std::hex << s.substr(2*i, 2);
        ss >> v;
        out[i] = (uint8_t)v;
    }
    return out;
}

static std::string hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) oss << std::setw(2) << (unsigned)data[i];
    return oss.str();
}

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::cerr << "FAIL: " << msg << "\n"; ++failures; } else { std::cerr << "PASS: " << msg << "\n"; } } while (0)

int main() {
    Ed25519Curve curve;
    EdDSA eddsa(curve);

    // --- Test 1: проверка базовой точки ---
    CHECK(Ed25519Curve::isValid(curve.G()), "base point is on curve");

    // --- Test 2: скалярное умножение q*G = O ---
    EdPoint qG = Ed25519Curve::scalarMul(curve.q(), curve.G());
    cpp_int qx, qy;
    Ed25519Curve::toAffine(qG, qx, qy);
    CHECK(qx == 0 && qy == 1, "q*G is identity");

    // --- Test 3: RFC 8032 test 1 (пустое сообщение) ---
    {
        std::vector<uint8_t> seedVec = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        std::array<uint8_t, 32> seed;
        std::copy(seedVec.begin(), seedVec.end(), seed.begin());

        auto kp = eddsa.keygen(seed);
        std::string pubHex = hex(kp.publicBytes.data(), 32);
        CHECK(pubHex == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
              "RFC 8032 test1 public key");

        std::vector<uint8_t> msg;
        auto sig = eddsa.sign(kp, msg);
        std::string rHex = hex(sig.R.data(), 32);
        CHECK(rHex == "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "RFC 8032 test1 R");

        CHECK(eddsa.verify(kp.publicBytes, msg, sig), "RFC 8032 test1 verify");
    }

    // --- Test 4: детерминированность подписи ---
    {
        std::vector<uint8_t> seedVec = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        std::array<uint8_t, 32> seed;
        std::copy(seedVec.begin(), seedVec.end(), seed.begin());
        auto kp = eddsa.keygen(seed);
        std::vector<uint8_t> msg = {1,2,3};
        auto s1 = eddsa.sign(kp, msg);
        auto s2 = eddsa.sign(kp, msg);
        CHECK(s1.R == s2.R && s1.S == s2.S, "deterministic signing");
        CHECK(eddsa.verify(kp.publicBytes, msg, s1), "sign/verify roundtrip");
    }

    // --- Test 5: подпись отвергается при искажении S ---
    {
        std::vector<uint8_t> seedVec = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        std::array<uint8_t, 32> seed;
        std::copy(seedVec.begin(), seedVec.end(), seed.begin());
        auto kp = eddsa.keygen(seed);
        std::vector<uint8_t> msg = {0xde, 0xad, 0xbe, 0xef};
        auto sig = eddsa.sign(kp, msg);
        CHECK(eddsa.verify(kp.publicBytes, msg, sig), "verify valid");

        auto bad = sig;
        bad.S ^= 1;
        CHECK(!eddsa.verify(kp.publicBytes, msg, bad), "tampered S rejected");
    }

    // --- Test 6: CSWAP constant-time (swap корректен для бита 0 и 1) ---
    {
        EdPoint a(cpp_int(1), cpp_int(2), cpp_int(3));
        EdPoint b(cpp_int(10), cpp_int(20), cpp_int(30));
        EdPoint a1 = a, b1 = b;
        Ed25519Curve::cswap(a1, b1, 0);
        CHECK(a1.X == 1 && b1.X == 10, "cswap bit=0 no-op");

        EdPoint a2 = a, b2 = b;
        Ed25519Curve::cswap(a2, b2, 1);
        CHECK(a2.X == 10 && b2.X == 1, "cswap bit=1 swaps");
    }

    // --- Test 7: (d1 + d2)*G == d1*G + d2*G ---
    {
        cpp_int d1 = 123456789;
        cpp_int d2 = 987654321;
        EdPoint lhs = Ed25519Curve::scalarMul(d1 + d2, curve.G());
        EdPoint rhs = Ed25519Curve::add(
            Ed25519Curve::scalarMul(d1, curve.G()),
            Ed25519Curve::scalarMul(d2, curve.G()));

        cpp_int lx, ly, rx, ry;
        Ed25519Curve::toAffine(lhs, lx, ly);
        Ed25519Curve::toAffine(rhs, rx, ry);
        CHECK(lx == rx && ly == ry, "distributivity of scalar mul");
    }

    std::cerr << (failures == 0 ? "\nALL TESTS PASSED\n" : "\nSOME TESTS FAILED\n");
    return failures == 0 ? 0 : 1;
}