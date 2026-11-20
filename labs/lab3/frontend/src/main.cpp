#include "eddsa.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

using namespace lab3;

static std::string hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) oss << std::setw(2) << (unsigned)data[i];
    return oss.str();
}

static std::vector<uint8_t> unhex(const std::string& s) {
    if (s.size() % 2) throw std::runtime_error("odd hex");
    std::vector<uint8_t> out(s.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned v = 0;
        std::stringstream ss; ss << std::hex << s.substr(2*i, 2);
        ss >> v;
        out[i] = (uint8_t)v;
    }
    return out;
}

static std::string cppintToHex32(const cpp_int& v) {
    uint8_t buf[32] = {0};
    cpp_int t = v;
    for (int i = 0; i < 32; ++i) { buf[i] = (uint8_t)(t & 0xFF).convert_to<unsigned>(); t >>= 8; }
    return hex(buf, 32);
}

int main(int argc, char** argv) {
    try {
        Ed25519Curve curve;
        EdDSA eddsa(curve);

        std::string msgHex;
        if (argc > 1) msgHex = argv[1];
        std::vector<uint8_t> msg = msgHex.empty() ? std::vector<uint8_t>{} : unhex(msgHex);

        // Фиксированный seed из RFC 8032 test 1
        auto seedVec = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        std::array<uint8_t, 32> seed;
        std::copy(seedVec.begin(), seedVec.end(), seed.begin());

        auto kp = eddsa.keygen(seed);
        auto sig = eddsa.sign(kp, msg);

        std::cout << "MSG:  " << msgHex << "\n";
        std::cout << "PUB:  " << hex(kp.publicBytes.data(), 32) << "\n";
        std::cout << "R:    " << hex(sig.R.data(), 32) << "\n";
        std::cout << "S:    " << cppintToHex32(sig.S) << "\n";
        std::cout << "VERIFY: " << (eddsa.verify(kp.publicBytes, msg, sig) ? "OK" : "FAIL") << "\n";

        Ed25519Signature bad = sig;
        bad.S ^= 1;
        std::cout << "VERIFY(tampered): "
                  << (eddsa.verify(kp.publicBytes, msg, bad) ? "ACCEPTED(!)" : "REJECTED") << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}