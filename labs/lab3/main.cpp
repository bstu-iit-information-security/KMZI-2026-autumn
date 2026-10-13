#include "ec_curve.h"
#include "ec_proto.h"
#include "ec_ct.h"
#include <iostream>

using namespace ecc;

int main() {
    const CurveParams c = load_secp256k1();
    Point G; G.x = c.gx; G.y = c.gy; G.inf = false;

    const KeyPair A = keygen(c);
    const KeyPair B = keygen(c);
    std::cout << "Q_A = " << to_hex(A.Q.x) << " " << to_hex(A.Q.y) << "\n";
    std::cout << "Q_B = " << to_hex(B.Q.x) << " " << to_hex(B.Q.y) << "\n";

    const BigInt K_A = ecdh_shared(A.d, B.Q, c);
    const BigInt K_B = ecdh_shared(B.d, A.Q, c);
    std::cout << "shared_A = " << to_hex(K_A) << "\nshared_B = " << to_hex(K_B) << "\n";

    const std::string MSG_HEX = "68656c6c6f"; // тестовое сообщение hex
    const BigInt e = from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); // его хэш
    const Signature sig = ecdsa_sign(e, A.d, generate_nonce(c), c);
    std::cout << "r = " << to_hex(sig.r) << "\ns = " << to_hex(sig.s) << "\n";
    std::cout << "verify = " << (ecdsa_verify(e, sig, A.Q, c) ? "true" : "false") << "\n";
    return 0;
}