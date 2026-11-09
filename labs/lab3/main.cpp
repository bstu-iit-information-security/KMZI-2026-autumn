#include <iostream>
#include "ec_algebra.h"
#include "protocols.h"

using namespace std;
using namespace ec;
using namespace protocols;

int main() {
    Curve curve;
    curve.p = BigInt("23");
    curve.a = BigInt("1");
    curve.b = BigInt("1");
    curve.G = Point(BigInt("3"), BigInt("10"));
    curve.q = BigInt("7");

    cout << "ECDSA | Аффинные | Constant-time инверсия (Ферма)" << endl;
    print_point("G", curve.G);
    cout << "q = " << curve.q.to_hex() << endl << endl;

    if (!is_on_curve(curve.G, curve)) { cerr << "[ERR] G not on curve\n"; return 1; }

    cout << "--- ECDH ---\n";
    auto alice = ecdh_generate_keys(curve);
    auto bob   = ecdh_generate_keys(curve);
    Point sa = ecdh_compute_shared_secret(alice.first, bob.second, curve);
    Point sb = ecdh_compute_shared_secret(bob.first, alice.second, curve);
    print_point("Alice shared", sa);
    print_point("Bob shared  ", sb);
    cout << (sa == sb ? "[OK] secrets match\n" : "[FAIL]\n") << endl;

    cout << "--- ECDSA ---\n";
    BigInt hash("5");
    auto sig = ecdsa_sign(hash, alice.first, curve);
    cout << "r = " << sig.first.to_hex() << ", s = " << sig.second.to_hex() << endl;
    cout << "verify: " << (ecdsa_verify(hash, sig, alice.second, curve) ? "VALID" : "INVALID") << endl;

    auto bad = sig;
    bad.second = bad.second + BigInt(1);
    cout << "verify tampered: " << (ecdsa_verify(hash, bad, alice.second, curve) ? "VALID" : "INVALID") << endl;

    return 0;
}