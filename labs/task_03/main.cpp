
#include "constant_time.hpp"
#include "gost_protocols.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

void printPoint(const std::string& label,
                const EllipticCurve& curve,
                const JacobianPoint& P) {
    const AffinePoint A = curve.toAffine(P);
    if (A.infinity) throw std::runtime_error("Attempt to print point at infinity");
    std::cout << label << ".X=" << BigIntUtils::toFixedHex(A.x, EllipticCurve::FIELD_BYTES) << '\n';
    std::cout << label << ".Y=" << BigIntUtils::toFixedHex(A.y, EllipticCurve::FIELD_BYTES) << '\n';
}

int main() {
    const std::string P_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97";
    const std::string A_HEX = "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335";
    const std::string B_HEX = "295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513";
    const std::string Q_HEX = "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67";
    const std::string GX_HEX = "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28";
    const std::string GY_HEX = "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C";
    const std::string MESSAGE_HEX = "54657374206D65737361676520666F7220474F53542033342E31302D32303132";

    const EllipticCurve curve(P_HEX, A_HEX, B_HEX, Q_HEX, GX_HEX, GY_HEX);
    const GostProtocols gost(curve);

    if (!curve.isOnCurveAffine(curve.toAffine(curve.generator()))) {
        throw std::runtime_error("Generator is not on curve");
    }

    const BigInt dA = gost.generatePrivateKey();
    const BigInt dB = gost.generatePrivateKey();
    const JacobianPoint QA = gost.publicKey(dA);
    const JacobianPoint QB = gost.publicKey(dB);
    const JacobianPoint sharedA = gost.ecdhShared(dA, QB);
    const JacobianPoint sharedB = gost.ecdhShared(dB, QA);

    printPoint("QA", curve, QA);
    printPoint("QB", curve, QB);
    printPoint("SHARED_A", curve, sharedA);
    printPoint("SHARED_B", curve, sharedB);

    const bool sameShared = ConstantTime::secureCompare(curve, sharedA, sharedB);
    std::cout << "ECDH_EQUAL=" << (sameShared ? "01" : "00") << '\n';

    const BigInt d = gost.generatePrivateKey();
    const JacobianPoint Qsign = gost.publicKey(d);
    const BigInt hash = gost.hashMessage(MESSAGE_HEX);
    const Signature sig = gost.signMessage(MESSAGE_HEX, d);
    const Signature sig2 = gost.signMessage(MESSAGE_HEX, d);

    printPoint("QSIGN", curve, Qsign);
    std::cout << "R=" << BigIntUtils::toFixedHex(sig.r, EllipticCurve::FIELD_BYTES) << '\n';
    std::cout << "S=" << BigIntUtils::toFixedHex(sig.s, EllipticCurve::FIELD_BYTES) << '\n';

    const bool signatureOk = gost.verifyMessage(MESSAGE_HEX, sig, Qsign);
    const bool signatureOk2 = gost.verifyMessage(MESSAGE_HEX, sig2, Qsign);
    const bool signaturesDiffer = sig.r != sig2.r || sig.s != sig2.s;

    std::cout << "VERIFY=" << (signatureOk ? "01" : "00") << '\n';
    std::cout << "VERIFY2=" << (signatureOk2 ? "01" : "00") << '\n';
    std::cout << "SIGNATURES_DIFFER=" << (signaturesDiffer ? "01" : "00") << '\n';

    Signature damaged = sig;
    damaged.s ^= 0x01;
    const bool damagedOk = gost.verifyMessage(MESSAGE_HEX, damaged, Qsign);
    std::cout << "VERIFY_DAMAGED=" << (damagedOk ? "01" : "00") << '\n';

    std::cout << "MESSAGE_HEX=" << MESSAGE_HEX << '\n';
    std::cout << "HASH_HEX=" << BigIntUtils::toFixedHex(hash, EllipticCurve::FIELD_BYTES) << '\n';

    return 0;
}
