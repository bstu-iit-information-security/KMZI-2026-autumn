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
    const std::string HASH_HEX = "2A1C6E8F4B7D90A12233445566778899AABBCCDDEEFF00112233445566778899";
    const std::string DA_HEX = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDE";
    const std::string DB_HEX = "234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";
    const std::string D_HEX = "1111111111111111111111111111111111111111111111111111111111111111";
    const std::string K_HEX = "3333333333333333333333333333333333333333333333333333333333333333";

    const EllipticCurve curve(P_HEX, A_HEX, B_HEX, Q_HEX, GX_HEX, GY_HEX);
    const GostProtocols gost(curve);

    const AffinePoint Gaff = curve.toAffine(curve.generator());
    if (!curve.isOnCurveAffine(Gaff)) {
        throw std::runtime_error("Generator is not on curve");
    }

    const BigInt dA = BigIntUtils::fromHex(DA_HEX);
    const BigInt dB = BigIntUtils::fromHex(DB_HEX);
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

    const BigInt hash = BigIntUtils::fromHex(HASH_HEX);
    const BigInt d = BigIntUtils::fromHex(D_HEX);
    const BigInt k = BigIntUtils::fromHex(K_HEX);
    const JacobianPoint Qsign = gost.publicKey(d);
    const Signature sig = gost.signHash(hash, d, k);

    printPoint("QSIGN", curve, Qsign);
    std::cout << "R=" << BigIntUtils::toFixedHex(sig.r, EllipticCurve::FIELD_BYTES) << '\n';
    std::cout << "S=" << BigIntUtils::toFixedHex(sig.s, EllipticCurve::FIELD_BYTES) << '\n';

    const bool signatureOk = gost.verifyHash(hash, sig, Qsign);
    std::cout << "VERIFY=" << (signatureOk ? "01" : "00") << '\n';

    Signature damaged = sig;
    damaged.s ^= 0x01;
    const bool damagedOk = gost.verifyHash(hash, damaged, Qsign);
    std::cout << "VERIFY_DAMAGED=" << (damagedOk ? "01" : "00") << '\n';

    std::cout << "MESSAGE_HEX=" << MESSAGE_HEX << '\n';
    std::cout << "HASH_HEX=" << HASH_HEX << '\n';

    return 0;
}
