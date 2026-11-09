#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "belt.hpp"
#include "ct_utils.hpp"
#include "galois_field.hpp"
#include "gcm.hpp"

namespace {

constexpr uint16_t kVariantPolynomial = 0x12B;

int failures = 0;

void check(bool ok, const std::string& name) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name.c_str());
    if (!ok) {
        ++failures;
    }
}

template <typename Container>
std::string hex(const Container& data) {
    static const char digits[] = "0123456789abcdef";
    std::string s;
    for (uint8_t byte : data) {
        s.push_back(digits[byte >> 4]);
        s.push_back(digits[byte & 0x0F]);
    }
    return s;
}

std::vector<uint8_t> fromHex(const std::string& s) {
    std::vector<uint8_t> out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    }
    return out;
}

int degreeOf(uint32_t v) {
    int d = -1;
    while (v != 0) {
        ++d;
        v >>= 1;
    }
    return d;
}

uint8_t referenceMultiply(uint8_t a, uint8_t b, uint16_t p) {
    uint32_t product = 0;
    for (int i = 0; i < 8; ++i) {
        if ((b >> i) & 1) {
            product ^= static_cast<uint32_t>(a) << i;
        }
    }
    for (int d = degreeOf(product); d >= 8; d = degreeOf(product)) {
        product ^= static_cast<uint32_t>(p) << (d - 8);
    }
    return static_cast<uint8_t>(product);
}

void testField() {
    check(GaloisField::isIrreducible(0x12B), "p(x)=0x12B irreducible");
    check(GaloisField::isIrreducible(0x11B), "p(x)=0x11B irreducible");
    check(!GaloisField::isIrreducible(0x101), "p(x)=0x101 reducible");
    check(!GaloisField::isIrreducible(0x11A), "p(x)=0x11A reducible");

    bool rejected = false;
    try {
        GaloisField bad(0x101);
    } catch (const std::exception&) {
        rejected = true;
    }
    check(rejected, "constructor rejects reducible polynomial");

    check(GaloisField::add(0x57, 0x83) == 0xD4, "add is XOR");
    check(GaloisField::multiply(0x57, 0x83, 0x11B) == 0xC1, "0x57*0x83=0xC1 mod 0x11B");
    check(GaloisField::multiply(0x80, 0x02, 0x12B) == 0x2B, "overflow reduction 0x80*0x02 mod 0x12B");
    check(GaloisField::multiply(0xFF, 0xFF, 0x12B) == referenceMultiply(0xFF, 0xFF, 0x12B), "0xFF*0xFF mod 0x12B");

    bool allMatch = true;
    for (unsigned a = 0; a < 256 && allMatch; ++a) {
        for (unsigned b = 0; b < 256; ++b) {
            if (GaloisField::multiply(static_cast<uint8_t>(a), static_cast<uint8_t>(b), kVariantPolynomial) !=
                referenceMultiply(static_cast<uint8_t>(a), static_cast<uint8_t>(b), kVariantPolynomial)) {
                allMatch = false;
                break;
            }
        }
    }
    check(allMatch, "multiply matches reference for all 65536 pairs");

    check(GaloisField::inverse(0x00, kVariantPolynomial) == 0x00, "inverse(0)=0");
    bool inverses = true;
    for (unsigned a = 1; a < 256; ++a) {
        const uint8_t inv = GaloisField::inverse(static_cast<uint8_t>(a), kVariantPolynomial);
        if (GaloisField::multiply(static_cast<uint8_t>(a), inv, kVariantPolynomial) != 1) {
            inverses = false;
        }
    }
    check(inverses, "a*inverse(a)=1 for all a!=0");
}

void testSBox() {
    const SBox aes = GaloisField(0x11B).generateSBox();
    check(aes[0x00] == 0x63 && aes[0x01] == 0x7C && aes[0x53] == 0xED && aes[0xFF] == 0x16,
          "S-box for 0x11B equals AES S-box");

    const SBox own = GaloisField(kVariantPolynomial).generateSBox();
    std::array<bool, 256> seen{};
    bool permutation = true;
    for (uint8_t v : own) {
        if (seen[v]) {
            permutation = false;
        }
        seen[v] = true;
    }
    check(permutation, "S-box for 0x12B is a permutation");
    check(own[0x00] == 0x63, "S-box for 0x12B maps 0 to 0x63");
}

void testRotations() {
    check(ct::rotl32(0x80000001u, 1) == 0x00000003u, "rotl32 wraps high bit");
    check(ct::rotr32(0x00000003u, 1) == 0x80000001u, "rotr32 wraps low bit");
    check(ct::rotl32(0xDEADBEEFu, 0) == 0xDEADBEEFu, "rotl32 by 0");
    check(ct::rotl32(0xDEADBEEFu, 32) == 0xDEADBEEFu, "rotl32 by 32");
    bool inverse = true;
    for (unsigned n = 0; n < 64; ++n) {
        if (ct::rotr32(ct::rotl32(0x12345678u, n), n) != 0x12345678u) {
            inverse = false;
        }
    }
    check(inverse, "rotr32(rotl32(x,n),n)=x for n in 0..63");
}

void testGhash() {
    const auto hv = fromHex("66e94bd4ef8a2c3b884cfa59ca342b2e");
    const auto cv = fromHex("0388dace60b6a392f328c2b971b2fe78");
    const auto ek = fromHex("58e2fccefa7e3061367f1d57a4e7455a");
    Gcm::Block h{};
    std::copy(hv.begin(), hv.end(), h.begin());
    Gcm::Block s = Gcm::ghash(h, {}, cv);
    for (std::size_t i = 0; i < 16; ++i) {
        s[i] = static_cast<uint8_t>(s[i] ^ ek[i]);
    }
    check(hex(s) == "ab6e47d42cec13bdf53a67b21257bddf", "GHASH matches NIST GCM test case 2");
}

void testCipherAndGcm() {
    BeltCipher::Key key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i * 7 + 1);
    }
    const GaloisField field(kVariantPolynomial);
    const BeltCipher cipher(key, field);

    BeltCipher::Block zero{};
    BeltCipher::Block one{};
    one[0] = 1;
    check(cipher.encryptBlock(zero) == cipher.encryptBlock(zero), "block encryption deterministic");
    check(cipher.encryptBlock(zero) != cipher.encryptBlock(one), "block encryption depends on input");

    Gcm gcm(cipher);
    Gcm::Iv iv{};
    for (std::size_t i = 0; i < iv.size(); ++i) {
        iv[i] = static_cast<uint8_t>(0xA0 + i);
    }

    const std::vector<std::size_t> sizes = {0, 1, 15, 16, 17, 31, 32, 33, 100};
    bool roundtrip = true;
    for (std::size_t n : sizes) {
        std::vector<uint8_t> aad(n % 23);
        std::vector<uint8_t> plain(n);
        for (std::size_t i = 0; i < aad.size(); ++i) {
            aad[i] = static_cast<uint8_t>(i * 3 + 5);
        }
        for (std::size_t i = 0; i < plain.size(); ++i) {
            plain[i] = static_cast<uint8_t>(i * 11 + 2);
        }
        const Gcm::Sealed sealed = gcm.encrypt(iv, aad, plain);
        std::vector<uint8_t> decrypted;
        const bool ok = gcm.decrypt(iv, aad, sealed.ciphertext, sealed.tag, decrypted);
        if (!ok || decrypted != plain || sealed.ciphertext.size() != plain.size()) {
            roundtrip = false;
        }
    }
    check(roundtrip, "GCM roundtrip for lengths 0..100");

    std::vector<uint8_t> aad = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19};
    std::vector<uint8_t> plain(40);
    for (std::size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<uint8_t>(0x30 + i);
    }
    const Gcm::Sealed sealed = gcm.encrypt(iv, aad, plain);
    std::printf("ciphertext: %s\n", hex(sealed.ciphertext).c_str());
    std::printf("tag:        %s\n", hex(sealed.tag).c_str());

    std::vector<uint8_t> out;
    bool tagRejected = true;
    for (std::size_t pos = 0; pos < 16; ++pos) {
        Gcm::Block bad = sealed.tag;
        bad[pos] = static_cast<uint8_t>(bad[pos] ^ 0x01);
        if (gcm.decrypt(iv, aad, sealed.ciphertext, bad, out) || !out.empty()) {
            tagRejected = false;
        }
    }
    check(tagRejected, "tampered tag rejected at every byte position");

    std::vector<uint8_t> badCipher = sealed.ciphertext;
    badCipher[5] = static_cast<uint8_t>(badCipher[5] ^ 0x80);
    check(!gcm.decrypt(iv, aad, badCipher, sealed.tag, out), "tampered ciphertext rejected");

    std::vector<uint8_t> badAad = aad;
    badAad[0] = static_cast<uint8_t>(badAad[0] ^ 0x01);
    check(!gcm.decrypt(iv, badAad, sealed.ciphertext, sealed.tag, out), "tampered AAD rejected");

    Gcm::Iv badIv = iv;
    badIv[11] = static_cast<uint8_t>(badIv[11] ^ 0x01);
    check(!gcm.decrypt(badIv, aad, sealed.ciphertext, sealed.tag, out), "wrong IV rejected");

    Gcm::Block t1 = sealed.tag;
    Gcm::Block t2 = sealed.tag;
    t2[0] = static_cast<uint8_t>(t2[0] ^ 0xFF);
    check(!ct::equal(t1.data(), t2.data(), 16), "tag compare detects first-byte difference");
    t2 = sealed.tag;
    t2[15] = static_cast<uint8_t>(t2[15] ^ 0xFF);
    check(!ct::equal(t1.data(), t2.data(), 16), "tag compare detects last-byte difference");
    check(ct::equal(t1.data(), sealed.tag.data(), 16), "tag compare accepts equal tags");
}

}

int main() {
    testField();
    testSBox();
    testRotations();
    testGhash();
    testCipherAndGcm();
    std::printf("failures: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
