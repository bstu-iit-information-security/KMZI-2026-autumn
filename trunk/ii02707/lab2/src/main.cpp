#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <cstring>
#include <cstdint>

#include "bigint.hpp"
#include "sha3.hpp"
#include "rsa_math.hpp"
#include "rsa_core.hpp"
#include "oaep.hpp"

static void print_hex(const uint8_t* data, size_t len, size_t max_bytes = 32) {
    size_t n = std::min(len, max_bytes);
    for (size_t i = 0; i < n; ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    if (len > max_bytes) std::cout << "...[" << std::dec << len << " bytes]";
    std::cout << std::dec;
}

static std::vector<uint8_t> make_test_message(size_t len) {
    std::vector<uint8_t> m(len);
    for (size_t i = 0; i < len; ++i) m[i] = (uint8_t)((i * 7 + 13) & 0xFF);
    return m;
}

static bool test_sha3() {
    std::cout << "[Test 1] SHA3-256 known-answer... ";
    auto h = SHA3_256::hash(nullptr, 0);
    const uint8_t expected[32] = {
        0xa7,0xff,0xc6,0xf8,0xbf,0x1e,0xd7,0x66,
        0x51,0xc1,0x47,0x56,0xa0,0x61,0xd6,0x62,
        0xf5,0x80,0xff,0x4d,0xe4,0x3b,0x49,0xfa,
        0x82,0xd8,0x0a,0x4b,0x80,0xf8,0x43,0x4a
    };
    bool ok = (std::memcmp(h.data(), expected, 32) == 0);
    std::cout << (ok ? "OK" : "FAIL") << "\n";
    return ok;
}

static bool test_keygen(RSAPublicKey& pub, RSAPrivateKey& priv) {
    std::cout << "[Test 2] RSA-3072 key generation... ";
    try {
        rsa_generate_keypair(3072, pub, priv);
        bool ok = (pub.N.bit_length() >= 3071 && pub.N.bit_length() <= 3072) &&
          (priv.p.bit_length() == 1536) &&
          (priv.q.bit_length() == 1536);
        std::cout << (ok ? "OK" : "FAIL")
                  << "  (|N|=" << pub.N.bit_length()
                  << ", |p|=" << priv.p.bit_length()
                  << ", |q|=" << priv.q.bit_length() << ")\n";
        return ok;
    } catch (const std::exception& e) {
        std::cout << "FAIL: " << e.what() << "\n";
        return false;
    }
}

static bool test_raw_rsa(const RSAPublicKey& pub, const RSAPrivateKey& priv) {
    std::cout << "[Test 3] Raw RSA encrypt/decrypt (blinded)... ";
    try {
        std::vector<uint8_t> m(64, 0xAB);
        auto c = rsa_encrypt_raw(pub, m);
        auto m2 = rsa_decrypt_blinded(pub, priv, c);

        bool ok = (m2.size() >= m.size()) &&
                  std::equal(m.begin(), m.end(),
                             m2.end() - m.size());
        std::cout << (ok ? "OK" : "FAIL") << "\n";
        return ok;
    } catch (const std::exception& e) {
        std::cout << "FAIL: " << e.what() << "\n";
        return false;
    }
}

static bool test_oaep_roundtrip(const RSAPublicKey& pub, const RSAPrivateKey& priv) {
    std::cout << "[Test 4] OAEP encrypt/decrypt round-trip... ";
    try {
        size_t k = pub.N.byte_length();
        size_t max_msg = k - 2*OAEP::HASH_LEN - 2;

        std::vector<uint8_t> m = make_test_message(100);
        auto em = OAEP::pad(m.data(), m.size(), k);
        auto c  = rsa_encrypt_raw(pub, em);
        auto dec_em = rsa_decrypt_blinded(pub, priv, c);
        auto m2 = OAEP::unpad(dec_em.data(), dec_em.size());

        bool ok = (m == m2);
        std::cout << (ok ? "OK" : "FAIL")
                  << "  (msg=" << m.size() << "B, max=" << max_msg << "B)\n";
        return ok;
    } catch (const std::exception& e) {
        std::cout << "FAIL: " << e.what() << "\n";
        return false;
    }
}

static bool test_edge_cases(const RSAPublicKey& pub, const RSAPrivateKey& priv) {
    std::cout << "[Test 5] Edge cases (empty + max-length message)... ";
    try {
        size_t k = pub.N.byte_length();
        size_t max_msg = k - 2*OAEP::HASH_LEN - 2;

        std::vector<uint8_t> empty;
        auto em1 = OAEP::pad(empty.data(), empty.size(), k);
        auto c1  = rsa_encrypt_raw(pub, em1);
        auto dec1 = rsa_decrypt_blinded(pub, priv, c1);
        auto m1  = OAEP::unpad(dec1.data(), dec1.size());
        bool ok1 = (m1 == empty);

        std::vector<uint8_t> full = make_test_message(max_msg);
        auto em2 = OAEP::pad(full.data(), full.size(), k);
        auto c2  = rsa_encrypt_raw(pub, em2);
        auto dec2 = rsa_decrypt_blinded(pub, priv, c2);
        auto m2  = OAEP::unpad(dec2.data(), dec2.size());
        bool ok2 = (m2 == full);

        std::cout << ((ok1 && ok2) ? "OK" : "FAIL")
                  << "  (empty=" << ok1 << ", max=" << ok2 << ")\n";
        return ok1 && ok2;
    } catch (const std::exception& e) {
        std::cout << "FAIL: " << e.what() << "\n";
        return false;
    }
}

static bool test_oaep_reject(const RSAPublicKey& pub, const RSAPrivateKey& priv) {
    std::cout << "[Test 6] OAEP rejects tampered ciphertext... ";
    try {
        size_t k = pub.N.byte_length();
        std::vector<uint8_t> m = make_test_message(50);
        auto em = OAEP::pad(m.data(), m.size(), k);
        auto c  = rsa_encrypt_raw(pub, em);

        c[c.size()/2] ^= 0x01;

        auto dec = rsa_decrypt_blinded(pub, priv, c);
        try {
            auto m2 = OAEP::unpad(dec.data(), dec.size());
            std::cout << "FAIL (should have thrown)\n";
            return false;
        } catch (const std::runtime_error&) {
            std::cout << "OK (correctly rejected)\n";
            return true;
        }
    } catch (const std::exception& e) {
        std::cout << "FAIL: " << e.what() << "\n";
        return false;
    }
}

static bool test_constant_time(const RSAPublicKey& pub, const RSAPrivateKey& priv) {
    std::cout << "[Test 7] Constant-time timing check (OAEP unpad)...\n";
    try {
        size_t k = pub.N.byte_length();
        std::vector<uint8_t> m = make_test_message(100);

        const int N_ITER = 20;
        int64_t t_valid_sum = 0, t_invalid_sum = 0;

        for (int it = 0; it < N_ITER; ++it) {
            auto em = OAEP::pad(m.data(), m.size(), k);
            auto c  = rsa_encrypt_raw(pub, em);

            auto t1 = std::chrono::high_resolution_clock::now();
            auto dec = rsa_decrypt_blinded(pub, priv, c);
            (void)OAEP::unpad(dec.data(), dec.size());
            auto t2 = std::chrono::high_resolution_clock::now();
            t_valid_sum += std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();

            std::vector<uint8_t> fake_em(k);
            for (size_t i = 0; i < k; ++i) fake_em[i] = (uint8_t)(i * 17 + it);
            fake_em[0] = 0x00;
            BigInt FakeC = BigInt::from_bytes(fake_em) % priv.N;
            std::vector<uint8_t> fake_c = FakeC.to_bytes_padded(k);

            auto t3 = std::chrono::high_resolution_clock::now();
            auto dec2 = rsa_decrypt_blinded(pub, priv, fake_c);
            try { (void)OAEP::unpad(dec2.data(), dec2.size()); } catch (...) {}
            auto t4 = std::chrono::high_resolution_clock::now();
            t_invalid_sum += std::chrono::duration_cast<std::chrono::microseconds>(t4 - t3).count();
        }

        double avg_valid   = (double)t_valid_sum   / N_ITER;
        double avg_invalid = (double)t_invalid_sum / N_ITER;
        double ratio = (avg_valid > 0) ? avg_invalid / avg_valid : 0;

        std::cout << "   avg valid   = " << std::fixed << std::setprecision(1)
                  << avg_valid   << " us\n";
        std::cout << "   avg invalid = " << avg_invalid << " us\n";
        std::cout << "   ratio invalid/valid = " << std::setprecision(3)
                  << ratio << "\n";
        
        bool ok = (ratio > 0.85 && ratio < 1.15);
        std::cout << "   -> " << (ok ? "CONSTANT-TIME OK" : "TIMING LEAK DETECTED") << "\n";
        return ok;
    } catch (const std::exception& e) {
        std::cout << "   FAIL: " << e.what() << "\n";
        return false;
    }
}

int main() {
    std::cout << "========================================================\n";
    std::cout << " RSA-3072 + SHA3-256 + OAEP + RSA Blinding (variant 4)\n";
    std::cout << "========================================================\n\n";

    int passed = 0, total = 0;

    auto run = [&](bool ok) { ++total; if (ok) ++passed; };

    run(test_sha3());

    RSAPublicKey  pub;
    RSAPrivateKey priv;
    run(test_keygen(pub, priv));

    if (pub.N.is_zero()) {
        std::cout << "Key generation failed, aborting.\n";
        return 1;
    }

    run(test_raw_rsa(pub, priv));
    run(test_oaep_roundtrip(pub, priv));
    run(test_edge_cases(pub, priv));
    run(test_oaep_reject(pub, priv));
    run(test_constant_time(pub, priv));

    std::cout << "\n========================================================\n";
    std::cout << " Results: " << passed << " / " << total << " tests passed\n";
    std::cout << "========================================================\n";

    return (passed == total) ? 0 : 1;
}