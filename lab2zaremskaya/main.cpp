#include "common.hpp"
#include "number_theory.hpp"
#include "oaep.hpp"
#include "rsa_core.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

uint64_t rdtsc() {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int lo = 0, hi = 0;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<uint64_t>(hi) << 32) | lo;
#else
    return 0;
#endif
}

std::string hex_of(const uint8_t* p, std::size_t n, std::size_t limit = 32) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    const std::size_t m = n < limit ? n : limit;
    for (std::size_t i = 0; i < m; ++i) {
        os << std::setw(2) << static_cast<int>(p[i]);
    }
    if (n > limit) {
        os << "...";
    }
    return os.str();
}

bool load_line(std::istream& in, const char* key, rsa::BigInt& out) {
    std::string line;
    if (!std::getline(in, line)) {
        return false;
    }
    const std::string prefix = std::string(key) + "=";
    if (line.rfind(prefix, 0) != 0) {
        return false;
    }
    out = rsa::BigInt::from_hex(line.c_str() + prefix.size());
    return true;
}

bool load_keys(const char* path, rsa::KeyPair& kp) {
    std::ifstream in(path);
    if (!in) {
        return false;
    }
    return load_line(in, "n", kp.n) && load_line(in, "e", kp.e) && load_line(in, "d", kp.d) &&
           load_line(in, "p", kp.p) && load_line(in, "q", kp.q) && load_line(in, "dp", kp.dp) &&
           load_line(in, "dq", kp.dq) && load_line(in, "qinv", kp.qinv) &&
           load_line(in, "lambda", kp.lambda);
}

void save_keys(const char* path, const rsa::KeyPair& kp) {
    std::ofstream out(path);
    out << "n=" << kp.n.to_hex() << "\n";
    out << "e=" << kp.e.to_hex() << "\n";
    out << "d=" << kp.d.to_hex() << "\n";
    out << "p=" << kp.p.to_hex() << "\n";
    out << "q=" << kp.q.to_hex() << "\n";
    out << "dp=" << kp.dp.to_hex() << "\n";
    out << "dq=" << kp.dq.to_hex() << "\n";
    out << "qinv=" << kp.qinv.to_hex() << "\n";
    out << "lambda=" << kp.lambda.to_hex() << "\n";
}

struct Stats {
    double mean_ns = 0;
    double std_ns = 0;
    double mean_cycles = 0;
};

Stats measure(const std::vector<double>& ns, const std::vector<double>& cyc) {
    Stats s;
    if (ns.empty()) {
        return s;
    }
    double sum = 0, sum2 = 0, sc = 0;
    for (std::size_t i = 0; i < ns.size(); ++i) {
        sum += ns[i];
        sum2 += ns[i] * ns[i];
        sc += cyc[i];
    }
    s.mean_ns = sum / static_cast<double>(ns.size());
    s.mean_cycles = sc / static_cast<double>(cyc.size());
    const double var = sum2 / static_cast<double>(ns.size()) - s.mean_ns * s.mean_ns;
    s.std_ns = var > 0 ? std::sqrt(var) : 0;
    return s;
}

int fail(const char* msg) {
    std::cerr << "FAIL: " << msg << "\n";
    return 1;
}

}

int main() {
    using clock = std::chrono::steady_clock;
    std::cout << " Лабораторная №2, вариант " << rsa::kVariant << " \n";
    std::cout << "N = " << rsa::kModulusBits << " бит, hash = " << rsa::kHashName
              << ", k = " << rsa::kModulusBytes << " байт\n";
    std::cout << "max |M| = k - 2*hLen - 2 = " << rsa::kMaxMessage << "\n";
    std::cout << "Задача оптимизации: " << rsa::kOptimization << "\n\n";

    if (!rsa::sha512_selftest()) {
        return fail("SHA-512 self-test");
    }
    std::cout << "[1] SHA-512 self-test: OK (NIST: \"\" и \"abc\")\n";

    uint8_t db_scan[rsa::kModulusBytes];
    std::memset(db_scan, 0, sizeof(db_scan));
    const std::size_t db_len = rsa::kModulusBytes - rsa::kHashLen - 1;
    db_scan[rsa::kHashLen] = 0x01;
    auto d0 = rsa::OaepEngine::find_delimiter(db_scan, db_len);
    if (!d0.found || d0.one_pos != rsa::kHashLen) {
        return fail("delim at start");
    }
    std::memset(db_scan, 0, sizeof(db_scan));
    db_scan[db_len - 1] = 0x01;
    auto d1 = rsa::OaepEngine::find_delimiter(db_scan, db_len);
    if (!d1.found || d1.one_pos != db_len - 1) {
        return fail("delim at end");
    }
    std::memset(db_scan, 0, sizeof(db_scan));
    auto dmiss = rsa::OaepEngine::find_delimiter(db_scan, db_len);
    if (dmiss.found) {
        return fail("missing delim reported found");
    }
    std::cout << "[2] Безусловный поиск 0x01: начало/конец/отсутствие — OK\n";

    const rsa::GarnerDemo gd = rsa::garner_demo_small();
    std::cout << "\n[3] Учебный пример алгоритма Гарнера (p=61, q=53, m=65):\n";
    std::cout << "    N = " << gd.n.to_dec() << ", e = " << gd.e.to_dec()
              << ", d = " << gd.d.to_dec() << "\n";
    std::cout << "    dp = " << gd.dp.to_dec() << ", dq = " << gd.dq.to_dec()
              << ", qinv = " << gd.qinv.to_dec() << "\n";
    std::cout << "    c = m^e mod N = " << gd.c.to_dec() << "\n";
    std::cout << "    m1 = c^dp mod p = " << gd.m1.to_dec() << "\n";
    std::cout << "    m2 = c^dq mod q = " << gd.m2.to_dec() << "\n";
    std::cout << "    h  = qinv*(m1-m2) mod p = " << gd.h.to_dec() << "\n";
    std::cout << "    m  = m2 + h*q = " << gd.recovered.to_dec() << "\n";
    if (gd.recovered.cmp(gd.m) != 0) {
        return fail("Garner small demo");
    }
    const rsa::BigInt naive = rsa::mod_exp_binary(gd.c, gd.d, gd.n);
    if (naive.cmp(gd.m) != 0) {
        return fail("binary modexp mismatch");
    }
    std::cout << "    сверка с c^d mod N: OK\n";

    rsa::KeyPair kp;
    const char* keyfile = "keys.txt";
    if (load_keys(keyfile, kp) && kp.n.bit_length() == rsa::kModulusBits) {
        std::cout << "\n[4] Ключи загружены из " << keyfile << " (N = " << kp.n.bit_length()
                  << " бит)\n";
    } else {
        std::cout << "\n[4] Генерация ключа RSA-" << rsa::kModulusBits
                  << " (Миллер–Рабин, λ(N), CRT-компоненты)...\n";
        const auto t0 = clock::now();
        kp = rsa::generate_keypair(rsa::kModulusBits, [](const char* s) {
            std::cerr << "    ... " << s << "\n";
        });
        const auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - t0).count();
        save_keys(keyfile, kp);
        std::cout << "    готово за " << ms << " мс, сохранено в " << keyfile << "\n";
    }
    std::cout << "    |N| = " << kp.n.bit_length() << ", |p| = " << kp.p.bit_length()
              << ", |q| = " << kp.q.bit_length() << ", e = " << kp.e.to_dec() << "\n";
    std::cout << "    N (hex, начало) = " << kp.n.to_hex().substr(0, 64) << "...\n";

    rsa::OaepEngine oaep;
    uint8_t em[rsa::kModulusBytes];
    uint8_t ct[rsa::kModulusBytes];

    // Границы |M|=0 и |M|=max
    {
        if (!oaep.encode(nullptr, 0, em)) {
            return fail("encode empty");
        }
        rsa::OaepResult d = oaep.decode(em);
        if (!d.ok || d.len != 0) {
            return fail("decode empty");
        }
        std::cout << "\n[5] Граница |M|=0: encode/decode OK\n";
    }
    {
        uint8_t maxm[rsa::kMaxMessage];
        for (std::size_t i = 0; i < rsa::kMaxMessage; ++i) {
            maxm[i] = static_cast<uint8_t>(i * 17 + 3);
        }
        if (!oaep.encode(maxm, rsa::kMaxMessage, em)) {
            return fail("encode max");
        }
        rsa::OaepResult d = oaep.decode(em);
        if (!d.ok || d.len != rsa::kMaxMessage ||
            std::memcmp(d.msg, maxm, rsa::kMaxMessage) != 0) {
            return fail("decode max");
        }
        std::cout << "[6] Граница |M|=max=" << rsa::kMaxMessage << ": encode/decode OK\n";
        if (oaep.encode(maxm, rsa::kMaxMessage + 1, em)) {
            return fail("encode oversize should fail");
        }
        std::cout << "[7] |M|=max+1 отвергнут на упаковке: OK\n";
    }

    const char* text = "RSA-OAEP lab variant 7: CT search for 0x01";
    const auto tlen = std::strlen(text);
    if (!rsa::rsa_oaep_encrypt(reinterpret_cast<const uint8_t*>(text), tlen, kp, ct)) {
        return fail("encrypt");
    }
    rsa::OaepResult dec = rsa::rsa_oaep_decrypt(ct, kp);
    if (!dec.ok || dec.len != tlen || std::memcmp(dec.msg, text, tlen) != 0) {
        return fail("decrypt roundtrip");
    }
    std::cout << "[8] Полный цикл OAEP+RSA-CRT: \"" << text << "\" — OK\n";
    std::cout << "    ciphertext: " << hex_of(ct, rsa::kModulusBytes) << "\n";

    uint8_t bad[rsa::kModulusBytes];
    std::memcpy(bad, ct, rsa::kModulusBytes);
    bad[rsa::kModulusBytes - 1] ^= 0x5a;
    rsa::OaepResult bad_dec = rsa::rsa_oaep_decrypt(bad, kp);
    if (bad_dec.ok) {
        return fail("corrupted ciphertext accepted");
    }
    std::cout << "[9] Повреждённый шифротекст отклонён (без утечки сообщения): OK\n";

    if (!oaep.encode(reinterpret_cast<const uint8_t*>(text), tlen, em)) {
        return fail("encode for ct tests");
    }
    uint8_t em_bad0[rsa::kModulusBytes];
    std::memcpy(em_bad0, em, rsa::kModulusBytes);
    em_bad0[0] = 0x01;
    if (oaep.decode(em_bad0).ok) {
        return fail("Y!=0 accepted");
    }
    uint8_t em_badh[rsa::kModulusBytes];
    std::memcpy(em_badh, em, rsa::kModulusBytes);
    em_badh[1 + rsa::kHashLen] ^= 0x01;
    if (oaep.decode(em_badh).ok) {
        return fail("bad lHash accepted");
    }
    std::cout << "[10] Деинкапсуляция с Y≠0 и сломанным maskedDB: отказ — OK\n";

    constexpr int kRounds = 40;
    auto time_decrypt = [&](const uint8_t* buf) {
        std::vector<double> ns, cyc;
        ns.reserve(kRounds);
        cyc.reserve(kRounds);
        for (int i = 0; i < kRounds; ++i) {
            const uint64_t c0 = rdtsc();
            const auto t0 = clock::now();
            volatile auto r = rsa::rsa_oaep_decrypt(buf, kp);
            (void)r.ok;
            const auto t1 = clock::now();
            const uint64_t c1 = rdtsc();
            ns.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count());
            cyc.push_back(c1 > c0 ? static_cast<double>(c1 - c0) : 0);
        }
        return measure(ns, cyc);
    };

    auto time_oaep = [&](const uint8_t* buf) {
        std::vector<double> ns, cyc;
        ns.reserve(kRounds * 4);
        cyc.reserve(kRounds * 4);
        rsa::OaepEngine eng;
        for (int i = 0; i < kRounds * 4; ++i) {
            const uint64_t c0 = rdtsc();
            const auto t0 = clock::now();
            volatile auto r = eng.decode(buf);
            (void)r.ok;
            const auto t1 = clock::now();
            const uint64_t c1 = rdtsc();
            ns.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count());
            cyc.push_back(c1 > c0 ? static_cast<double>(c1 - c0) : 0);
        }
        return measure(ns, cyc);
    };

    const Stats valid_rsa = time_decrypt(ct);
    const Stats bad_rsa = time_decrypt(bad);
    const Stats valid_oaep = time_oaep(em);
    const Stats bad_oaep = time_oaep(em_badh);

    uint8_t em_empty[rsa::kModulusBytes];
    uint8_t em_max[rsa::kModulusBytes];
    uint8_t maxm[rsa::kMaxMessage];
    for (std::size_t i = 0; i < rsa::kMaxMessage; ++i) {
        maxm[i] = static_cast<uint8_t>(i * 17 + 3);
    }
    if (!oaep.encode(nullptr, 0, em_empty) || !oaep.encode(maxm, rsa::kMaxMessage, em_max)) {
        return fail("encode for delim timing");
    }
    const Stats oaep_empty = time_oaep(em_empty);
    const Stats oaep_max = time_oaep(em_max);

    const double rsa_ratio = valid_rsa.mean_ns > 0 ? bad_rsa.mean_ns / valid_rsa.mean_ns : 0;
    const double oaep_ratio = valid_oaep.mean_ns > 0 ? bad_oaep.mean_ns / valid_oaep.mean_ns : 0;
    const double delim_ratio = oaep_empty.mean_ns > 0 ? oaep_max.mean_ns / oaep_empty.mean_ns : 0;

    std::cout << "\n[11] Измерение времени / тактов (constant-time):\n";
    std::cout << std::fixed << std::setprecision(1);
    std::cout << "    RSA-OAEP decrypt VALID:     " << valid_rsa.mean_ns << " нс ± "
              << valid_rsa.std_ns << "  (" << valid_rsa.mean_cycles << " тактов)\n";
    std::cout << "    RSA-OAEP decrypt CORRUPT:   " << bad_rsa.mean_ns << " нс ± " << bad_rsa.std_ns
              << "  (" << bad_rsa.mean_cycles << " тактов)\n";
    std::cout << "    отношение corrupt/valid = " << std::setprecision(4) << rsa_ratio << "\n";
    std::cout << std::setprecision(1);
    std::cout << "    OAEP decode VALID:          " << valid_oaep.mean_ns << " нс ± "
              << valid_oaep.std_ns << "  (" << valid_oaep.mean_cycles << " тактов)\n";
    std::cout << "    OAEP decode CORRUPT lHash:  " << bad_oaep.mean_ns << " нс ± " << bad_oaep.std_ns
              << "  (" << bad_oaep.mean_cycles << " тактов)\n";
    std::cout << "    отношение corrupt/valid = " << std::setprecision(4) << oaep_ratio << "\n";
    std::cout << std::setprecision(1);
    std::cout << "    OAEP decode |M|=0 (0x01 в конце):  " << oaep_empty.mean_ns << " нс ± "
              << oaep_empty.std_ns << "  (" << oaep_empty.mean_cycles << " тактов)\n";
    std::cout << "    OAEP decode |M|=max (0x01 сразу):  " << oaep_max.mean_ns << " нс ± "
              << oaep_max.std_ns << "  (" << oaep_max.mean_cycles << " тактов)\n";
    std::cout << "    отношение max/empty = " << std::setprecision(4) << delim_ratio << "\n";

    std::ofstream res("reports/results.txt");
    res << std::fixed;
    res << "variant=" << rsa::kVariant << "\n";
    res << "modulus_bits=" << rsa::kModulusBits << "\n";
    res << "hash=" << rsa::kHashName << "\n";
    res << "hLen=" << rsa::kHashLen << "\n";
    res << "k=" << rsa::kModulusBytes << "\n";
    res << "max_msg=" << rsa::kMaxMessage << "\n";
    res << "p_bits=" << kp.p.bit_length() << "\n";
    res << "q_bits=" << kp.q.bit_length() << "\n";
    res << "e=" << kp.e.to_dec() << "\n";
    res << "d_dec=" << gd.d.to_dec() << "\n";
    res << "garner_n=" << gd.n.to_dec() << "\n";
    res << "garner_d=" << gd.d.to_dec() << "\n";
    res << "garner_dp=" << gd.dp.to_dec() << "\n";
    res << "garner_dq=" << gd.dq.to_dec() << "\n";
    res << "garner_qinv=" << gd.qinv.to_dec() << "\n";
    res << "garner_c=" << gd.c.to_dec() << "\n";
    res << "garner_m1=" << gd.m1.to_dec() << "\n";
    res << "garner_m2=" << gd.m2.to_dec() << "\n";
    res << "garner_h=" << gd.h.to_dec() << "\n";
    res << "garner_m=" << gd.recovered.to_dec() << "\n";
    res << std::setprecision(3);
    res << "rsa_valid_ns=" << valid_rsa.mean_ns << "\n";
    res << "rsa_valid_std=" << valid_rsa.std_ns << "\n";
    res << "rsa_valid_cyc=" << valid_rsa.mean_cycles << "\n";
    res << "rsa_bad_ns=" << bad_rsa.mean_ns << "\n";
    res << "rsa_bad_std=" << bad_rsa.std_ns << "\n";
    res << "rsa_bad_cyc=" << bad_rsa.mean_cycles << "\n";
    res << "rsa_ratio=" << rsa_ratio << "\n";
    res << "oaep_valid_ns=" << valid_oaep.mean_ns << "\n";
    res << "oaep_valid_std=" << valid_oaep.std_ns << "\n";
    res << "oaep_valid_cyc=" << valid_oaep.mean_cycles << "\n";
    res << "oaep_bad_ns=" << bad_oaep.mean_ns << "\n";
    res << "oaep_bad_std=" << bad_oaep.std_ns << "\n";
    res << "oaep_bad_cyc=" << bad_oaep.mean_cycles << "\n";
    res << "oaep_ratio=" << oaep_ratio << "\n";
    res << "oaep_empty_ns=" << oaep_empty.mean_ns << "\n";
    res << "oaep_empty_cyc=" << oaep_empty.mean_cycles << "\n";
    res << "oaep_max_ns=" << oaep_max.mean_ns << "\n";
    res << "oaep_max_cyc=" << oaep_max.mean_cycles << "\n";
    res << "delim_ratio=" << delim_ratio << "\n";
    res.close();

    std::cout << "\nВсе проверки пройдены. Метрики записаны в reports/results.txt\n";
    return 0;
}