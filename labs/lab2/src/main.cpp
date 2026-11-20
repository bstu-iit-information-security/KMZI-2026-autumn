// Демонстрация: генерация ключа RSA-3072, OAEP-SHA-512 шифрование/расшифрование.
// Записывает key.conf (для сборки DER-ключа в OpenSSL) и ct.bin - проверка совместимости со стандартом PKCS#1 v2.1.
#include "oaep.hpp"
#include <cstdio>
#include <cstring>

using namespace cfg;

static void put_hex(FILE* f, const char* tag, const BigInt& x, size_t len) {
    uint8_t buf[K];
    rsa::int_to_bytes(x, buf, len);
    std::fprintf(f, "%s=INTEGER:0x", tag);
    for (size_t i = 0; i < len; ++i) std::fprintf(f, "%02X", buf[i]);
    std::fprintf(f, "\n");
}

int main() {
    PublicKey pub; PrivateKey prv;
    std::puts("Генерация ключа RSA-3072 ...");
    nt::generate_keypair(pub, prv, RSA_BITS);
    std::printf("N: %zu бит, p: %zu бит, q: %zu бит, e = %u\n", prv.n.bits(), prv.p.bits(), prv.q.bits(), E_PUB);

    const char* text = "Лабораторная №2: RSA-OAEP, вариант 3";
    const size_t mlen = std::strlen(text);
    uint8_t ct[K], out[MAX_MSG]; size_t olen = 0;

    if (!oaep::encrypt(pub, reinterpret_cast<const uint8_t*>(text), mlen, nullptr, 0, ct)) { std::puts("encrypt: ошибка"); return 1; }
    std::printf("Шифротекст (%zu байт), первые 16: ", K);
    for (int i = 0; i < 16; ++i) std::printf("%02x", ct[i]);
    std::puts(" ...");

    if (!oaep::decrypt(prv, ct, nullptr, 0, out, &olen)) { std::puts("decrypt: ошибка"); return 1; }
    std::printf("Расшифровано (%zu байт): %.*s\n", olen, static_cast<int>(olen), reinterpret_cast<const char*>(out));

    if (FILE* f = std::fopen("key.conf", "w")) {
        std::fprintf(f, "asn1=SEQUENCE:rsa\n[rsa]\nversion=INTEGER:0\n");
        put_hex(f, "n", prv.n, K);  put_hex(f, "e", prv.e, 8);  put_hex(f, "d", prv.d, K);
        put_hex(f, "p", prv.p, K / 2); put_hex(f, "q", prv.q, K / 2);
        put_hex(f, "dp", prv.dp, K / 2); put_hex(f, "dq", prv.dq, K / 2); put_hex(f, "qi", prv.qinv, K / 2);
        std::fclose(f);
    }
    if (FILE* f = std::fopen("ct.bin", "wb")) { std::fwrite(ct, 1, K, f); std::fclose(f); }
    std::puts("Сохранено: key.conf, ct.bin");
    return 0;
}
