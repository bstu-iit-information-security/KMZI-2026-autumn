#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "bn.h"
#include "ed.h"
#include "ct.h"
#include "sha512.h"
#include "eddsa.h"

#define MAXMSG 256

typedef struct {
    const char *name;
    const char *seed;
    const char *msg;
    const char *pub;
    const char *sig;
} vec;

static const vec V[] = {
    {
        "RFC8032 test 1",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    },
    {
        "RFC8032 test 2",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "72",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
        "custom 1",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "48656c6c6f2c20456432353531392100",
        "",
        ""
    },
    {
        "custom 2",
        "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "",
        ""
    }
};

static int hex2bytes(const char *h, uint8_t *out, size_t max, size_t *n)
{
    size_t l = strlen(h);
    if (l % 2 != 0 || l / 2 > max) {
        return -1;
    }
    for (size_t i = 0; i < l / 2; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    *n = l / 2;
    return 0;
}

static void bytes2hex(const uint8_t *b, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) {
        sprintf(out + 2 * i, "%02x", b[i]);
    }
}

static void print_point(const char *name, const ed_point *P)
{
    u256 x, y;
    char hx[65], hy[65];
    ed_to_affine(&x, &y, P);
    u256_to_hex(&x, hx);
    u256_to_hex(&y, hy);
    printf("%s.x = %s\n%s.y = %s\n", name, hx, name, hy);
}

static int test_sha(void)
{
    const char *abc = "abc";
    const char *exp =
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    uint8_t d[64];
    char hex[129];
    sha512((const uint8_t *)abc, 3, d);
    bytes2hex(d, 64, hex);
    int ok = strcmp(hex, exp) == 0;
    printf("SHA-512(\"abc\") = %s\n%s\n\n", hex, ok ? "OK" : "FAIL");
    return ok;
}

static int test_signatures(void)
{
    int all = 1;
    size_t nv = sizeof V / sizeof V[0];

    for (size_t i = 0; i < nv; i++) {
        const vec *t = &V[i];
        uint8_t seed[32], msg[MAXMSG], sig[64], bad[64];
        size_t sl = 0, ml = 0;
        char pubhex[65], sighex[129];
        eddsa_key key;
        int ok = 1;

        hex2bytes(t->seed, seed, 32, &sl);
        hex2bytes(t->msg, msg, MAXMSG, &ml);

        eddsa_keygen(&key, seed);
        eddsa_sign(sig, &key, msg, ml);
        bytes2hex(key.pub, 32, pubhex);
        bytes2hex(sig, 64, sighex);

        printf("[%s]\n", t->name);
        printf("message = %s\n", t->msg[0] ? t->msg : "(empty)");
        printf("public  = %s\n", pubhex);
        printf("R||S    = %s\n", sighex);

        if (t->pub[0]) {
            int m = strcmp(pubhex, t->pub) == 0;
            printf("public key matches reference: %s\n", m ? "yes" : "NO");
            ok &= m;
        }
        if (t->sig[0]) {
            int m = strcmp(sighex, t->sig) == 0;
            printf("signature matches reference:  %s\n", m ? "yes" : "NO");
            ok &= m;
        }

        int v = eddsa_verify(sig, key.pub, msg, ml);
        printf("verify(valid signature):      %s\n", v ? "accepted" : "REJECTED");
        ok &= v;

        memcpy(bad, sig, 64);
        bad[32 + 7] ^= 0x01;
        int vb = eddsa_verify(bad, key.pub, msg, ml);
        printf("verify(S with one byte changed): %s\n", vb ? "ACCEPTED" : "rejected");
        ok &= !vb;

        if (ml > 0) {
            uint8_t m2[MAXMSG];
            memcpy(m2, msg, ml);
            m2[0] ^= 0x01;
            int vm = eddsa_verify(sig, key.pub, m2, ml);
            printf("verify(message changed):         %s\n", vm ? "ACCEPTED" : "rejected");
            ok &= !vm;
        }

        printf("%s\n\n", ok ? "OK" : "FAIL");
        all &= ok;
    }
    return all;
}

static int test_ecdh(void)
{
    const char *sa = "5b5a5958575655545352515049484746454443424140393837363534333231a0";
    const char *sb = "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff1";
    uint8_t seedA[32], seedB[32];
    size_t n = 0;
    eddsa_key A, B;
    ed_point QA, QB;
    u256 kA, kB;
    char ha[65], hb[65];

    hex2bytes(sa, seedA, 32, &n);
    hex2bytes(sb, seedB, 32, &n);
    eddsa_keygen(&A, seedA);
    eddsa_keygen(&B, seedB);

    ed_decode(&QA, A.pub);
    ed_decode(&QB, B.pub);

    printf("[ECDH]\n");
    print_point("Alice Q", &QA);
    print_point("Bob   Q", &QB);

    int e1 = eddsa_ecdh(&kA, &A, B.pub);
    int e2 = eddsa_ecdh(&kB, &B, A.pub);
    u256_to_hex(&kA, ha);
    u256_to_hex(&kB, hb);
    printf("Alice shared = %s\nBob   shared = %s\n", ha, hb);

    int ok = (e1 == 0) && (e2 == 0) && ct_eq_u256(&kA, &kB);
    printf("%s\n\n", ok ? "OK" : "FAIL");
    return ok;
}

static int test_ct_vs_vartime(void)
{
    const ed_params *c = ed_curve();
    u256 k;
    ed_point R1, R2;
    u256_from_hex(&k, "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    ct_scalar_mul(&R1, &k, &c->G);
    ed_multiply_vartime(&R2, &k, &c->G);
    int ok = (int)ed_equal(&R1, &R2);
    printf("[ladder vs double-and-add]\n%s\n\n", ok ? "OK" : "FAIL");
    return ok;
}

int main(void)
{
    int ok = 1;
    ok &= test_sha();
    ok &= test_ct_vs_vartime();
    ok &= test_signatures();
    ok &= test_ecdh();
    printf("%s\n", ok ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return ok ? 0 : 1;
}
