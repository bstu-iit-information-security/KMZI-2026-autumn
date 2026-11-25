#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t h[8];
    uint8_t buf[128];
    size_t buflen;
    uint64_t total;
} sha512_ctx;

void sha512_init(sha512_ctx *c);
void sha512_update(sha512_ctx *c, const uint8_t *data, size_t len);
void sha512_final(sha512_ctx *c, uint8_t out[64]);
void sha512(const uint8_t *data, size_t len, uint8_t out[64]);

#endif
