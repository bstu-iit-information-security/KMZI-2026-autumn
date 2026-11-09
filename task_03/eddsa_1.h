#ifndef EDDSA_H
#define EDDSA_H

#include <stdint.h>
#include <stddef.h>
#include "bn.h"
#include "ed.h"

typedef struct {
    uint8_t seed[32];
    uint8_t prefix[32];
    u256 a;
    uint8_t pub[32];
} eddsa_key;

void eddsa_keygen(eddsa_key *k, const uint8_t seed[32]);
void eddsa_sign(uint8_t sig[64], const eddsa_key *k, const uint8_t *msg, size_t len);
int eddsa_verify(const uint8_t sig[64], const uint8_t pub[32], const uint8_t *msg, size_t len);
int eddsa_ecdh(u256 *shared_x, const eddsa_key *self, const uint8_t peer_pub[32]);

#endif
