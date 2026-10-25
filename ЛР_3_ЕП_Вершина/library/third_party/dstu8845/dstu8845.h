// SPDX-License-Identifier: Apache-2.0
#ifndef DSTU8845_H
#define DSTU8845_H

#include <stddef.h>
#include <stdint.h>

#include "dstu9212/utils.h"

#define DSTU8845_KEY_BYTES 64
#define DSTU8845_IV_BYTES 32
#define DSTU8845_BLOCK_BYTES 128

typedef struct {
    uint64_t s[16];
    uint64_t r[2];
    uint64_t key[8];
    uint64_t iv[4];
    uint8_t key_size;
} dstu8845_core;

typedef struct {
    dstu8845_core core;
    uint64_t rest64[16];
    size_t rest_len;
} dstu8845_prng;

dstu8845_prng *dstu8845_prng_alloc(void);
void dstu8845_prng_free(dstu8845_prng *ctx);
dstu9212_status dstu8845_random_init(dstu8845_prng *ctx,
                                     const uint8_t *key,
                                     size_t key_len,
                                     const uint8_t iv[DSTU8845_IV_BYTES]);
dstu9212_status dstu8845_pseudo_random_init(dstu8845_prng *ctx,
                                            const uint8_t *b,
                                            size_t b_len);
dstu9212_status dstu8845_prng_generate_blocks(dstu8845_prng *ctx,
                                              uint8_t *out,
                                              size_t block_count);
dstu9212_status dstu8845_prng_generate_octets(dstu8845_prng *ctx,
                                              uint8_t *out,
                                              size_t out_len);
dstu9212_status dstu8845_prng_generate(dstu8845_prng *ctx, uint8_t *out, size_t out_len);
void dstu8845_prng_clear(dstu8845_prng *ctx);

#endif
