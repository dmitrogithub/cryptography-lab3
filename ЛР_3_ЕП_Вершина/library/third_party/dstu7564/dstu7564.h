// SPDX-License-Identifier: Apache-2.0
#ifndef DSTU7564_H
#define DSTU7564_H

#include <stddef.h>
#include <stdint.h>

#include "dstu9212/parameters.h"
#include "dstu9212/utils.h"

#define DSTU7564_HASH256_BYTES 32
#define DSTU7564_HASH512_BYTES 64

dstu9212_status dstu7564_hash_256(const uint8_t *data, size_t data_len, uint8_t out[DSTU7564_HASH256_BYTES]);
dstu9212_status dstu7564_hash_512(const uint8_t *data, size_t data_len, uint8_t out[DSTU7564_HASH512_BYTES]);

/*
 * DSTU 9212 appendix B.4 universal Hash function.
 * Produces HASH_OCTETS bytes for the selected DSTU9212_MODE.
 */
dstu9212_status dstu9212_hash(const uint8_t *data, size_t data_len,
                              uint8_t out[DSTU9212_HASH_OCTETS]);
dstu9212_status dstu9212_hash_with_byte(const uint8_t *data, size_t data_len,
                                        uint8_t suffix,
                                        uint8_t out[DSTU9212_HASH_OCTETS]);

#endif
