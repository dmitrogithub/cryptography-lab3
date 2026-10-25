// SPDX-License-Identifier: Apache-2.0
#ifndef DSTU9212_TABLES_H
#define DSTU9212_TABLES_H

#include <stdint.h>

#define DSTU9212_NTT_Z256_LEN 256U
#define DSTU9212_NTT_Z512_LEN 512U

#define DSTU9212_NTT_N256_INV 8347681U
#define DSTU9212_NTT_N512_INV 8364049U

/*
 * Appendix V.1, precomputed NTT tables for n = 256.
 */
extern const uint32_t dstu9212_ntt_z256[DSTU9212_NTT_Z256_LEN];
extern const uint32_t dstu9212_ntt_z256_inv[DSTU9212_NTT_Z256_LEN];

/*
 * Appendix V.2, precomputed NTT tables for n = 512.
 */
extern const uint32_t dstu9212_ntt_z512[DSTU9212_NTT_Z512_LEN];
extern const uint32_t dstu9212_ntt_z512_inv[DSTU9212_NTT_Z512_LEN];

#endif
