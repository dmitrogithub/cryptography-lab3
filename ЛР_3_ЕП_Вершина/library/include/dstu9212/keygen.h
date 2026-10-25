// SPDX-License-Identifier: Apache-2.0
#ifndef DSTU9212_KEYGEN_H
#define DSTU9212_KEYGEN_H

#include <stddef.h>
#include <stdint.h>

#include <dstu9212/parameters.h>
#include <dstu9212/utils.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Section 6.2 key generation helpers.
 * Vectors and matrices are stored as consecutive polynomials, each with
 * DSTU9212_N int32_t coefficients.
 */
size_t dstu9212_matrix_coeff_count(void);
size_t dstu9212_s1_coeff_count(void);
size_t dstu9212_s2_coeff_count(void);
size_t dstu9212_secret_coeff_count(void);

/*
 * Section 6.2.3, ds_gen_key.
 */
dstu9212_status dstu9212_gen_key(
	const uint8_t rho[DSTU9212_SEED_OCTETS],
	const uint8_t rho1[DSTU9212_SEED_OCTETS],
	const uint8_t key[DSTU9212_SEED_OCTETS],
	uint8_t *pk, size_t pk_capacity, size_t *pk_len,
	uint8_t *sk, size_t sk_capacity, size_t *sk_len);

/*
 * Section 6.2.6, ds_gen_hl.
 */
dstu9212_status dstu9212_gen_hl(
	const int32_t *t, int32_t base,
	int32_t *t1, int32_t *t0, size_t capacity);

/*
 * Section 6.2.5.2, ds_expand_s_values.
 */
dstu9212_status dstu9212_expand_s_values(
	const uint8_t *src, size_t src_len,
	int32_t *dst, size_t dst_capacity, size_t *dst_len);

/*
 * Section 6.2.5.1, ds_expand_s.
 */
dstu9212_status dstu9212_expand_s_flat(
	const uint8_t rho1[DSTU9212_SEED_OCTETS],
	int32_t *s, size_t s_capacity);

/*
 * Section 6.2.5.1, ds_expand_s.
 */
dstu9212_status dstu9212_expand_s(
	const uint8_t rho1[DSTU9212_SEED_OCTETS],
	int32_t *s1, size_t s1_capacity,
	int32_t *s2, size_t s2_capacity);

/*
 * Section 6.2.4, ds_expand_matr.
 */
dstu9212_status dstu9212_expand_matr(
	const uint8_t rho[DSTU9212_SEED_OCTETS],
	int32_t *a, size_t a_capacity);

#ifdef __cplusplus
}
#endif

#endif
