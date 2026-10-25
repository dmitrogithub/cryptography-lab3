// SPDX-License-Identifier: Apache-2.0
#ifndef DSTU9212_SIGN_H
#define DSTU9212_SIGN_H

#include <stddef.h>
#include <stdint.h>

#include <dstu9212/parameters.h>
#include <dstu9212/utils.h>
#include <dstu8845/dstu8845.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Section 7.2 signing helpers.
 * Vectors and matrices are stored as consecutive polynomials, each with
 * DSTU9212_N int32_t coefficients. Matrix h is stored as DSTU9212_K by
 * DSTU9212_N uint8_t values in row-major order.
 */
size_t dstu9212_y_coeff_count(void);
size_t dstu9212_w1_coeff_count(void);
size_t dstu9212_hint_coeff_count(void);

/*
 * Section 7.1, ds_sign.
 * If variant is non-zero, ctx must point to an initialized PRNG context.
 */
dstu9212_status dstu9212_sign(
	const uint8_t *m, size_t m_len,
	const uint8_t *sk, size_t sk_len,
	int variant, dstu8845_prng *ctx,
	uint8_t *ds, size_t ds_capacity, size_t *ds_len);

/*
 * Section 8.1, ds_verify.
 */
dstu9212_status dstu9212_verify(
	const uint8_t *m, size_t m_len,
	const uint8_t *pk, size_t pk_len,
	const uint8_t *ds, size_t ds_len);

/*
 * Section 7.2.1, ds_gen_y.
 */
dstu9212_status dstu9212_gen_y(
	dstu8845_prng *ctx, int32_t *y, size_t y_capacity);

/*
 * Section 7.2.2, ds_prepare_gen_c.
 */
dstu9212_status dstu9212_prepare_gen_c(
	const uint8_t mu[DSTU9212_HASH_OCTETS], const int32_t *w1,
	uint8_t seed[DSTU9212_SEED_OCTETS]);

/*
 * Section 7.2.3, ds_gen_c.
 */
dstu9212_status dstu9212_gen_c(
	const uint8_t seed[DSTU9212_SEED_OCTETS],
	int32_t *c, size_t c_capacity);

/*
 * Section 7.2.4, ds_check.
 */
dstu9212_status dstu9212_check(
	const int32_t *src, int32_t norma, size_t src_capacity);

/*
 * Section 7.2.4, ds_check_vect.
 */
dstu9212_status dstu9212_check_vect(
	const int32_t *src, size_t src_size, int32_t norma, size_t src_capacity);

/*
 * Section 7.2.5, ds_gen_h.
 */
dstu9212_status dstu9212_gen_h(
	const int32_t *vec1, const int32_t *vec2,
	uint8_t *h, size_t h_capacity, size_t *cnt);

#ifdef __cplusplus
}
#endif

#endif
