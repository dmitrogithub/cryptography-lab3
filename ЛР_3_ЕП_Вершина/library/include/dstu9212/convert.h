// SPDX-License-Identifier: Apache-2.0
#ifndef DSTU9212_CONVERT_H
#define DSTU9212_CONVERT_H

#include <stddef.h>
#include <stdint.h>

#include "parameters.h"
#include "utils.h"

/*
 * Section 6.2.7 helpers.
 * Vectors are stored as size consecutive polynomials, each with DSTU9212_N
 * int32_t coefficients.
 */
size_t dstu9212_vec_os_len(size_t size, unsigned int width);
size_t dstu9212_public_key_os_len(void);
size_t dstu9212_secret_key_os_len(void);
size_t dstu9212_signature_os_len(void);
size_t dstu9212_hint_os_len(void);

/*
 * Section 6.2.7.1, ds_pack_vec.
 */
dstu9212_status dstu9212_pack_vec(
	const int32_t *vec, size_t size, unsigned int width, int32_t base,
	uint8_t *os, size_t os_capacity, size_t *os_len);

/*
 * Section 6.2.7.2, ds_unpack_vec.
 */
dstu9212_status dstu9212_unpack_vec(
	const uint8_t *os, size_t os_len, size_t size,
	unsigned int width, int32_t base, int32_t *vec);

/*
 * Section 6.2.8, ds_pack_pk.
 */
dstu9212_status dstu9212_pack_pk(
	const uint8_t *rho, const int32_t *t1,
	uint8_t *pk, size_t pk_capacity, size_t *pk_len);

/*
 * Section 6.2.9, ds_unpack_pk.
 */
dstu9212_status dstu9212_unpack_pk(
	const uint8_t *pk, size_t pk_len,
	uint8_t *rho, int32_t *t1);

/*
 * Section 6.2.10, ds_pack_sk.
 */
dstu9212_status dstu9212_pack_sk(
	const uint8_t *rho, const uint8_t *key, const uint8_t *tr,
	const int32_t *s1, const int32_t *s2, const int32_t *t0,
	uint8_t *sk, size_t sk_capacity, size_t *sk_len);

/*
 * Section 6.2.11, ds_unpack_sk.
 */
dstu9212_status dstu9212_unpack_sk(
	const uint8_t *sk, size_t sk_len,
	uint8_t *rho, uint8_t *key, uint8_t *tr,
	int32_t *s1, int32_t *s2, int32_t *t0);

/*
 * Section 7.2.6.3.1, ds_pack_matr_h.
 * h is a DSTU9212_K by DSTU9212_N binary matrix in row-major order.
 */
dstu9212_status dstu9212_pack_matr_h(
	const uint8_t *h, uint8_t *os, size_t os_capacity, size_t *os_len);

/*
 * Section 7.2.6.3.2, ds_unpack_matr_h.
 */
dstu9212_status dstu9212_unpack_matr_h(
	const uint8_t *os, size_t os_len, uint8_t *h);

/*
 * Section 7.2.6.1, ds_pack_ds.
 */
dstu9212_status dstu9212_pack_ds(
	const uint8_t *seed, const int32_t *z, const uint8_t *h,
	uint8_t *ds, size_t ds_capacity, size_t *ds_len);

/*
 * Section 7.2.6.2, ds_unpack_ds.
 */
dstu9212_status dstu9212_unpack_ds(
	const uint8_t *ds, size_t ds_len,
	uint8_t *seed, int32_t *z, uint8_t *h);

#endif
