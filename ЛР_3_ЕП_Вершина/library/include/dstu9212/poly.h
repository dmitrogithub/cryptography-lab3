// SPDX-License-Identifier: Apache-2.0
#ifndef DSTU9212_POLY_H
#define DSTU9212_POLY_H

#include <stddef.h>
#include <stdint.h>

#include <dstu9212/parameters.h>
#include <dstu9212/utils.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Appendix B.1, representation of ring elements.
 */
int32_t dstu9212_mod_q_centered(int64_t value);
uint32_t dstu9212_mod_q_unsigned(int64_t value);

/*
 * Appendix B.2.1.1, pol_add.
 */
dstu9212_status dstu9212_pol_add(
	int32_t *c, const int32_t *a, const int32_t *b, size_t c_capacity);

/*
 * Appendix B.2.1.2, pol_sub.
 */
dstu9212_status dstu9212_pol_sub(
	int32_t *c, const int32_t *a, const int32_t *b, size_t c_capacity);

/*
 * Appendix B.2.1.3, pol_cmul.
 */
dstu9212_status dstu9212_pol_cmul(
	int32_t *b, int32_t scalar, const int32_t *a, size_t b_capacity);

/*
 * Appendix B.2.1.4.1, ntt.
 */
dstu9212_status dstu9212_ntt(int32_t *a, size_t capacity);

/*
 * Appendix B.2.1.4.2, ntt_.
 */
dstu9212_status dstu9212_ntt_inv(int32_t *a, size_t capacity);

/*
 * Appendix B.2.1.4.3, pointwize.
 */
dstu9212_status dstu9212_pointwize(
	int32_t *c, const int32_t *a, const int32_t *b, size_t c_capacity);

/*
 * Appendix B.2.2.1, vector component-wise operations.
 */
dstu9212_status dstu9212_vec_ntt(int32_t *vec, size_t size, size_t capacity);
dstu9212_status dstu9212_vec_ntt_inv(int32_t *vec, size_t size, size_t capacity);
dstu9212_status dstu9212_vec_add(
	int32_t *c, const int32_t *a, const int32_t *b, size_t size, size_t c_capacity);
dstu9212_status dstu9212_vec_sub(
	int32_t *c, const int32_t *a, const int32_t *b, size_t size, size_t c_capacity);
dstu9212_status dstu9212_vec_cmul(
	int32_t *b, int32_t scalar, const int32_t *a, size_t size, size_t b_capacity);
dstu9212_status dstu9212_vec_mul(
	int32_t *c, const int32_t *a, const int32_t *b, size_t size, size_t c_capacity);

/*
 * Appendix B.2.2.2, vec_smul.
 */
dstu9212_status dstu9212_vec_smul(
	int32_t *c, const int32_t *a, const int32_t *b, size_t size, size_t c_capacity);

/*
 * Appendix B.2.3, matr_vec_mul.
 * Matrix A is stored in row-major order as rows * cols consecutive polynomials.
 */
dstu9212_status dstu9212_matr_vec_mul(
	int32_t *c, const int32_t *a, const int32_t *b,
	size_t rows, size_t cols, size_t c_capacity);

#ifdef __cplusplus
}
#endif

#endif
