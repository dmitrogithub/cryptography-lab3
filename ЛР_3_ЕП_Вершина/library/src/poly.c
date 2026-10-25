// SPDX-License-Identifier: Apache-2.0
#include "dstu9212/poly.h"

#include "dstu9212/tables.h"
#include "ntt_tables.h"
#include "reduce.h"

#include <stdint.h>

static dstu9212_status checked_vec_coeff_count(size_t size, size_t *coeff_count)
{
	if (coeff_count == NULL || size > SIZE_MAX / DSTU9212_N) {
		return DSTU9212_ERROR;
	}

	*coeff_count = size * DSTU9212_N;
	return DSTU9212_OK;
}

static dstu9212_status checked_matr_coeff_count(size_t rows, size_t cols, size_t *coeff_count)
{
	size_t pol_count;

	if (coeff_count == NULL ||
		(rows != 0U && cols > SIZE_MAX / rows)) {
		return DSTU9212_ERROR;
	}

	pol_count = rows * cols;
	if (pol_count > SIZE_MAX / DSTU9212_N) {
		return DSTU9212_ERROR;
	}

	*coeff_count = pol_count * DSTU9212_N;
	return DSTU9212_OK;
}

static dstu9212_status check_poly_output(
	int32_t *c, const int32_t *a, const int32_t *b, size_t c_capacity)
{
	if (c == NULL || a == NULL || b == NULL || c_capacity < DSTU9212_N) {
		return DSTU9212_ERROR;
	}

	return DSTU9212_OK;
}

static const uint32_t *ntt_table(void)
{
	return DSTU9212_N == 256 ? dstu9212_ntt_z256_mont : dstu9212_ntt_z512_mont;
}

static uint32_t ntt_inv_n(void)
{
	return DSTU9212_N == 256 ? DSTU9212_NTT_N256_INV : DSTU9212_NTT_N512_INV;
}

int32_t dstu9212_mod_q_centered(int64_t value)
{
	return dstu9212_reduce_i64_centered(value);
}

uint32_t dstu9212_mod_q_unsigned(int64_t value)
{
	return dstu9212_reduce_i64_unsigned(value);
}

/*
 * Appendix B.2.1.1, pol_add.
 */
dstu9212_status dstu9212_pol_add(
	int32_t *c, const int32_t *a, const int32_t *b, size_t c_capacity)
{
	size_t i;

	if (check_poly_output(c, a, b, c_capacity) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < DSTU9212_N; ++i) {
		c[i] = dstu9212_reduce_i64_bounded_centered((int64_t)a[i] + b[i]);
	}

	return DSTU9212_OK;
}

/*
 * Appendix B.2.1.2, pol_sub.
 */
dstu9212_status dstu9212_pol_sub(
	int32_t *c, const int32_t *a, const int32_t *b, size_t c_capacity)
{
	size_t i;

	if (check_poly_output(c, a, b, c_capacity) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < DSTU9212_N; ++i) {
		c[i] = dstu9212_reduce_i64_bounded_centered((int64_t)a[i] - b[i]);
	}

	return DSTU9212_OK;
}

/*
 * Appendix B.2.1.3, pol_cmul.
 */
dstu9212_status dstu9212_pol_cmul(
	int32_t *b, int32_t scalar, const int32_t *a, size_t b_capacity)
{
	size_t i;

	if (b == NULL || a == NULL || b_capacity < DSTU9212_N) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < DSTU9212_N; ++i) {
		b[i] = dstu9212_mod_q_centered((int64_t)scalar * a[i]);
	}

	return DSTU9212_OK;
}

/*
 * Appendix B.2.1.4.1, ntt.
 */
dstu9212_status dstu9212_ntt(int32_t *a, size_t capacity)
{
	const uint32_t *z = ntt_table();
	size_t f = 1U;
	size_t g = DSTU9212_N / 2U;
	size_t i;

	if (a == NULL || capacity < DSTU9212_N) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < DSTU9212_N; ++i)
		a[i] = (int32_t)dstu9212_reduce_i32_unsigned(a[i]);

	while (g > 0U) {
		size_t s;

		for (s = 0U; s < DSTU9212_N;) {
			uint32_t temp = z[f];
			size_t j;

			for (j = s; j < s + g; ++j) {
				uint32_t t = dstu9212_montgomery_reduce(
					(uint64_t)temp * (uint32_t)a[j + g]);
				uint32_t aj = (uint32_t)a[j];

				a[j + g] = (int32_t)dstu9212_sub_mod(aj, t);
				a[j] = (int32_t)dstu9212_add_mod(aj, t);
			}
			++f;
			s = j + g;
		}
		g /= 2U;
	}

	return DSTU9212_OK;
}

/*
 * Appendix B.2.1.4.2, ntt_.
 */
dstu9212_status dstu9212_ntt_inv(int32_t *a, size_t capacity)
{
	const uint32_t *z = ntt_table();
	uint32_t n_inv = ntt_inv_n();
	size_t f = 0U;
	size_t g = 1U;
	size_t i;

	if (a == NULL || capacity < DSTU9212_N) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < DSTU9212_N; ++i)
		a[i] = (int32_t)dstu9212_reduce_i32_unsigned(a[i]);

	while (g < DSTU9212_N) {
		size_t s = 0U;

		while (s < DSTU9212_N) {
			size_t j;

			uint32_t zeta = (uint32_t)DSTU9212_Q - z[DSTU9212_N - 1U - f];

			for (j = s; j < s + g; ++j) {
				uint32_t t = (uint32_t)a[j];
				uint32_t ajg = (uint32_t)a[j + g];

				a[j] = (int32_t)dstu9212_add_mod(t, ajg);
				a[j + g] = (int32_t)dstu9212_montgomery_reduce(
					(uint64_t)zeta * dstu9212_sub_mod(t, ajg));
			}
			++f;
			s = j + g;
		}
		g *= 2U;
	}

	n_inv = dstu9212_to_montgomery(n_inv);
	for (i = 0; i < DSTU9212_N; ++i)
		a[i] = (int32_t)dstu9212_montgomery_reduce(
			(uint64_t)n_inv * (uint32_t)a[i]);

	return DSTU9212_OK;
}

/*
 * Appendix B.2.1.4.3, pointwize.
 */
dstu9212_status dstu9212_pointwize(
	int32_t *c, const int32_t *a, const int32_t *b, size_t c_capacity)
{
	size_t i;

	if (check_poly_output(c, a, b, c_capacity) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < DSTU9212_N; ++i) {
		uint32_t ai = dstu9212_reduce_i32_unsigned(a[i]);
		uint32_t bi = dstu9212_reduce_i32_unsigned(b[i]);

		c[i] = (int32_t)dstu9212_mul_mod(ai, bi);
	}

	return DSTU9212_OK;
}

dstu9212_status dstu9212_vec_ntt(int32_t *vec, size_t size, size_t capacity)
{
	size_t coeff_count;
	size_t i;

	if (vec == NULL ||
		checked_vec_coeff_count(size, &coeff_count) != DSTU9212_OK ||
		capacity < coeff_count) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < size; ++i) {
		if (dstu9212_ntt(vec + i * DSTU9212_N, DSTU9212_N) != DSTU9212_OK) {
			return DSTU9212_ERROR;
		}
	}

	return DSTU9212_OK;
}

dstu9212_status dstu9212_vec_ntt_inv(int32_t *vec, size_t size, size_t capacity)
{
	size_t coeff_count;
	size_t i;

	if (vec == NULL ||
		checked_vec_coeff_count(size, &coeff_count) != DSTU9212_OK ||
		capacity < coeff_count) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < size; ++i) {
		if (dstu9212_ntt_inv(vec + i * DSTU9212_N, DSTU9212_N) != DSTU9212_OK) {
			return DSTU9212_ERROR;
		}
	}

	return DSTU9212_OK;
}

dstu9212_status dstu9212_vec_add(
	int32_t *c, const int32_t *a, const int32_t *b, size_t size, size_t c_capacity)
{
	size_t coeff_count;
	size_t i;

	if (c == NULL || a == NULL || b == NULL ||
		checked_vec_coeff_count(size, &coeff_count) != DSTU9212_OK ||
		c_capacity < coeff_count) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < size; ++i) {
		if (dstu9212_pol_add(
				c + i * DSTU9212_N, a + i * DSTU9212_N,
				b + i * DSTU9212_N, DSTU9212_N) != DSTU9212_OK) {
			return DSTU9212_ERROR;
		}
	}

	return DSTU9212_OK;
}

dstu9212_status dstu9212_vec_sub(
	int32_t *c, const int32_t *a, const int32_t *b, size_t size, size_t c_capacity)
{
	size_t coeff_count;
	size_t i;

	if (c == NULL || a == NULL || b == NULL ||
		checked_vec_coeff_count(size, &coeff_count) != DSTU9212_OK ||
		c_capacity < coeff_count) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < size; ++i) {
		if (dstu9212_pol_sub(
				c + i * DSTU9212_N, a + i * DSTU9212_N,
				b + i * DSTU9212_N, DSTU9212_N) != DSTU9212_OK) {
			return DSTU9212_ERROR;
		}
	}

	return DSTU9212_OK;
}

dstu9212_status dstu9212_vec_cmul(
	int32_t *b, int32_t scalar, const int32_t *a, size_t size, size_t b_capacity)
{
	size_t coeff_count;
	size_t i;

	if (b == NULL || a == NULL ||
		checked_vec_coeff_count(size, &coeff_count) != DSTU9212_OK ||
		b_capacity < coeff_count) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < size; ++i) {
		if (dstu9212_pol_cmul(
				b + i * DSTU9212_N, scalar,
				a + i * DSTU9212_N, DSTU9212_N) != DSTU9212_OK) {
			return DSTU9212_ERROR;
		}
	}

	return DSTU9212_OK;
}

dstu9212_status dstu9212_vec_mul(
	int32_t *c, const int32_t *a, const int32_t *b, size_t size, size_t c_capacity)
{
	size_t coeff_count;
	size_t i;

	if (c == NULL || a == NULL || b == NULL ||
		checked_vec_coeff_count(size, &coeff_count) != DSTU9212_OK ||
		c_capacity < coeff_count) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < size; ++i) {
		if (dstu9212_pointwize(
				c + i * DSTU9212_N, a + i * DSTU9212_N,
				b + i * DSTU9212_N, DSTU9212_N) != DSTU9212_OK) {
			return DSTU9212_ERROR;
		}
	}

	return DSTU9212_OK;
}

/*
 * Appendix B.2.2.2, vec_smul.
 */
dstu9212_status dstu9212_vec_smul(
	int32_t *c, const int32_t *a, const int32_t *b, size_t size, size_t c_capacity)
{
	size_t coeff_count;
	size_t i;
	size_t j;

	if (c == NULL || a == NULL || b == NULL ||
		checked_vec_coeff_count(size, &coeff_count) != DSTU9212_OK ||
		c_capacity < DSTU9212_N) {
		return DSTU9212_ERROR;
	}

	(void)coeff_count;
	for (j = 0; j < DSTU9212_N; ++j) {
		c[j] = 0;
	}
	for (i = 0; i < size; ++i) {
		for (j = 0; j < DSTU9212_N; ++j) {
			uint32_t ai = dstu9212_reduce_i32_unsigned(a[i * DSTU9212_N + j]);
			uint32_t bi = dstu9212_reduce_i32_unsigned(b[i * DSTU9212_N + j]);
			uint32_t term = dstu9212_mul_mod(ai, bi);

			c[j] = (int32_t)dstu9212_add_mod((uint32_t)c[j], term);
		}
	}

	return DSTU9212_OK;
}

/*
 * Appendix B.2.3, matr_vec_mul.
 */
dstu9212_status dstu9212_matr_vec_mul(
	int32_t *c, const int32_t *a, const int32_t *b,
	size_t rows, size_t cols, size_t c_capacity)
{
	size_t matrix_coeff_count;
	size_t c_coeff_count;
	size_t i;

	if (c == NULL || a == NULL || b == NULL ||
		checked_matr_coeff_count(rows, cols, &matrix_coeff_count) != DSTU9212_OK ||
		checked_vec_coeff_count(rows, &c_coeff_count) != DSTU9212_OK ||
		c_capacity < c_coeff_count) {
		return DSTU9212_ERROR;
	}

	(void)matrix_coeff_count;
	for (i = 0; i < rows; ++i) {
		if (dstu9212_vec_smul(
				c + i * DSTU9212_N, a + i * cols * DSTU9212_N,
				b, cols, DSTU9212_N) != DSTU9212_OK) {
			return DSTU9212_ERROR;
		}
	}

	return DSTU9212_OK;
}
