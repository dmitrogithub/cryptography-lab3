// SPDX-License-Identifier: Apache-2.0
#include "dstu9212/poly.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fill_poly(int32_t *a, int seed)
{
	size_t i;

	for (i = 0; i < DSTU9212_N; ++i) {
		int64_t value = (int64_t)(i + 1U) * (seed * 271 + 17);

		if ((i & 1U) != 0U) {
			value = -value;
		}
		a[i] = dstu9212_mod_q_centered(value);
	}
}

static void naive_negacyclic_mul(int32_t *c, const int32_t *a, const int32_t *b)
{
	size_t i;

	for (i = 0; i < DSTU9212_N; ++i) {
		c[i] = 0;
	}
	for (i = 0; i < DSTU9212_N; ++i) {
		size_t j;

		for (j = 0; j < DSTU9212_N; ++j) {
			size_t idx = i + j;
			int64_t term = (int64_t)a[i] * b[j];

			if (idx >= DSTU9212_N) {
				idx -= DSTU9212_N;
				term = -term;
			}
			c[idx] = dstu9212_mod_q_centered((int64_t)c[idx] + term);
		}
	}
}

static int test_mod_q(void)
{
	if (dstu9212_mod_q_unsigned(-1) != DSTU9212_Q - 1U ||
		dstu9212_mod_q_centered(DSTU9212_Q - 1) != -1 ||
		dstu9212_mod_q_centered((DSTU9212_Q - 1) / 2) != (DSTU9212_Q - 1) / 2 ||
		dstu9212_mod_q_centered((DSTU9212_Q + 1) / 2) != -(DSTU9212_Q - 1) / 2) {
		return 1;
	}

	return 0;
}

static int test_poly_basic(void)
{
	int32_t a[DSTU9212_N];
	int32_t b[DSTU9212_N];
	int32_t c[DSTU9212_N];
	size_t i;

	fill_poly(a, 1);
	fill_poly(b, 2);
	if (dstu9212_pol_add(c, a, b, DSTU9212_N) != DSTU9212_OK) {
		return 1;
	}
	for (i = 0; i < DSTU9212_N; ++i) {
		if (c[i] != dstu9212_mod_q_centered((int64_t)a[i] + b[i])) {
			return 1;
		}
	}
	if (dstu9212_pol_sub(c, a, b, DSTU9212_N) != DSTU9212_OK) {
		return 1;
	}
	for (i = 0; i < DSTU9212_N; ++i) {
		if (c[i] != dstu9212_mod_q_centered((int64_t)a[i] - b[i])) {
			return 1;
		}
	}
	if (dstu9212_pol_cmul(c, -7, a, DSTU9212_N) != DSTU9212_OK) {
		return 1;
	}
	for (i = 0; i < DSTU9212_N; ++i) {
		if (c[i] != dstu9212_mod_q_centered((int64_t)-7 * a[i])) {
			return 1;
		}
	}

	return 0;
}

static int test_ntt_roundtrip(void)
{
	int32_t a[DSTU9212_N];
	int32_t expected[DSTU9212_N];
	size_t i;

	fill_poly(a, 3);
	for (i = 0; i < DSTU9212_N; ++i) {
		expected[i] = (int32_t)dstu9212_mod_q_unsigned(a[i]);
	}

	if (dstu9212_ntt(a, DSTU9212_N) != DSTU9212_OK ||
		dstu9212_ntt_inv(a, DSTU9212_N) != DSTU9212_OK) {
		return 1;
	}
	for (i = 0; i < DSTU9212_N; ++i) {
		if (a[i] != expected[i]) {
			return 1;
		}
	}

	return 0;
}

static int test_pointwize_matches_naive(void)
{
	int32_t a[DSTU9212_N];
	int32_t b[DSTU9212_N];
	int32_t a_ntt[DSTU9212_N];
	int32_t b_ntt[DSTU9212_N];
	int32_t c[DSTU9212_N];
	int32_t expected[DSTU9212_N];
	size_t i;

	fill_poly(a, 4);
	fill_poly(b, 5);
	memcpy(a_ntt, a, sizeof(a));
	memcpy(b_ntt, b, sizeof(b));
	naive_negacyclic_mul(expected, a, b);

	if (dstu9212_ntt(a_ntt, DSTU9212_N) != DSTU9212_OK ||
		dstu9212_ntt(b_ntt, DSTU9212_N) != DSTU9212_OK ||
		dstu9212_pointwize(c, a_ntt, b_ntt, DSTU9212_N) != DSTU9212_OK ||
		dstu9212_ntt_inv(c, DSTU9212_N) != DSTU9212_OK) {
		return 1;
	}
	for (i = 0; i < DSTU9212_N; ++i) {
		if (dstu9212_mod_q_centered(c[i]) != expected[i]) {
			return 1;
		}
	}

	return 0;
}

static int test_vec_and_matrix(void)
{
	enum { SIZE = 3, ROWS = 2 };
	int32_t a[SIZE * DSTU9212_N];
	int32_t b[SIZE * DSTU9212_N];
	int32_t mul[SIZE * DSTU9212_N];
	int32_t smul[DSTU9212_N];
	int32_t expected[DSTU9212_N];
	int32_t matrix[ROWS * SIZE * DSTU9212_N];
	int32_t mv[ROWS * DSTU9212_N];
	size_t i;
	size_t j;

	for (i = 0; i < SIZE; ++i) {
		fill_poly(a + i * DSTU9212_N, (int)i + 6);
		fill_poly(b + i * DSTU9212_N, (int)i + 10);
	}
	if (dstu9212_vec_ntt(a, SIZE, SIZE * DSTU9212_N) != DSTU9212_OK ||
		dstu9212_vec_ntt(b, SIZE, SIZE * DSTU9212_N) != DSTU9212_OK ||
		dstu9212_vec_mul(mul, a, b, SIZE, SIZE * DSTU9212_N) != DSTU9212_OK ||
		dstu9212_vec_smul(smul, a, b, SIZE, DSTU9212_N) != DSTU9212_OK) {
		return 1;
	}
	for (j = 0; j < DSTU9212_N; ++j) {
		expected[j] = 0;
		for (i = 0; i < SIZE; ++i) {
			expected[j] = (int32_t)(((uint64_t)(uint32_t)expected[j] +
				(uint32_t)mul[i * DSTU9212_N + j]) % DSTU9212_Q);
		}
		if (smul[j] != expected[j]) {
			return 1;
		}
	}

	for (i = 0; i < ROWS * SIZE * DSTU9212_N; ++i) {
		matrix[i] = a[i % (SIZE * DSTU9212_N)];
	}
	if (dstu9212_matr_vec_mul(mv, matrix, b, ROWS, SIZE, ROWS * DSTU9212_N) != DSTU9212_OK) {
		return 1;
	}
	for (i = 0; i < ROWS; ++i) {
		if (memcmp(mv + i * DSTU9212_N, smul, DSTU9212_N * sizeof(*smul)) != 0) {
			return 1;
		}
	}

	return 0;
}

int main(void)
{
	if (test_mod_q() != 0 ||
		test_poly_basic() != 0 ||
		test_ntt_roundtrip() != 0 ||
		test_pointwize_matches_naive() != 0 ||
		test_vec_and_matrix() != 0) {
		fprintf(stderr, "test_poly failed\n");
		return 1;
	}

	return 0;
}
