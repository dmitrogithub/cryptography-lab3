// SPDX-License-Identifier: Apache-2.0
#include "dstu9212/poly.h"
#include "dstu9212/utils.h"
#include "dstu9212/tables.h"
#include "ntt_tables.h"
#include "reduce.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>

static uint32_t reference_i64_unsigned(int64_t value)
{
	int64_t reduced = value % (int64_t)DSTU9212_Q;

	if (reduced < 0) {
		reduced += DSTU9212_Q;
	}
	return (uint32_t)reduced;
}

static int32_t reference_i64_centered(int64_t value)
{
	uint32_t reduced = reference_i64_unsigned(value);

	if (reduced > DSTU9212_Q / 2U) {
		return (int32_t)reduced - DSTU9212_Q;
	}
	return (int32_t)reduced;
}

static int test_fixed_inputs(void)
{
	static const int64_t inputs[] = {
		INT64_MIN, INT64_MIN + 1, -((int64_t)DSTU9212_Q * DSTU9212_Q),
		-(int64_t)DSTU9212_Q - 1, -(int64_t)DSTU9212_Q,
		-(int64_t)DSTU9212_Q + 1, -1, 0, 1,
		(int64_t)DSTU9212_Q - 1, DSTU9212_Q,
		(int64_t)DSTU9212_Q + 1,
		(int64_t)DSTU9212_Q * DSTU9212_Q, INT64_MAX - 1, INT64_MAX
	};
	size_t i;

	for (i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i) {
		if (dstu9212_reduce_i64_unsigned(inputs[i]) !=
				reference_i64_unsigned(inputs[i]) ||
			dstu9212_reduce_i64_centered(inputs[i]) !=
				reference_i64_centered(inputs[i]) ||
			dstu9212_mod_q_unsigned(inputs[i]) !=
				reference_i64_unsigned(inputs[i]) ||
			dstu9212_mod_q_centered(inputs[i]) !=
				reference_i64_centered(inputs[i])) {
			return 1;
		}
	}

	return 0;
}

static int test_random_inputs(void)
{
	uint64_t state = UINT64_C(0x243f6a8885a308d3);
	size_t i;

	for (i = 0; i < 200000U; ++i) {
		int64_t signed_value;
		uint32_t a;
		uint32_t b;

		state ^= state << 13;
		state ^= state >> 7;
		state ^= state << 17;
		signed_value = (int64_t)(state & (uint64_t)INT64_MAX);
		if ((state & 1U) != 0U) {
			signed_value = -signed_value;
		}
		if (dstu9212_reduce_u64(state) != (uint32_t)(state % DSTU9212_Q) ||
			dstu9212_reduce_i64_unsigned(signed_value) !=
				reference_i64_unsigned(signed_value) ||
			dstu9212_reduce_i64_centered(signed_value) !=
				reference_i64_centered(signed_value)) {
			return 1;
		}

		a = (uint32_t)(state % DSTU9212_Q);
		b = (uint32_t)((state >> 23) % DSTU9212_Q);
		if (dstu9212_montgomery_reduce(dstu9212_to_montgomery(a)) != a ||
			dstu9212_mul_mod(a, b) !=
				(uint32_t)(((uint64_t)a * b) % DSTU9212_Q)) {
			return 1;
		}
	}

	return 0;
}

static int test_bounded_paths(void)
{
	static const int32_t values[] = {
		INT32_MIN, INT32_MIN + 1, -DSTU9212_Q, -1, 0, 1,
		DSTU9212_Q, INT32_MAX - 1, INT32_MAX
	};
	size_t i;
	size_t j;

	for (i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
		if (dstu9212_reduce_i32_unsigned(values[i]) !=
				reference_i64_unsigned(values[i]) ||
			dstu9212_reduce_i32_centered(values[i]) !=
				reference_i64_centered(values[i])) {
			return 1;
		}
		for (j = 0; j < sizeof(values) / sizeof(values[0]); ++j) {
			int64_t sum = (int64_t)values[i] + values[j];
			int64_t difference = (int64_t)values[i] - values[j];

			if (dstu9212_reduce_i64_bounded_centered(sum) !=
					reference_i64_centered(sum) ||
				dstu9212_reduce_i64_bounded_centered(difference) !=
					reference_i64_centered(difference)) {
				return 1;
			}
		}
	}

	return 0;
}

static int test_constant_time_helpers(void)
{
	uint8_t a[32] = {0};
	uint8_t b[32] = {0};
	uint8_t secret[32];
	size_t i;

	if (!dstu9212_constant_time_equal(a, b, sizeof(a)) ||
		!dstu9212_constant_time_equal(NULL, NULL, 0U)) {
		return 1;
	}
	for (i = 0; i < sizeof(b); ++i) {
		b[i] = 1U;
		if (dstu9212_constant_time_equal(a, b, sizeof(a))) {
			return 1;
		}
		b[i] = 0U;
		secret[i] = (uint8_t)(i + 1U);
	}
	dstu9212_secure_zero(secret, sizeof(secret));
	for (i = 0; i < sizeof(secret); ++i) {
		if (secret[i] != 0U) {
			return 1;
		}
	}
	return 0;
}

static int test_montgomery_ntt_tables(void)
{
	const uint32_t *standard = DSTU9212_N == 256U ?
		dstu9212_ntt_z256 : dstu9212_ntt_z512;
	const uint32_t *montgomery = DSTU9212_N == 256U ?
		dstu9212_ntt_z256_mont : dstu9212_ntt_z512_mont;
	size_t i;

	for (i = 0; i < DSTU9212_N; ++i) {
		if (dstu9212_montgomery_reduce(montgomery[i]) != standard[i]) {
			return 1;
		}
	}
	return 0;
}

int main(void)
{
	if (test_fixed_inputs() != 0 || test_random_inputs() != 0 ||
		test_bounded_paths() != 0 || test_constant_time_helpers() != 0 ||
		test_montgomery_ntt_tables() != 0) {
		fprintf(stderr, "test_reduce failed\n");
		return 1;
	}
	return 0;
}
