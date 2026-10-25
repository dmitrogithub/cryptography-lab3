// SPDX-License-Identifier: Apache-2.0
#ifndef DSTU9212_REDUCE_INTERNAL_H
#define DSTU9212_REDUCE_INTERNAL_H

#include <stdint.h>

#include "dstu9212/parameters.h"

#define DSTU9212_MONT 4193792U
#define DSTU9212_MONT_R2 2365951U
#define DSTU9212_QINV_NEG 4236238847U

static inline uint32_t dstu9212_csubq(uint32_t a)
{
	uint32_t t = a - (uint32_t)DSTU9212_Q;

	return t + ((0U - (t >> 31)) & (uint32_t)DSTU9212_Q);
}

static inline uint32_t dstu9212_add_mod(uint32_t a, uint32_t b)
{
	return dstu9212_csubq(a + b);
}

static inline uint32_t dstu9212_sub_mod(uint32_t a, uint32_t b)
{
	uint32_t t = a - b;

	return t + ((0U - (t >> 31)) & (uint32_t)DSTU9212_Q);
}

/* Unsigned Montgomery reduction. The input bound used by this project is
 * below Q^2, so the result is a canonical representative in [0,Q). */
static inline uint32_t dstu9212_montgomery_reduce(uint64_t a)
{
	uint32_t m = (uint32_t)a * DSTU9212_QINV_NEG;
	uint32_t t = (uint32_t)((a + (uint64_t)m * DSTU9212_Q) >> 32);

	return dstu9212_csubq(t);
}

static inline uint32_t dstu9212_to_montgomery(uint32_t a)
{
	return dstu9212_montgomery_reduce((uint64_t)a * DSTU9212_MONT_R2);
}

static inline uint32_t dstu9212_mul_mod(uint32_t a, uint32_t b)
{
	const uint64_t low_mask = (UINT64_C(1) << 23) - 1U;
	uint64_t product = (uint64_t)a * b;

	/* For canonical a and b, three fixed pseudo-Mersenne folds reduce the
	 * product below 2Q. This avoids both division and a second Montgomery
	 * conversion in pointwise products. */
	product = (product & low_mask) + (product >> 23) * 8191U;
	product = (product & low_mask) + (product >> 23) * 8191U;
	product = (product & low_mask) + (product >> 23) * 8191U;
	return dstu9212_csubq((uint32_t)product);
}

uint32_t dstu9212_reduce_u64(uint64_t value);
uint32_t dstu9212_reduce_i32_unsigned(int32_t value);
int32_t dstu9212_reduce_i32_centered(int32_t value);
int32_t dstu9212_reduce_i64_bounded_centered(int64_t value);
uint32_t dstu9212_reduce_i64_unsigned(int64_t value);
int32_t dstu9212_reduce_i64_centered(int64_t value);

#endif
