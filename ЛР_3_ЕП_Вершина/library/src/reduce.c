// SPDX-License-Identifier: Apache-2.0
#include "reduce.h"

/* Q = 2^23 - 2^13 + 1, hence 2^23 = 2^13 - 1 (mod Q).
 * Five fixed folds reduce every 64-bit input without division or
 * data-dependent control flow. */
uint32_t dstu9212_reduce_u64(uint64_t value)
{
	const uint64_t low_mask = (UINT64_C(1) << 23) - 1U;
	unsigned int i;

	for (i = 0; i < 5U; ++i) {
		value = (value & low_mask) + (value >> 23) * 8191U;
	}

	return dstu9212_csubq(dstu9212_csubq((uint32_t)value));
}

uint32_t dstu9212_reduce_i32_unsigned(int32_t value)
{
	uint32_t bits = (uint32_t)value;
	uint32_t negative = bits >> 31;
	uint32_t mask = 0U - negative;
	uint32_t magnitude = (bits ^ mask) + negative;
	uint32_t reduced = (magnitude & ((1U << 23) - 1U)) +
		(magnitude >> 23) * 8191U;
	uint32_t negated;
	uint32_t select;

	reduced = dstu9212_csubq(reduced);
	negated = dstu9212_csubq((uint32_t)DSTU9212_Q - reduced);
	select = 0U - negative;
	return (reduced & ~select) | (negated & select);
}

int32_t dstu9212_reduce_i32_centered(int32_t value)
{
	uint32_t reduced = dstu9212_reduce_i32_unsigned(value);
	uint32_t above_half = ((uint32_t)(DSTU9212_Q / 2) - reduced) >> 31;

	return (int32_t)reduced - (int32_t)(above_half * DSTU9212_Q);
}

/* The add/sub paths call this with |value| <= UINT32_MAX. One pseudo-Mersenne
 * fold and one conditional subtraction are sufficient for that bound. */
int32_t dstu9212_reduce_i64_bounded_centered(int64_t value)
{
	uint64_t bits = (uint64_t)value;
	uint64_t negative = bits >> 63;
	uint64_t mask = UINT64_C(0) - negative;
	uint64_t magnitude = (bits ^ mask) + negative;
	uint32_t reduced = (uint32_t)((magnitude & ((UINT64_C(1) << 23) - 1U)) +
		(magnitude >> 23) * 8191U);
	uint32_t negated;
	uint32_t select;
	uint32_t above_half;

	reduced = dstu9212_csubq(reduced);
	negated = dstu9212_csubq((uint32_t)DSTU9212_Q - reduced);
	select = 0U - (uint32_t)negative;
	reduced = (reduced & ~select) | (negated & select);
	above_half = ((uint32_t)(DSTU9212_Q / 2) - reduced) >> 31;
	return (int32_t)reduced - (int32_t)(above_half * DSTU9212_Q);
}

uint32_t dstu9212_reduce_i64_unsigned(int64_t value)
{
	uint64_t bits = (uint64_t)value;
	uint64_t negative = bits >> 63;
	uint64_t mask = UINT64_C(0) - negative;
	uint32_t reduced = dstu9212_reduce_u64((bits ^ mask) + negative);
	uint32_t negated = dstu9212_csubq((uint32_t)DSTU9212_Q - reduced);
	uint32_t select = 0U - (uint32_t)negative;

	return (reduced & ~select) | (negated & select);
}

int32_t dstu9212_reduce_i64_centered(int64_t value)
{
	uint32_t reduced = dstu9212_reduce_i64_unsigned(value);
	uint32_t above_half = ((uint32_t)(DSTU9212_Q / 2) - reduced) >> 31;

	return (int32_t)reduced - (int32_t)(above_half * DSTU9212_Q);
}
