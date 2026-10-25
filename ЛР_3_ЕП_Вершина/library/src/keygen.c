// SPDX-License-Identifier: Apache-2.0
#include "dstu9212/keygen.h"

#include "dstu9212/convert.h"
#include "dstu9212/poly.h"
#include "dstu7564/dstu7564.h"
#include "dstu8845/dstu8845.h"
#include "reduce.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static size_t ceil_div_size(size_t a, size_t b)
{
	return (a + b - 1U) / b;
}

static dstu9212_status checked_mul_size(size_t a, size_t b, size_t *result)
{
	if (result == NULL || (a != 0U && b > SIZE_MAX / a)) {
		return DSTU9212_ERROR;
	}

	*result = a * b;
	return DSTU9212_OK;
}

static dstu9212_status checked_add_size(size_t a, size_t b, size_t *result)
{
	if (result == NULL || b > SIZE_MAX - a) {
		return DSTU9212_ERROR;
	}

	*result = a + b;
	return DSTU9212_OK;
}

static dstu9212_status init_prng_from_seed(
	dstu8845_prng *ctx, const uint8_t seed[DSTU9212_SEED_OCTETS])
{
	if (ctx == NULL || seed == NULL) {
		return DSTU9212_ERROR;
	}

	if (dstu8845_pseudo_random_init(ctx, seed, DSTU9212_SEED_OCTETS) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	return DSTU9212_OK;
}

static dstu9212_status generate_prng_octets(
	dstu8845_prng *ctx, uint8_t *dst, size_t dst_len)
{
	if (dst_len == 0U) {
		return DSTU9212_OK;
	}

	if (dstu8845_prng_generate_octets(ctx, dst, dst_len) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	return DSTU9212_OK;
}

static size_t process_matrix_candidates(
	const uint8_t *src, size_t src_len, int32_t *a,
	size_t offset, size_t capacity)
{
	size_t i;

	for (i = 0; i + 2U < src_len && offset < capacity; i += 3U) {
		uint32_t value;

		value = (uint32_t)src[i];
		value |= (uint32_t)src[i + 1U] << 8U;
		value |= (uint32_t)src[i + 2U] << 16U;
		value &= (uint32_t)((1U << DSTU9212_Q_BITS) - 1U);
		if (value < (uint32_t)DSTU9212_Q) {
			a[offset] = (int32_t)value;
			++offset;
		}
	}

	return offset;
}

size_t dstu9212_matrix_coeff_count(void)
{
	return DSTU9212_K * DSTU9212_L * DSTU9212_N;
}

size_t dstu9212_s1_coeff_count(void)
{
	return DSTU9212_L * DSTU9212_N;
}

size_t dstu9212_s2_coeff_count(void)
{
	return DSTU9212_K * DSTU9212_N;
}

size_t dstu9212_secret_coeff_count(void)
{
	return (DSTU9212_L + DSTU9212_K) * DSTU9212_N;
}

/*
 * Section 6.2.3, ds_gen_key.
 */
dstu9212_status dstu9212_gen_key(
	const uint8_t rho[DSTU9212_SEED_OCTETS],
	const uint8_t rho1[DSTU9212_SEED_OCTETS],
	const uint8_t key[DSTU9212_SEED_OCTETS],
	uint8_t *pk, size_t pk_capacity, size_t *pk_len,
	uint8_t *sk, size_t sk_capacity, size_t *sk_len)
{
	int32_t *workspace = NULL;
	int32_t *a = NULL;
	int32_t *s1 = NULL;
	int32_t *s1_ntt = NULL;
	int32_t *s2 = NULL;
	int32_t *t = NULL;
	int32_t *t1 = NULL;
	int32_t *t0 = NULL;
	uint8_t tr[DSTU9212_HASH_OCTETS];
	size_t a_count = dstu9212_matrix_coeff_count();
	size_t s1_count = dstu9212_s1_coeff_count();
	size_t s2_count = dstu9212_s2_coeff_count();
	size_t workspace_count = a_count + 2U * s1_count + 4U * s2_count;
	size_t i;
	dstu9212_status status = DSTU9212_ERROR;

	if (rho == NULL || rho1 == NULL || key == NULL ||
		pk == NULL || pk_len == NULL || sk == NULL || sk_len == NULL ||
		pk_capacity < DSTU9212_PK_OCTETS || sk_capacity < DSTU9212_SK_OCTETS) {
		return DSTU9212_ERROR;
	}

	*pk_len = 0;
	*sk_len = 0;

	workspace = calloc(workspace_count, sizeof(*workspace));
	if (workspace == NULL) {
		goto cleanup;
	}
	a = workspace;
	s1 = a + a_count;
	s1_ntt = s1 + s1_count;
	s2 = s1_ntt + s1_count;
	t = s2 + s2_count;
	t1 = t + s2_count;
	t0 = t1 + s2_count;

	if (dstu9212_expand_matr(rho, a, a_count) != DSTU9212_OK ||
		dstu9212_expand_s(rho1, s1, s1_count, s2, s2_count) != DSTU9212_OK) {
		goto cleanup;
	}

	memcpy(s1_ntt, s1, s1_count * sizeof(*s1_ntt));
	if (dstu9212_vec_ntt(s1_ntt, DSTU9212_L, s1_count) != DSTU9212_OK ||
		dstu9212_matr_vec_mul(t, a, s1_ntt, DSTU9212_K, DSTU9212_L, s2_count) != DSTU9212_OK ||
		dstu9212_vec_ntt_inv(t, DSTU9212_K, s2_count) != DSTU9212_OK ||
		dstu9212_vec_add(t, t, s2, DSTU9212_K, s2_count) != DSTU9212_OK) {
		goto cleanup;
	}

	for (i = 0; i < DSTU9212_K; ++i) {
		if (dstu9212_gen_hl(
				t + i * DSTU9212_N, 1 << DSTU9212_D,
				t1 + i * DSTU9212_N, t0 + i * DSTU9212_N,
				DSTU9212_N) != DSTU9212_OK) {
			goto cleanup;
		}
	}

	if (dstu9212_pack_pk(rho, t1, pk, pk_capacity, pk_len) != DSTU9212_OK ||
		dstu9212_hash(pk, *pk_len, tr) != DSTU9212_OK ||
		dstu9212_pack_sk(
			rho, key, tr, s1, s2, t0,
			sk, sk_capacity, sk_len) != DSTU9212_OK) {
		goto cleanup;
	}

	status = DSTU9212_OK;

cleanup:
	dstu9212_secure_zero(workspace, workspace_count * sizeof(*workspace));
	dstu9212_secure_zero(tr, sizeof(tr));
	free(workspace);
	return status;
}

/*
 * Section 6.2.6, ds_gen_hl.
 */
dstu9212_status dstu9212_gen_hl(
	const int32_t *t, int32_t base,
	int32_t *t1, int32_t *t0, size_t capacity)
{
	size_t i;

	if (t == NULL || t1 == NULL || t0 == NULL ||
		base <= 0 || base >= DSTU9212_Q || capacity < DSTU9212_N) {
		return DSTU9212_ERROR;
	}

	if (base == (1 << DSTU9212_D)) {
		for (i = 0; i < DSTU9212_N; ++i) {
			int32_t a = (int32_t)dstu9212_reduce_i32_unsigned(t[i]);
			int32_t high = (a + (1 << (DSTU9212_D - 1)) - 1) >> DSTU9212_D;

			t1[i] = high;
			t0[i] = a - high * (1 << DSTU9212_D);
		}
	} else if (base == 2 * DSTU9212_GAMMA2) {
		for (i = 0; i < DSTU9212_N; ++i) {
			int32_t a = (int32_t)dstu9212_reduce_i32_unsigned(t[i]);
			int32_t high = (a + 127) >> 7;
			int32_t low;
			uint32_t above_half;

			high = (high * 1025 + (1 << 21)) >> 22;
			high &= 15;
			low = a - high * (2 * DSTU9212_GAMMA2);
			above_half = ((uint32_t)((DSTU9212_Q - 1) / 2 - low)) >> 31;
			low -= (int32_t)(above_half * DSTU9212_Q);
			t1[i] = high;
			t0[i] = low;
		}
	} else {
		return DSTU9212_ERROR;
	}

	return DSTU9212_OK;
}

/*
 * Section 6.2.5.2, ds_expand_s_values.
 */
dstu9212_status dstu9212_expand_s_values(
	const uint8_t *src, size_t src_len,
	int32_t *dst, size_t dst_capacity, size_t *dst_len)
{
	size_t i;
	size_t offset = 0;
	uint32_t max_value;

	if (dst_len == NULL) {
		return DSTU9212_ERROR;
	}
	*dst_len = 0;

	if ((src == NULL && src_len != 0U) || (dst == NULL && dst_capacity != 0U)) {
		return DSTU9212_ERROR;
	}

	max_value = DSTU9212_ETA == 2 ? 15U : (uint32_t)(2U * DSTU9212_ETA + 1U);
	for (i = 0; i < src_len && offset < dst_capacity; ++i) {
		uint32_t nibbles[2];
		size_t j;

		nibbles[0] = src[i] & 0x0FU;
		nibbles[1] = src[i] >> 4U;

		for (j = 0; j < 2U && offset < dst_capacity; ++j) {
			uint32_t value = nibbles[j];

			if (value >= max_value) {
				continue;
			}
				if (DSTU9212_ETA == 2) {
					value -= ((205U * value) >> 10) * 5U;
			}
			dst[offset] = (int32_t)DSTU9212_ETA - (int32_t)value;
			++offset;
		}
	}

	*dst_len = offset;
	return DSTU9212_OK;
}

/*
 * Section 6.2.5.1, ds_expand_s.
 */
dstu9212_status dstu9212_expand_s_flat(
	const uint8_t rho1[DSTU9212_SEED_OCTETS],
	int32_t *s, size_t s_capacity)
{
	dstu8845_prng ctx;
	uint8_t *buf = NULL;
	uint8_t block[DSTU8845_BLOCK_BYTES];
	size_t coeff_count = dstu9212_secret_coeff_count();
	size_t need_octets;
	size_t need_blocks;
	size_t buf_len;
	size_t generated = 0;
	dstu9212_status status = DSTU9212_ERROR;

	if (rho1 == NULL || s == NULL || s_capacity < coeff_count) {
		return DSTU9212_ERROR;
	}
	if (checked_mul_size(coeff_count, 6U, &need_octets) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}
	need_octets = ceil_div_size(need_octets, 8U);
	need_blocks = ceil_div_size(need_octets, DSTU8845_BLOCK_BYTES);
	if (checked_mul_size(need_blocks, DSTU8845_BLOCK_BYTES, &buf_len) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	buf = calloc(1U, buf_len);
	if (buf == NULL) {
		return DSTU9212_ERROR;
	}

	if (init_prng_from_seed(&ctx, rho1) != DSTU9212_OK) {
		goto cleanup_buf;
	}
	if (dstu8845_prng_generate_blocks(&ctx, buf, need_blocks) != DSTU9212_OK) {
		goto cleanup_ctx;
	}
	if (dstu9212_expand_s_values(buf, buf_len, s, coeff_count, &generated) != DSTU9212_OK) {
		goto cleanup_ctx;
	}

	while (generated < coeff_count) {
		size_t added = 0;

		if (dstu8845_prng_generate_blocks(&ctx, block, 1U) != DSTU9212_OK) {
			goto cleanup_ctx;
		}
		if (dstu9212_expand_s_values(
				block, sizeof(block), s + generated,
				coeff_count - generated, &added) != DSTU9212_OK) {
			goto cleanup_ctx;
		}
		generated += added;
	}

	status = DSTU9212_OK;

cleanup_ctx:
	dstu8845_prng_clear(&ctx);
cleanup_buf:
	dstu9212_secure_zero(block, sizeof(block));
	dstu9212_secure_zero(buf, buf_len);
	free(buf);
	return status;
}

dstu9212_status dstu9212_expand_s(
	const uint8_t rho1[DSTU9212_SEED_OCTETS],
	int32_t *s1, size_t s1_capacity,
	int32_t *s2, size_t s2_capacity)
{
	int32_t *s = NULL;
	size_t s1_count = dstu9212_s1_coeff_count();
	size_t s2_count = dstu9212_s2_coeff_count();
	size_t coeff_count = dstu9212_secret_coeff_count();
	dstu9212_status status;

	if (rho1 == NULL || s1 == NULL || s2 == NULL ||
		s1_capacity < s1_count || s2_capacity < s2_count) {
		return DSTU9212_ERROR;
	}

	s = calloc(coeff_count, sizeof(*s));
	if (s == NULL) {
		return DSTU9212_ERROR;
	}

	status = dstu9212_expand_s_flat(rho1, s, coeff_count);
	if (status == DSTU9212_OK) {
		memcpy(s1, s, s1_count * sizeof(*s1));
		memcpy(s2, s + s1_count, s2_count * sizeof(*s2));
	}

	dstu9212_secure_zero(s, coeff_count * sizeof(*s));
	free(s);
	return status;
}

/*
 * Section 6.2.4, ds_expand_matr.
 */
dstu9212_status dstu9212_expand_matr(
	const uint8_t rho[DSTU9212_SEED_OCTETS],
	int32_t *a, size_t a_capacity)
{
	dstu8845_prng ctx;
	uint8_t *buf = NULL;
	uint8_t extra[3U * DSTU8845_BLOCK_BYTES];
	size_t coeff_count = dstu9212_matrix_coeff_count();
	size_t candidate_octets;
	size_t buf_len;
	size_t offset = 0;
	dstu9212_status status = DSTU9212_ERROR;

	if (rho == NULL || a == NULL || a_capacity < coeff_count) {
		return DSTU9212_ERROR;
	}
	if (checked_mul_size(coeff_count, 3U, &candidate_octets) != DSTU9212_OK ||
		checked_add_size(candidate_octets, sizeof(extra), &buf_len) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	buf = calloc(1U, buf_len);
	if (buf == NULL) {
		return DSTU9212_ERROR;
	}

	if (init_prng_from_seed(&ctx, rho) != DSTU9212_OK) {
		goto cleanup_buf;
	}
	if (generate_prng_octets(&ctx, buf, buf_len) != DSTU9212_OK) {
		goto cleanup_ctx;
	}

	offset = process_matrix_candidates(buf, buf_len, a, offset, coeff_count);
	while (offset < coeff_count) {
		if (generate_prng_octets(&ctx, extra, sizeof(extra)) != DSTU9212_OK) {
			goto cleanup_ctx;
		}
		offset = process_matrix_candidates(extra, sizeof(extra), a, offset, coeff_count);
	}

	status = DSTU9212_OK;

cleanup_ctx:
	dstu8845_prng_clear(&ctx);
cleanup_buf:
	free(buf);
	return status;
}
