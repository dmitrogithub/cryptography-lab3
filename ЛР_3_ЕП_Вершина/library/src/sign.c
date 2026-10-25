// SPDX-License-Identifier: Apache-2.0
#include "dstu9212/sign.h"

#include "dstu9212/convert.h"
#include "dstu9212/keygen.h"
#include "dstu9212/poly.h"
#include "dstu7564/dstu7564.h"
#include "reduce.h"

#include <stdlib.h>
#include <string.h>

#define DSTU9212_W1_WIDTH 4U
#define DSTU9212_SIGN_MAX_ATTEMPTS 1000U

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

static unsigned int get_bit_le(const uint8_t *src, size_t bit_pos)
{
	return (unsigned int)((src[bit_pos / 8U] >> (bit_pos % 8U)) & 1U);
}

static uint32_t read_bits_le(const uint8_t *src, size_t start, unsigned int count)
{
	uint32_t value = 0;
	unsigned int i;

	for (i = 0; i < count; ++i) {
		value |= (uint32_t)(get_bit_le(src, start + i) << i);
	}

	return value;
}

static dstu9212_status hash_seed(
	const uint8_t *src, size_t src_len, uint8_t seed[DSTU9212_SEED_OCTETS])
{
#if DSTU9212_SEED_OCTETS == 48
	uint8_t h[DSTU7564_HASH512_BYTES];
#endif

	if ((src == NULL && src_len != 0U) || seed == NULL) {
		return DSTU9212_ERROR;
	}

#if DSTU9212_SEED_OCTETS == 32
	return dstu7564_hash_256(src, src_len, seed);
#elif DSTU9212_SEED_OCTETS == 48
	{
		dstu9212_status status = dstu7564_hash_512(src, src_len, h);

		if (status == DSTU9212_OK) {
			memcpy(seed, h + 8U, DSTU9212_SEED_OCTETS);
		}
		dstu9212_secure_zero(h, sizeof(h));
		return status;
	}
#elif DSTU9212_SEED_OCTETS == 64
	return dstu7564_hash_512(src, src_len, seed);
#else
#error "Unsupported DSTU9212_SEED_OCTETS"
#endif
}

static dstu9212_status fill_y_from_octets(
	const uint8_t *src, size_t src_len,
	int32_t *y, size_t y_capacity, size_t *generated)
{
	size_t coeff_count = dstu9212_y_coeff_count();
	size_t bit_count;
	size_t candidate_count;
	size_t i;
	size_t u;

	if (generated == NULL) {
		return DSTU9212_ERROR;
	}
	if ((src == NULL && src_len != 0U) || y == NULL || y_capacity < coeff_count ||
		src_len > SIZE_MAX / 8U) {
		return DSTU9212_ERROR;
	}

	bit_count = src_len * 8U;
	candidate_count = bit_count / DSTU9212_LOG2_2G1;
	u = *generated;
	for (i = 0; i < candidate_count && u < coeff_count; ++i) {
		uint32_t coef = read_bits_le(src, i * DSTU9212_LOG2_2G1, DSTU9212_LOG2_2G1);

		if (coef < 2U * (uint32_t)DSTU9212_GAMMA1) {
			y[u] = (DSTU9212_GAMMA1 - 1) - (int32_t)coef;
			++u;
		}
	}

	*generated = u;
	return DSTU9212_OK;
}

static dstu9212_status hash_concat2(
	const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
	uint8_t out[DSTU9212_HASH_OCTETS])
{
	uint8_t *buf = NULL;
	size_t buf_len;
	dstu9212_status status;

	if ((a == NULL && a_len != 0U) || (b == NULL && b_len != 0U) || out == NULL ||
		checked_add_size(a_len, b_len, &buf_len) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	buf = calloc(1U, buf_len == 0U ? 1U : buf_len);
	if (buf == NULL) {
		return DSTU9212_ERROR;
	}
	if (a_len != 0U) {
		memcpy(buf, a, a_len);
	}
	if (b_len != 0U) {
		memcpy(buf + a_len, b, b_len);
	}

	status = dstu9212_hash(buf, buf_len, out);
	free(buf);
	return status;
}

static dstu9212_status prepare_y_seed(
	const uint8_t *rand_comp, size_t rand_comp_len,
	const uint8_t key[DSTU9212_SEED_OCTETS],
	const uint8_t mu[DSTU9212_HASH_OCTETS],
	uint8_t y_seed[DSTU9212_HASH_OCTETS])
{
	uint8_t *buf = NULL;
	size_t buf_len;
	size_t offset = 0;
	dstu9212_status status;

	if ((rand_comp == NULL && rand_comp_len != 0U) || key == NULL || mu == NULL ||
		y_seed == NULL ||
		checked_add_size(rand_comp_len, DSTU9212_SEED_OCTETS, &buf_len) != DSTU9212_OK ||
		checked_add_size(buf_len, DSTU9212_HASH_OCTETS, &buf_len) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	buf = calloc(1U, buf_len);
	if (buf == NULL) {
		return DSTU9212_ERROR;
	}
	if (rand_comp_len != 0U) {
		memcpy(buf + offset, rand_comp, rand_comp_len);
		offset += rand_comp_len;
	}
	memcpy(buf + offset, key, DSTU9212_SEED_OCTETS);
	offset += DSTU9212_SEED_OCTETS;
	memcpy(buf + offset, mu, DSTU9212_HASH_OCTETS);

	status = dstu9212_hash(buf, buf_len, y_seed);
	dstu9212_secure_zero(buf, buf_len);
	free(buf);
	return status;
}

static dstu9212_status generate_random_component(
	dstu8845_prng *ctx, uint8_t rand_comp[DSTU9212_SEED_OCTETS])
{
	uint8_t block[DSTU8845_BLOCK_BYTES];
	dstu9212_status status;

	if (ctx == NULL || rand_comp == NULL) {
		return DSTU9212_ERROR;
	}

	status = dstu8845_prng_generate_blocks(ctx, block, 1U);
	if (status == DSTU9212_OK) {
		memcpy(rand_comp, block, DSTU9212_SEED_OCTETS);
	}
	dstu9212_secure_zero(block, sizeof(block));
	return status;
}

static dstu9212_status pointwise_poly_vec(
	int32_t *dst, const int32_t *poly, const int32_t *vec,
	size_t size, size_t dst_capacity)
{
	size_t coeff_count;
	size_t i;

	if (dst == NULL || poly == NULL || vec == NULL ||
		checked_mul_size(size, DSTU9212_N, &coeff_count) != DSTU9212_OK ||
		dst_capacity < coeff_count) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < size; ++i) {
		if (dstu9212_pointwize(
				dst + i * DSTU9212_N, poly,
				vec + i * DSTU9212_N, DSTU9212_N) != DSTU9212_OK) {
			return DSTU9212_ERROR;
		}
	}

	return DSTU9212_OK;
}

static dstu9212_status decompose_vec(
	const int32_t *src, int32_t *high, int32_t *low, size_t size)
{
	size_t i;

	if (src == NULL || high == NULL || low == NULL) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < size; ++i) {
		if (dstu9212_gen_hl(
				src + i * DSTU9212_N, 2 * DSTU9212_GAMMA2,
				high + i * DSTU9212_N, low + i * DSTU9212_N,
				DSTU9212_N) != DSTU9212_OK) {
			return DSTU9212_ERROR;
		}
	}

	return DSTU9212_OK;
}

static dstu9212_status sign_core(
	const uint8_t *m, size_t m_len,
	const uint8_t *sk, size_t sk_len,
	const uint8_t *rand_comp, size_t rand_comp_len,
	uint8_t *ds, size_t ds_capacity, size_t *ds_len)
{
	uint8_t rho[DSTU9212_SEED_OCTETS];
	uint8_t key[DSTU9212_SEED_OCTETS];
	uint8_t tr[DSTU9212_HASH_OCTETS];
	uint8_t mu[DSTU9212_HASH_OCTETS];
	uint8_t y_seed[DSTU9212_HASH_OCTETS];
	uint8_t seed[DSTU9212_SEED_OCTETS];
	dstu8845_prng ctx_y;
	int32_t *workspace = NULL;
	int32_t *a = NULL;
	int32_t *s1 = NULL;
	int32_t *s2 = NULL;
	int32_t *t0 = NULL;
	int32_t *y = NULL;
	int32_t *y_ntt = NULL;
	int32_t *w = NULL;
	int32_t *w1 = NULL;
	int32_t *low = NULL;
	int32_t *c = NULL;
	int32_t *c_ntt = NULL;
	int32_t *z = NULL;
	int32_t *r = NULL;
	int32_t *r1 = NULL;
	int32_t *ct0 = NULL;
	int32_t *temp = NULL;
	int32_t *temp1 = NULL;
	uint8_t *h = NULL;
	size_t a_count = dstu9212_matrix_coeff_count();
	size_t l_count = dstu9212_y_coeff_count();
	size_t k_count = dstu9212_w1_coeff_count();
	size_t workspace_count = a_count + 4U * l_count + 10U * k_count +
		2U * DSTU9212_N;
	size_t cnt;
	size_t attempt;
	dstu9212_status status = DSTU9212_ERROR;

	if (ds_len == NULL) {
		return DSTU9212_ERROR;
	}
	*ds_len = 0;

	if ((m == NULL && m_len != 0U) || sk == NULL || sk_len != DSTU9212_SK_OCTETS ||
		(rand_comp == NULL && rand_comp_len != 0U) ||
		ds == NULL || ds_capacity < DSTU9212_DS_OCTETS) {
		return DSTU9212_ERROR;
	}

	workspace = calloc(workspace_count, sizeof(*workspace));
	h = calloc(k_count, sizeof(*h));
	if (workspace == NULL || h == NULL) {
		goto cleanup;
	}
	a = workspace;
	s1 = a + a_count;
	y = s1 + l_count;
	y_ntt = y + l_count;
	z = y_ntt + l_count;
	s2 = z + l_count;
	t0 = s2 + k_count;
	w = t0 + k_count;
	w1 = w + k_count;
	low = w1 + k_count;
	r = low + k_count;
	r1 = r + k_count;
	ct0 = r1 + k_count;
	temp = ct0 + k_count;
	temp1 = temp + k_count;
	c = temp1 + k_count;
	c_ntt = c + DSTU9212_N;

	if (dstu9212_unpack_sk(sk, sk_len, rho, key, tr, s1, s2, t0) != DSTU9212_OK ||
		dstu9212_vec_ntt(s1, DSTU9212_L, l_count) != DSTU9212_OK ||
		dstu9212_vec_ntt(s2, DSTU9212_K, k_count) != DSTU9212_OK ||
		dstu9212_vec_ntt(t0, DSTU9212_K, k_count) != DSTU9212_OK ||
		hash_concat2(tr, DSTU9212_HASH_OCTETS, m, m_len, mu) != DSTU9212_OK ||
		dstu9212_expand_matr(rho, a, a_count) != DSTU9212_OK ||
		prepare_y_seed(rand_comp, rand_comp_len, key, mu, y_seed) != DSTU9212_OK ||
		dstu8845_pseudo_random_init(&ctx_y, y_seed, DSTU9212_HASH_OCTETS) != DSTU9212_OK) {
		goto cleanup;
	}

	for (attempt = 0; attempt < DSTU9212_SIGN_MAX_ATTEMPTS; ++attempt) {
		if (dstu9212_gen_y(&ctx_y, y, l_count) != DSTU9212_OK) {
			goto cleanup_ctx_y;
		}

		memcpy(y_ntt, y, l_count * sizeof(*y_ntt));
		if (dstu9212_vec_ntt(y_ntt, DSTU9212_L, l_count) != DSTU9212_OK ||
			dstu9212_matr_vec_mul(w, a, y_ntt, DSTU9212_K, DSTU9212_L, k_count) != DSTU9212_OK ||
			dstu9212_vec_ntt_inv(w, DSTU9212_K, k_count) != DSTU9212_OK ||
			decompose_vec(w, w1, low, DSTU9212_K) != DSTU9212_OK ||
			dstu9212_prepare_gen_c(mu, w1, seed) != DSTU9212_OK ||
			dstu9212_gen_c(seed, c, DSTU9212_N) != DSTU9212_OK) {
			goto cleanup_ctx_y;
		}

		memcpy(c_ntt, c, DSTU9212_N * sizeof(*c_ntt));
		if (dstu9212_ntt(c_ntt, DSTU9212_N) != DSTU9212_OK ||
			pointwise_poly_vec(z, c_ntt, s1, DSTU9212_L, l_count) != DSTU9212_OK ||
			dstu9212_vec_ntt_inv(z, DSTU9212_L, l_count) != DSTU9212_OK ||
			dstu9212_vec_add(z, z, y, DSTU9212_L, l_count) != DSTU9212_OK) {
			goto cleanup_ctx_y;
		}
		if (dstu9212_check_vect(z, DSTU9212_L, DSTU9212_GAMMA1 - DSTU9212_BETA,
								l_count) != DSTU9212_OK) {
			continue;
		}

		if (pointwise_poly_vec(r, c_ntt, s2, DSTU9212_K, k_count) != DSTU9212_OK ||
			dstu9212_vec_ntt_inv(r, DSTU9212_K, k_count) != DSTU9212_OK ||
			dstu9212_vec_sub(r, w, r, DSTU9212_K, k_count) != DSTU9212_OK ||
			decompose_vec(r, r1, low, DSTU9212_K) != DSTU9212_OK) {
			goto cleanup_ctx_y;
		}
		if (dstu9212_check_vect(low, DSTU9212_K,
								DSTU9212_GAMMA2 - DSTU9212_BETA,
								k_count) != DSTU9212_OK) {
			continue;
		}

		if (pointwise_poly_vec(ct0, c_ntt, t0, DSTU9212_K, k_count) != DSTU9212_OK ||
			dstu9212_vec_ntt_inv(ct0, DSTU9212_K, k_count) != DSTU9212_OK) {
			goto cleanup_ctx_y;
		}
		if (dstu9212_check_vect(ct0, DSTU9212_K, DSTU9212_GAMMA2, k_count) != DSTU9212_OK) {
			continue;
		}

		if (dstu9212_vec_add(temp, r, ct0, DSTU9212_K, k_count) != DSTU9212_OK ||
			decompose_vec(temp, temp1, low, DSTU9212_K) != DSTU9212_OK ||
			dstu9212_gen_h(r1, temp1, h, k_count, &cnt) != DSTU9212_OK) {
			goto cleanup_ctx_y;
		}
		if (cnt > DSTU9212_OMEGA) {
			continue;
		}

		status = dstu9212_pack_ds(seed, z, h, ds, ds_capacity, ds_len);
		break;
	}

cleanup_ctx_y:
	dstu8845_prng_clear(&ctx_y);
cleanup:
	dstu9212_secure_zero(workspace, workspace_count * sizeof(*workspace));
	dstu9212_secure_zero(h, k_count * sizeof(*h));
	dstu9212_secure_zero(rho, sizeof(rho));
	dstu9212_secure_zero(key, sizeof(key));
	dstu9212_secure_zero(tr, sizeof(tr));
	dstu9212_secure_zero(mu, sizeof(mu));
	dstu9212_secure_zero(y_seed, sizeof(y_seed));
	dstu9212_secure_zero(seed, sizeof(seed));
	free(workspace);
	free(h);
	return status;
}

/*
 * Section 7.1, ds_sign.
 */
dstu9212_status dstu9212_sign(
	const uint8_t *m, size_t m_len,
	const uint8_t *sk, size_t sk_len,
	int variant, dstu8845_prng *ctx,
	uint8_t *ds, size_t ds_capacity, size_t *ds_len)
{
	uint8_t rand_comp[DSTU9212_SEED_OCTETS];
	const uint8_t *rand_ptr = NULL;
	size_t rand_len = 0;
	dstu9212_status status;

	if (variant != 0) {
		if (generate_random_component(ctx, rand_comp) != DSTU9212_OK) {
			return DSTU9212_ERROR;
		}
		rand_ptr = rand_comp;
		rand_len = sizeof(rand_comp);
	}

	status = sign_core(m, m_len, sk, sk_len, rand_ptr, rand_len,
					   ds, ds_capacity, ds_len);
	dstu9212_secure_zero(rand_comp, sizeof(rand_comp));

	return status;
}

/*
 * Section 8.1, ds_verify.
 */
dstu9212_status dstu9212_verify(
	const uint8_t *m, size_t m_len,
	const uint8_t *pk, size_t pk_len,
	const uint8_t *ds, size_t ds_len)
{
	uint8_t rho[DSTU9212_SEED_OCTETS];
	uint8_t hash_pk[DSTU9212_HASH_OCTETS];
	uint8_t mu[DSTU9212_HASH_OCTETS];
	uint8_t seed[DSTU9212_SEED_OCTETS];
	uint8_t calc_seed[DSTU9212_SEED_OCTETS];
	int32_t *workspace = NULL;
	int32_t *t1 = NULL;
	int32_t *z = NULL;
	uint8_t *h = NULL;
	int32_t *a = NULL;
	int32_t *c = NULL;
	int32_t *c_ntt = NULL;
	int32_t *z_ntt = NULL;
	int32_t *az = NULL;
	int32_t *t1_shift = NULL;
	int32_t *ct1 = NULL;
	int32_t *w1 = NULL;
	int32_t *low = NULL;
	size_t a_count = dstu9212_matrix_coeff_count();
	size_t l_count = dstu9212_y_coeff_count();
	size_t k_count = dstu9212_w1_coeff_count();
	size_t workspace_count = a_count + 2U * l_count + 6U * k_count +
		2U * DSTU9212_N;
	size_t cnt = 0;
	size_t i;
	dstu9212_status status = DSTU9212_ERROR;

	if ((m == NULL && m_len != 0U) || pk == NULL || pk_len != DSTU9212_PK_OCTETS ||
		ds == NULL || ds_len != DSTU9212_DS_OCTETS) {
		return DSTU9212_ERROR;
	}

	workspace = calloc(workspace_count, sizeof(*workspace));
	h = calloc(k_count, sizeof(*h));
	if (workspace == NULL || h == NULL) {
		goto cleanup;
	}
	a = workspace;
	z = a + a_count;
	z_ntt = z + l_count;
	t1 = z_ntt + l_count;
	az = t1 + k_count;
	t1_shift = az + k_count;
	ct1 = t1_shift + k_count;
	w1 = ct1 + k_count;
	low = w1 + k_count;
	c = low + k_count;
	c_ntt = c + DSTU9212_N;

	if (dstu9212_unpack_pk(pk, pk_len, rho, t1) != DSTU9212_OK ||
		dstu9212_unpack_ds(ds, ds_len, seed, z, h) != DSTU9212_OK ||
		dstu9212_check_vect(z, DSTU9212_L, DSTU9212_GAMMA1 - DSTU9212_BETA,
							l_count) != DSTU9212_OK ||
		dstu9212_hash(pk, pk_len, hash_pk) != DSTU9212_OK ||
		hash_concat2(hash_pk, DSTU9212_HASH_OCTETS, m, m_len, mu) != DSTU9212_OK ||
		dstu9212_expand_matr(rho, a, a_count) != DSTU9212_OK ||
		dstu9212_gen_c(seed, c, DSTU9212_N) != DSTU9212_OK) {
		goto cleanup;
	}

	for (i = 0; i < k_count; ++i) {
		cnt += h[i];
		t1_shift[i] = (int32_t)((int64_t)t1[i] * (1 << DSTU9212_D));
	}
	if (cnt > DSTU9212_OMEGA) {
		goto cleanup;
	}

	memcpy(c_ntt, c, DSTU9212_N * sizeof(*c_ntt));
	memcpy(z_ntt, z, l_count * sizeof(*z_ntt));
	if (dstu9212_ntt(c_ntt, DSTU9212_N) != DSTU9212_OK ||
		dstu9212_vec_ntt(z_ntt, DSTU9212_L, l_count) != DSTU9212_OK ||
		dstu9212_vec_ntt(t1_shift, DSTU9212_K, k_count) != DSTU9212_OK ||
		dstu9212_matr_vec_mul(az, a, z_ntt, DSTU9212_K, DSTU9212_L, k_count) != DSTU9212_OK ||
		pointwise_poly_vec(ct1, c_ntt, t1_shift, DSTU9212_K, k_count) != DSTU9212_OK ||
		dstu9212_vec_sub(az, az, ct1, DSTU9212_K, k_count) != DSTU9212_OK ||
		dstu9212_vec_ntt_inv(az, DSTU9212_K, k_count) != DSTU9212_OK ||
		decompose_vec(az, w1, low, DSTU9212_K) != DSTU9212_OK) {
		goto cleanup;
	}

	for (i = 0; i < k_count; ++i) {
		if (h[i] != 0U) {
			int32_t modulus = DSTU9212_Q / (2 * DSTU9212_GAMMA2);

			if (low[i] > 0) {
				++w1[i];
			} else {
				--w1[i];
			}
			w1[i] %= modulus;
			if (w1[i] < 0) {
				w1[i] += modulus;
			}
		}
	}

	if (dstu9212_prepare_gen_c(mu, w1, calc_seed) != DSTU9212_OK) {
		goto cleanup;
	}
	status = dstu9212_constant_time_equal(
		calc_seed, seed, DSTU9212_SEED_OCTETS) ? DSTU9212_OK : DSTU9212_ERROR;

cleanup:
	dstu9212_secure_zero(workspace, workspace_count * sizeof(*workspace));
	free(workspace);
	free(h);
	return status;
}

size_t dstu9212_y_coeff_count(void)
{
	return DSTU9212_L * DSTU9212_N;
}

size_t dstu9212_w1_coeff_count(void)
{
	return DSTU9212_K * DSTU9212_N;
}

size_t dstu9212_hint_coeff_count(void)
{
	return DSTU9212_K * DSTU9212_N;
}

/*
 * Section 7.2.1, ds_gen_y.
 */
dstu9212_status dstu9212_gen_y(
	dstu8845_prng *ctx, int32_t *y, size_t y_capacity)
{
	uint8_t *buf = NULL;
	uint8_t extra[5U * DSTU8845_BLOCK_BYTES];
	size_t coeff_count = dstu9212_y_coeff_count();
	size_t initial_bits;
	size_t initial_octets;
	size_t initial_blocks;
	size_t buf_len;
	size_t generated = 0;
	dstu9212_status status = DSTU9212_ERROR;

	if (ctx == NULL || y == NULL || y_capacity < coeff_count) {
		return DSTU9212_ERROR;
	}
	if (checked_add_size(coeff_count, 2U, &initial_bits) != DSTU9212_OK ||
		checked_mul_size(initial_bits, DSTU9212_LOG2_2G1, &initial_bits) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}
	initial_octets = ceil_div_size(initial_bits, 8U);
	initial_blocks = ceil_div_size(initial_octets, 5U * DSTU8845_BLOCK_BYTES) * 5U;
	if (checked_mul_size(initial_blocks, DSTU8845_BLOCK_BYTES, &buf_len) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	buf = calloc(1U, buf_len);
	if (buf == NULL) {
		return DSTU9212_ERROR;
	}

	if (dstu8845_prng_generate_blocks(ctx, buf, initial_blocks) != DSTU9212_OK ||
		fill_y_from_octets(buf, buf_len, y, y_capacity, &generated) != DSTU9212_OK) {
		goto cleanup;
	}

	while (generated < coeff_count) {
		if (dstu8845_prng_generate_blocks(ctx, extra, 5U) != DSTU9212_OK ||
			fill_y_from_octets(extra, sizeof(extra), y, y_capacity, &generated) != DSTU9212_OK) {
			goto cleanup;
		}
	}

	status = DSTU9212_OK;

cleanup:
	dstu9212_secure_zero(extra, sizeof(extra));
	dstu9212_secure_zero(buf, buf_len);
	free(buf);
	return status;
}

/*
 * Section 7.2.2, ds_prepare_gen_c.
 */
dstu9212_status dstu9212_prepare_gen_c(
	const uint8_t mu[DSTU9212_HASH_OCTETS], const int32_t *w1,
	uint8_t seed[DSTU9212_SEED_OCTETS])
{
	uint8_t *buf = NULL;
	size_t w1_len;
	size_t packed_len = 0;
	size_t buf_len;
	dstu9212_status status = DSTU9212_ERROR;

	if (mu == NULL || w1 == NULL || seed == NULL) {
		return DSTU9212_ERROR;
	}

	w1_len = dstu9212_vec_os_len(DSTU9212_K, DSTU9212_W1_WIDTH);
	if (w1_len == 0U ||
		checked_add_size(DSTU9212_HASH_OCTETS, w1_len, &buf_len) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	buf = calloc(1U, buf_len);
	if (buf == NULL) {
		return DSTU9212_ERROR;
	}

	memcpy(buf, mu, DSTU9212_HASH_OCTETS);
	if (dstu9212_pack_vec(
			w1, DSTU9212_K, DSTU9212_W1_WIDTH, 0,
			buf + DSTU9212_HASH_OCTETS, buf_len - DSTU9212_HASH_OCTETS,
			&packed_len) != DSTU9212_OK ||
		packed_len != w1_len ||
		hash_seed(buf, buf_len, seed) != DSTU9212_OK) {
		goto cleanup;
	}

	status = DSTU9212_OK;

cleanup:
	dstu9212_secure_zero(buf, buf_len);
	free(buf);
	return status;
}

/*
 * Section 7.2.3, ds_gen_c.
 */
dstu9212_status dstu9212_gen_c(
	const uint8_t seed[DSTU9212_SEED_OCTETS],
	int32_t *c, size_t c_capacity)
{
	dstu8845_prng ctx;
	uint8_t *dest = NULL;
	uint8_t *signs = NULL;
	size_t olen_ind = DSTU9212_N * DSTU9212_WC / DSTU8845_BLOCK_BYTES;
	size_t olen_sign = ceil_div_size(DSTU9212_WC, 8U);
	size_t blocks;
	size_t octets;
	size_t available;
	size_t pos;
	size_t h;
	size_t sign_bit = 0;
	size_t i;
	dstu9212_status status = DSTU9212_ERROR;

	if (seed == NULL || c == NULL || c_capacity < DSTU9212_N) {
		return DSTU9212_ERROR;
	}
	if (DSTU9212_N == 512U && (olen_sign % 2U) != 0U) {
		++olen_sign;
	}
	if (checked_add_size(olen_ind, olen_sign, &octets) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}
	blocks = ceil_div_size(octets, DSTU8845_BLOCK_BYTES);
	if (checked_mul_size(blocks, DSTU8845_BLOCK_BYTES, &octets) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	dest = calloc(1U, octets);
	signs = calloc(1U, olen_sign);
	if (dest == NULL || signs == NULL) {
		free(signs);
		free(dest);
		return DSTU9212_ERROR;
	}

	memset(c, 0, DSTU9212_N * sizeof(*c));
	if (dstu8845_pseudo_random_init(&ctx, seed, DSTU9212_SEED_OCTETS) != DSTU9212_OK) {
		goto cleanup_dest;
	}
	if (dstu8845_prng_generate_blocks(&ctx, dest, blocks) != DSTU9212_OK) {
		goto cleanup_ctx;
	}
	memcpy(signs, dest, olen_sign);

	pos = olen_sign;
	available = octets;
	h = DSTU9212_N / 256U;
	for (i = DSTU9212_N - DSTU9212_WC; i < DSTU9212_N; ++i) {
		size_t r = DSTU9212_N;

		while (r > i) {
			if (pos > available - h) {
				if (dstu8845_prng_generate_blocks(&ctx, dest, 1U) != DSTU9212_OK) {
					goto cleanup_ctx;
				}
				available = DSTU8845_BLOCK_BYTES;
				pos = 0;
			}

			r = dest[pos];
			if (DSTU9212_N == 512U) {
				r = (r + 256U * (size_t)dest[pos + 1U]) % DSTU9212_N;
			}
			pos += h;
		}

		c[i] = c[r];
		c[r] = get_bit_le(signs, sign_bit) != 0U ? -1 : 1;
		++sign_bit;
	}

	status = DSTU9212_OK;

cleanup_ctx:
	dstu8845_prng_clear(&ctx);
cleanup_dest:
	dstu9212_secure_zero(signs, olen_sign);
	dstu9212_secure_zero(dest, octets);
	free(signs);
	free(dest);
	return status;
}

/*
 * Section 7.2.4, ds_check.
 */
dstu9212_status dstu9212_check(
	const int32_t *src, int32_t norma, size_t src_capacity)
{
	size_t i;
	uint32_t invalid = 0U;

	if (src == NULL || norma <= 0 || norma > (DSTU9212_Q - 1) / 8 ||
		src_capacity < DSTU9212_N) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < DSTU9212_N; ++i) {
		int32_t value = dstu9212_reduce_i32_centered(src[i]);
		uint32_t bits = (uint32_t)value;
		uint32_t negative = bits >> 31;
		uint32_t mask = 0U - negative;
		uint32_t absolute = (bits ^ mask) + negative;

		invalid |= (uint32_t)(absolute >= (uint32_t)norma);
	}

	return invalid == 0U ? DSTU9212_OK : DSTU9212_ERROR;
}

/*
 * Section 7.2.4, ds_check_vect.
 */
dstu9212_status dstu9212_check_vect(
	const int32_t *src, size_t src_size, int32_t norma, size_t src_capacity)
{
	size_t coeff_count;
	size_t i;
	uint32_t invalid = 0U;

	if (src == NULL || src_size == 0U ||
		checked_mul_size(src_size, DSTU9212_N, &coeff_count) != DSTU9212_OK ||
		src_capacity < coeff_count) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < src_size; ++i) {
		invalid |= (uint32_t)(dstu9212_check(
			src + i * DSTU9212_N, norma, DSTU9212_N) != DSTU9212_OK);
	}

	return invalid == 0U ? DSTU9212_OK : DSTU9212_ERROR;
}

/*
 * Section 7.2.5, ds_gen_h.
 */
dstu9212_status dstu9212_gen_h(
	const int32_t *vec1, const int32_t *vec2,
	uint8_t *h, size_t h_capacity, size_t *cnt)
{
	size_t coeff_count = dstu9212_hint_coeff_count();
	size_t i;
	size_t count = 0;

	if (cnt == NULL) {
		return DSTU9212_ERROR;
	}
	*cnt = 0;

	if (vec1 == NULL || vec2 == NULL || h == NULL || h_capacity < coeff_count) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < coeff_count; ++i) {
		h[i] = vec1[i] == vec2[i] ? 0U : 1U;
		count += h[i];
	}

	*cnt = count;
	return DSTU9212_OK;
}
