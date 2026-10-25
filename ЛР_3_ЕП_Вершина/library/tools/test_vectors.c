// SPDX-License-Identifier: Apache-2.0
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dstu7564/dstu7564.h"
#include "dstu8845/dstu8845.h"
#include "dstu9212/convert.h"
#include "dstu9212/keygen.h"
#include "dstu9212/parameters.h"
#include "dstu9212/poly.h"
#include "dstu9212/sign.h"

#define DSTU9212_TOOL_MAX_SIGN_ATTEMPTS 1000U

static dstu9212_status checked_add_size(size_t a, size_t b, size_t *result)
{
	if (result == NULL || b > SIZE_MAX - a) {
		return DSTU9212_ERROR;
	}

	*result = a + b;
	return DSTU9212_OK;
}

static const char *default_output_path(void)
{
#if DSTU9212_MODE == DSTU9212_MODE_128_64
	return "test_vectors/DSTU9212GeneratedMode1.txt";
#elif DSTU9212_MODE == DSTU9212_MODE_256_128
	return "test_vectors/DSTU9212GeneratedMode2.txt";
#elif DSTU9212_MODE == DSTU9212_MODE_384_192
	return "test_vectors/DSTU9212GeneratedMode3.txt";
#elif DSTU9212_MODE == DSTU9212_MODE_512_256
	return "test_vectors/DSTU9212GeneratedMode4.txt";
#else
	return "test_vectors/DSTU9212Generated.txt";
#endif
}

static int write_hex_block(FILE *file, const char *label, const uint8_t *data, size_t len)
{
	size_t i;

	if (fprintf(file, "%s (size %zu):\n", label, len) < 0) {
		return -1;
	}

	for (i = 0; i < len; ++i) {
		if (fprintf(file, "0x%02x", data[i]) < 0) {
			return -1;
		}
		if (i + 1U < len && fprintf(file, ", ") < 0) {
			return -1;
		}
		if ((i + 1U) % 16U == 0 || i + 1U == len) {
			if (fprintf(file, "\n") < 0) {
				return -1;
			}
		}
	}

	return fprintf(file, "\n") < 0 ? -1 : 0;
}

static int write_int_block(FILE *file, const char *label, const int32_t *data, size_t len)
{
	size_t i;

	if (fprintf(file, "%s (size %zu):\n", label, len) < 0) {
		return -1;
	}

	for (i = 0; i < len; ++i) {
		if (fprintf(file, "%d", data[i]) < 0) {
			return -1;
		}
		if (i + 1U < len && fprintf(file, ", ") < 0) {
			return -1;
		}
		if ((i + 1U) % 16U == 0 || i + 1U == len) {
			if (fprintf(file, "\n") < 0) {
				return -1;
			}
		}
	}

	return fprintf(file, "\n") < 0 ? -1 : 0;
}

static int write_binary_matrix_block(FILE *file, const char *label, const uint8_t *data, size_t len)
{
	size_t i;

	if (fprintf(file, "%s (size %zu):\n", label, len) < 0) {
		return -1;
	}

	for (i = 0; i < len; ++i) {
		if (fprintf(file, "%u", (unsigned int)data[i]) < 0) {
			return -1;
		}
		if (i + 1U < len && fprintf(file, ", ") < 0) {
			return -1;
		}
		if ((i + 1U) % 16U == 0 || i + 1U == len) {
			if (fprintf(file, "\n") < 0) {
				return -1;
			}
		}
	}

	return fprintf(file, "\n") < 0 ? -1 : 0;
}

static int write_size_value_block(FILE *file, const char *label, size_t value)
{
	return fprintf(file, "%s (size 1):\n%zu\n\n", label, value) < 0 ? -1 : 0;
}

static int write_status_block(FILE *file, const char *label, dstu9212_status value)
{
	return fprintf(file, "%s (size 1):\n%d\n\n", label, value == DSTU9212_OK ? 1 : 0) < 0
			   ? -1
			   : 0;
}

static void fill_vector_seed(uint8_t seed[DSTU9212_SEED_OCTETS])
{
	size_t i;
	uint32_t state = 0x92120000U + (uint32_t)DSTU9212_MODE;

	for (i = 0; i < DSTU9212_SEED_OCTETS; ++i) {
		state = state * 1664525U + 1013904223U;
		seed[i] = (uint8_t)(state >> 24);
	}
}

static dstu9212_status derive_vector_inputs(
	const uint8_t seed[DSTU9212_SEED_OCTETS],
	uint8_t rho[DSTU9212_SEED_OCTETS],
	uint8_t rho1[DSTU9212_SEED_OCTETS],
	uint8_t key[DSTU9212_SEED_OCTETS],
	uint8_t rand_comp[DSTU9212_SEED_OCTETS])
{
	dstu8845_prng ctx;
	dstu9212_status status = DSTU9212_ERROR;

	if (dstu8845_pseudo_random_init(&ctx, seed, DSTU9212_SEED_OCTETS) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	if (dstu8845_prng_generate_octets(&ctx, rho, DSTU9212_SEED_OCTETS) == DSTU9212_OK &&
		dstu8845_prng_generate_octets(&ctx, rho1, DSTU9212_SEED_OCTETS) == DSTU9212_OK &&
		dstu8845_prng_generate_octets(&ctx, key, DSTU9212_SEED_OCTETS) == DSTU9212_OK &&
		dstu8845_prng_generate_octets(&ctx, rand_comp, DSTU9212_SEED_OCTETS) == DSTU9212_OK) {
		status = DSTU9212_OK;
	}

	dstu8845_prng_clear(&ctx);
	return status;
}

static void fill_message(uint8_t *m, size_t m_len)
{
	size_t i;

	for (i = 0; i < m_len; ++i) {
		m[i] = (uint8_t)(0x61U + i);
	}
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
	free(buf);
	return status;
}

static dstu9212_status pointwise_poly_vec(
	int32_t *dst, const int32_t *poly, const int32_t *vec,
	size_t size, size_t dst_capacity)
{
	size_t i;

	if (dst == NULL || poly == NULL || vec == NULL ||
		dst_capacity < size * DSTU9212_N) {
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

static dstu9212_status trace_signature(
	const uint8_t *m, size_t m_len,
	const uint8_t *sk, size_t sk_len,
	const uint8_t *rand_comp, size_t rand_comp_len,
	uint8_t mu[DSTU9212_HASH_OCTETS],
	uint8_t seed[DSTU9212_SEED_OCTETS],
	int32_t *c, int32_t *y, int32_t *w1, int32_t *z, uint8_t *h,
	uint8_t *ds, size_t ds_capacity, size_t *ds_len)
{
	uint8_t rho[DSTU9212_SEED_OCTETS];
	uint8_t key[DSTU9212_SEED_OCTETS];
	uint8_t tr[DSTU9212_HASH_OCTETS];
	uint8_t y_seed[DSTU9212_HASH_OCTETS];
	dstu8845_prng ctx_y;
	int32_t *a = NULL;
	int32_t *s1 = NULL;
	int32_t *s2 = NULL;
	int32_t *t0 = NULL;
	int32_t *y_ntt = NULL;
	int32_t *w = NULL;
	int32_t *low = NULL;
	int32_t *c_ntt = NULL;
	int32_t *r = NULL;
	int32_t *r1 = NULL;
	int32_t *ct0 = NULL;
	int32_t *temp = NULL;
	int32_t *temp1 = NULL;
	size_t a_count = dstu9212_matrix_coeff_count();
	size_t l_count = dstu9212_y_coeff_count();
	size_t k_count = dstu9212_w1_coeff_count();
	size_t cnt;
	size_t attempt;
	dstu9212_status status = DSTU9212_ERROR;
	int ctx_ready = 0;

	if ((m == NULL && m_len != 0U) || sk == NULL || sk_len != DSTU9212_SK_OCTETS ||
		(rand_comp == NULL && rand_comp_len != 0U) || mu == NULL || seed == NULL ||
		c == NULL || y == NULL || w1 == NULL || z == NULL || h == NULL ||
		ds == NULL || ds_capacity < DSTU9212_DS_OCTETS || ds_len == NULL) {
		return DSTU9212_ERROR;
	}
	*ds_len = 0;

	a = calloc(a_count, sizeof(*a));
	s1 = calloc(l_count, sizeof(*s1));
	s2 = calloc(k_count, sizeof(*s2));
	t0 = calloc(k_count, sizeof(*t0));
	y_ntt = calloc(l_count, sizeof(*y_ntt));
	w = calloc(k_count, sizeof(*w));
	low = calloc(k_count, sizeof(*low));
	c_ntt = calloc(DSTU9212_N, sizeof(*c_ntt));
	r = calloc(k_count, sizeof(*r));
	r1 = calloc(k_count, sizeof(*r1));
	ct0 = calloc(k_count, sizeof(*ct0));
	temp = calloc(k_count, sizeof(*temp));
	temp1 = calloc(k_count, sizeof(*temp1));
	if (a == NULL || s1 == NULL || s2 == NULL || t0 == NULL ||
		y_ntt == NULL || w == NULL || low == NULL || c_ntt == NULL ||
		r == NULL || r1 == NULL || ct0 == NULL || temp == NULL || temp1 == NULL) {
		goto cleanup;
	}

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
	ctx_ready = 1;

	for (attempt = 0; attempt < DSTU9212_TOOL_MAX_SIGN_ATTEMPTS; ++attempt) {
		if (dstu9212_gen_y(&ctx_y, y, l_count) != DSTU9212_OK) {
			goto cleanup;
		}

		memcpy(y_ntt, y, l_count * sizeof(*y_ntt));
		if (dstu9212_vec_ntt(y_ntt, DSTU9212_L, l_count) != DSTU9212_OK ||
			dstu9212_matr_vec_mul(w, a, y_ntt, DSTU9212_K, DSTU9212_L, k_count) != DSTU9212_OK ||
			dstu9212_vec_ntt_inv(w, DSTU9212_K, k_count) != DSTU9212_OK ||
			decompose_vec(w, w1, low, DSTU9212_K) != DSTU9212_OK ||
			dstu9212_prepare_gen_c(mu, w1, seed) != DSTU9212_OK ||
			dstu9212_gen_c(seed, c, DSTU9212_N) != DSTU9212_OK) {
			goto cleanup;
		}

		memcpy(c_ntt, c, DSTU9212_N * sizeof(*c_ntt));
		if (dstu9212_ntt(c_ntt, DSTU9212_N) != DSTU9212_OK ||
			pointwise_poly_vec(z, c_ntt, s1, DSTU9212_L, l_count) != DSTU9212_OK ||
			dstu9212_vec_ntt_inv(z, DSTU9212_L, l_count) != DSTU9212_OK ||
			dstu9212_vec_add(z, z, y, DSTU9212_L, l_count) != DSTU9212_OK) {
			goto cleanup;
		}
		if (dstu9212_check_vect(
				z, DSTU9212_L, DSTU9212_GAMMA1 - DSTU9212_BETA, l_count) != DSTU9212_OK) {
			continue;
		}

		if (pointwise_poly_vec(r, c_ntt, s2, DSTU9212_K, k_count) != DSTU9212_OK ||
			dstu9212_vec_ntt_inv(r, DSTU9212_K, k_count) != DSTU9212_OK ||
			dstu9212_vec_sub(r, w, r, DSTU9212_K, k_count) != DSTU9212_OK ||
			decompose_vec(r, r1, low, DSTU9212_K) != DSTU9212_OK) {
			goto cleanup;
		}
		if (dstu9212_check_vect(
				low, DSTU9212_K, DSTU9212_GAMMA2 - DSTU9212_BETA,
				k_count) != DSTU9212_OK) {
			continue;
		}

		if (pointwise_poly_vec(ct0, c_ntt, t0, DSTU9212_K, k_count) != DSTU9212_OK ||
			dstu9212_vec_ntt_inv(ct0, DSTU9212_K, k_count) != DSTU9212_OK) {
			goto cleanup;
		}
		if (dstu9212_check_vect(ct0, DSTU9212_K, DSTU9212_GAMMA2, k_count) != DSTU9212_OK) {
			continue;
		}

		if (dstu9212_vec_add(temp, r, ct0, DSTU9212_K, k_count) != DSTU9212_OK ||
			decompose_vec(temp, temp1, low, DSTU9212_K) != DSTU9212_OK ||
			dstu9212_gen_h(r1, temp1, h, k_count, &cnt) != DSTU9212_OK) {
			goto cleanup;
		}
		if (cnt > DSTU9212_OMEGA) {
			continue;
		}

		status = dstu9212_pack_ds(seed, z, h, ds, ds_capacity, ds_len);
		break;
	}

cleanup:
	if (ctx_ready) {
		dstu8845_prng_clear(&ctx_y);
	}
	free(a);
	free(s1);
	free(s2);
	free(t0);
	free(y_ntt);
	free(w);
	free(low);
	free(c_ntt);
	free(r);
	free(r1);
	free(ct0);
	free(temp);
	free(temp1);
	return status;
}

static int write_signature_vectors(
	FILE *file, const char *prefix,
	const uint8_t *m, size_t m_len,
	const uint8_t *pk, const uint8_t *sk,
	const uint8_t *rand_comp, size_t rand_comp_len)
{
	uint8_t ds[DSTU9212_DS_OCTETS];
	uint8_t mu[DSTU9212_HASH_OCTETS];
	uint8_t seed[DSTU9212_SEED_OCTETS];
	int32_t *c = NULL;
	int32_t *y = NULL;
	int32_t *w1 = NULL;
	int32_t *z = NULL;
	uint8_t *h = NULL;
	size_t ds_len = 0;
	size_t l_count = dstu9212_y_coeff_count();
	size_t k_count = dstu9212_w1_coeff_count();
	dstu9212_status verify_status;
	int status = EXIT_FAILURE;
	char label[96];

	c = calloc(DSTU9212_N, sizeof(*c));
	y = calloc(l_count, sizeof(*y));
	w1 = calloc(k_count, sizeof(*w1));
	z = calloc(l_count, sizeof(*z));
	h = calloc(k_count, sizeof(*h));
	if (c == NULL || y == NULL || w1 == NULL || z == NULL || h == NULL) {
		goto cleanup;
	}

	if (write_size_value_block(file, "m_len", m_len) != 0 ||
		write_hex_block(file, "m", m, m_len) != 0) {
		goto cleanup;
	}
	if (rand_comp_len != 0U) {
		if (snprintf(label, sizeof(label), "%s.rand_comp", prefix) < 0 ||
			write_hex_block(file, label, rand_comp, rand_comp_len) != 0) {
			goto cleanup;
		}
	}

	if (trace_signature(
			m, m_len, sk, DSTU9212_SK_OCTETS,
			rand_comp, rand_comp_len,
			mu, seed, c, y, w1, z, h,
			ds, sizeof(ds), &ds_len) != DSTU9212_OK ||
		ds_len != DSTU9212_DS_OCTETS) {
		goto cleanup;
	}
	verify_status = dstu9212_verify(m, m_len, pk, DSTU9212_PK_OCTETS, ds, ds_len);

	if (snprintf(label, sizeof(label), "%s.ds", prefix) < 0 ||
		write_hex_block(file, label, ds, ds_len) != 0 ||
		snprintf(label, sizeof(label), "%s.verify_result_ok", prefix) < 0 ||
		write_status_block(file, label, verify_status) != 0 ||
		snprintf(label, sizeof(label), "%s.trace.mu", prefix) < 0 ||
		write_hex_block(file, label, mu, sizeof(mu)) != 0 ||
		snprintf(label, sizeof(label), "%s.trace.c_seed", prefix) < 0 ||
		write_hex_block(file, label, seed, sizeof(seed)) != 0 ||
		snprintf(label, sizeof(label), "%s.trace.c", prefix) < 0 ||
		write_int_block(file, label, c, DSTU9212_N) != 0 ||
		snprintf(label, sizeof(label), "%s.trace.y", prefix) < 0 ||
		write_int_block(file, label, y, l_count) != 0 ||
		snprintf(label, sizeof(label), "%s.trace.w1", prefix) < 0 ||
		write_int_block(file, label, w1, k_count) != 0 ||
		snprintf(label, sizeof(label), "%s.trace.z", prefix) < 0 ||
		write_int_block(file, label, z, l_count) != 0 ||
		snprintf(label, sizeof(label), "%s.trace.h", prefix) < 0 ||
		write_binary_matrix_block(file, label, h, k_count) != 0) {
		goto cleanup;
	}

	status = verify_status == DSTU9212_OK ? EXIT_SUCCESS : EXIT_FAILURE;

cleanup:
	free(c);
	free(y);
	free(w1);
	free(z);
	free(h);
	return status;
}

static int write_keygen_vectors(
	FILE *file,
	const uint8_t seed[DSTU9212_SEED_OCTETS],
	const uint8_t rho[DSTU9212_SEED_OCTETS],
	const uint8_t rho1[DSTU9212_SEED_OCTETS],
	const uint8_t key[DSTU9212_SEED_OCTETS],
	uint8_t pk[DSTU9212_PK_OCTETS],
	uint8_t sk[DSTU9212_SK_OCTETS])
{
	int32_t *a = NULL;
	int32_t *s1 = NULL;
	int32_t *s1_ntt = NULL;
	int32_t *s2 = NULL;
	int32_t *t = NULL;
	int32_t *t0 = NULL;
	int32_t *t1 = NULL;
	size_t a_count = dstu9212_matrix_coeff_count();
	size_t s1_count = dstu9212_s1_coeff_count();
	size_t s2_count = dstu9212_s2_coeff_count();
	size_t pk_len = 0;
	size_t sk_len = 0;
	size_t i;
	int status = EXIT_FAILURE;

	a = calloc(a_count, sizeof(*a));
	s1 = calloc(s1_count, sizeof(*s1));
	s1_ntt = calloc(s1_count, sizeof(*s1_ntt));
	s2 = calloc(s2_count, sizeof(*s2));
	t = calloc(s2_count, sizeof(*t));
	t0 = calloc(s2_count, sizeof(*t0));
	t1 = calloc(s2_count, sizeof(*t1));
	if (a == NULL || s1 == NULL || s1_ntt == NULL || s2 == NULL ||
		t == NULL || t0 == NULL || t1 == NULL) {
		goto cleanup;
	}

	if (dstu9212_expand_matr(rho, a, a_count) != DSTU9212_OK ||
		dstu9212_expand_s(rho1, s1, s1_count, s2, s2_count) != DSTU9212_OK ||
		dstu9212_gen_key(
			rho, rho1, key,
			pk, DSTU9212_PK_OCTETS, &pk_len,
			sk, DSTU9212_SK_OCTETS, &sk_len) != DSTU9212_OK ||
		pk_len != DSTU9212_PK_OCTETS || sk_len != DSTU9212_SK_OCTETS) {
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

	if (write_hex_block(file, "seed", seed, DSTU9212_SEED_OCTETS) != 0 ||
		write_hex_block(file, "rho", rho, DSTU9212_SEED_OCTETS) != 0 ||
		write_hex_block(file, "rho1", rho1, DSTU9212_SEED_OCTETS) != 0 ||
		write_hex_block(file, "key", key, DSTU9212_SEED_OCTETS) != 0 ||
		write_hex_block(file, "pk", pk, DSTU9212_PK_OCTETS) != 0 ||
		write_hex_block(file, "sk", sk, DSTU9212_SK_OCTETS) != 0 ||
		write_int_block(file, "trace.matrix_a", a, a_count) != 0 ||
		write_int_block(file, "trace.s1", s1, s1_count) != 0 ||
		write_int_block(file, "trace.s2", s2, s2_count) != 0 ||
		write_int_block(file, "trace.t0", t0, s2_count) != 0 ||
		write_int_block(file, "trace.t1", t1, s2_count) != 0) {
		goto cleanup;
	}

	status = EXIT_SUCCESS;

cleanup:
	free(a);
	free(s1);
	free(s1_ntt);
	free(s2);
	free(t);
	free(t0);
	free(t1);
	return status;
}

static int generate_vectors(FILE *file)
{
	uint8_t seed[DSTU9212_SEED_OCTETS];
	uint8_t rho[DSTU9212_SEED_OCTETS];
	uint8_t rho1[DSTU9212_SEED_OCTETS];
	uint8_t key[DSTU9212_SEED_OCTETS];
	uint8_t rand_comp[DSTU9212_SEED_OCTETS];
	uint8_t pk[DSTU9212_PK_OCTETS];
	uint8_t sk[DSTU9212_SK_OCTETS];
	uint8_t m[4];

	fill_vector_seed(seed);
	fill_message(m, sizeof(m));

	if (fprintf(file, "mode: %s\n\n", DSTU9212_MODE_NAME) < 0 ||
		derive_vector_inputs(seed, rho, rho1, key, rand_comp) != DSTU9212_OK ||
		write_keygen_vectors(file, seed, rho, rho1, key, pk, sk) != EXIT_SUCCESS ||
		write_signature_vectors(
			file, "deterministic",
			m, sizeof(m), pk, sk, NULL, 0U) != EXIT_SUCCESS ||
		write_signature_vectors(
			file, "randomized",
			m, sizeof(m), pk, sk, rand_comp, sizeof(rand_comp)) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	const char *path = default_output_path();
	FILE *file;
	int status;

	if (argc > 2) {
		fprintf(stderr, "usage: %s [output-file]\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (argc == 2) {
		path = argv[1];
	}

	file = fopen(path, "wb");
	if (file == NULL) {
		perror(path);
		return EXIT_FAILURE;
	}

	status = generate_vectors(file);
	if (fclose(file) != 0) {
		perror(path);
		return EXIT_FAILURE;
	}
	if (status != EXIT_SUCCESS) {
		fprintf(stderr, "failed to generate test vectors\n");
		return status;
	}

	printf("Wrote %s\n", path);
	return EXIT_SUCCESS;
}
