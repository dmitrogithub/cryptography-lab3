// SPDX-License-Identifier: Apache-2.0
#include "dstu9212/keygen.h"

#include "dstu9212/convert.h"
#include "dstu7564/dstu7564.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_gen_hl_base(int32_t base)
{
	int32_t t[DSTU9212_N];
	int32_t t1[DSTU9212_N];
	int32_t t0[DSTU9212_N];
	size_t i;

	for (i = 0; i < DSTU9212_N; ++i) {
		t[i] = (int32_t)((i * 7919U) % DSTU9212_Q);
	}
	t[0] = 0;
	t[1] = DSTU9212_Q - 1;
	t[2] = -1;
	t[3] = base / 2;
	t[4] = base / 2 + 1;

	if (dstu9212_gen_hl(t, base, t1, t0, DSTU9212_N) != DSTU9212_OK) {
		return 1;
	}

	for (i = 0; i < DSTU9212_N; ++i) {
		int64_t lhs = (int64_t)t1[i] * base + t0[i];
		int64_t rhs = t[i] % (int64_t)DSTU9212_Q;

		if (rhs < 0) {
			rhs += DSTU9212_Q;
		}
		lhs %= DSTU9212_Q;
		if (lhs < 0) {
			lhs += DSTU9212_Q;
		}
		if (lhs != rhs || t0[i] < -base / 2 - 1 || t0[i] > base / 2) {
			return 1;
		}
	}

	return 0;
}

static int test_expand_s_values(void)
{
	uint8_t src[8];
	int32_t dst[16];
	size_t dst_len = 0;
	size_t expected = 0;
	size_t i;
	uint32_t max_value = DSTU9212_ETA == 2 ? 15U : (uint32_t)(2U * DSTU9212_ETA + 1U);

	for (i = 0; i < sizeof(src); ++i) {
		src[i] = (uint8_t)((i * 2U) | ((i * 2U + 1U) << 4U));
	}
	if (dstu9212_expand_s_values(src, sizeof(src), dst, 16U, &dst_len) != DSTU9212_OK) {
		return 1;
	}

	for (i = 0; i < 16U; ++i) {
		uint32_t nibble = (uint32_t)i;

		if (nibble < max_value) {
			uint32_t value = DSTU9212_ETA == 2 ? nibble % 5U : nibble;
			if (expected >= dst_len ||
				dst[expected] != (int32_t)DSTU9212_ETA - (int32_t)value) {
				return 1;
			}
			++expected;
		}
	}

	return dst_len == expected ? 0 : 1;
}

static int test_expand_s(void)
{
	uint8_t rho1[DSTU9212_SEED_OCTETS];
	int32_t *s1 = NULL;
	int32_t *s2 = NULL;
	int32_t *s1_again = NULL;
	int32_t *s2_again = NULL;
	size_t s1_count = dstu9212_s1_coeff_count();
	size_t s2_count = dstu9212_s2_coeff_count();
	size_t i;
	int failed = 1;

	for (i = 0; i < sizeof(rho1); ++i) {
		rho1[i] = (uint8_t)(0xA5U ^ i);
	}

	s1 = calloc(s1_count, sizeof(*s1));
	s2 = calloc(s2_count, sizeof(*s2));
	s1_again = calloc(s1_count, sizeof(*s1_again));
	s2_again = calloc(s2_count, sizeof(*s2_again));
	if (s1 == NULL || s2 == NULL || s1_again == NULL || s2_again == NULL) {
		goto cleanup;
	}

	if (dstu9212_expand_s(rho1, s1, s1_count, s2, s2_count) != DSTU9212_OK ||
		dstu9212_expand_s(rho1, s1_again, s1_count, s2_again, s2_count) != DSTU9212_OK) {
		goto cleanup;
	}
	if (memcmp(s1, s1_again, s1_count * sizeof(*s1)) != 0 ||
		memcmp(s2, s2_again, s2_count * sizeof(*s2)) != 0) {
		goto cleanup;
	}
	for (i = 0; i < s1_count; ++i) {
		if (s1[i] < -DSTU9212_ETA || s1[i] > DSTU9212_ETA) {
			goto cleanup;
		}
	}
	for (i = 0; i < s2_count; ++i) {
		if (s2[i] < -DSTU9212_ETA || s2[i] > DSTU9212_ETA) {
			goto cleanup;
		}
	}

	failed = 0;

cleanup:
	free(s1);
	free(s2);
	free(s1_again);
	free(s2_again);
	return failed;
}

static int test_expand_matr(void)
{
	uint8_t rho[DSTU9212_SEED_OCTETS];
	int32_t *a = NULL;
	int32_t *a_again = NULL;
	size_t a_count = dstu9212_matrix_coeff_count();
	size_t i;
	int failed = 1;

	for (i = 0; i < sizeof(rho); ++i) {
		rho[i] = (uint8_t)(0x3CU + i);
	}

	a = calloc(a_count, sizeof(*a));
	a_again = calloc(a_count, sizeof(*a_again));
	if (a == NULL || a_again == NULL) {
		goto cleanup;
	}

	if (dstu9212_expand_matr(rho, a, a_count) != DSTU9212_OK ||
		dstu9212_expand_matr(rho, a_again, a_count) != DSTU9212_OK) {
		goto cleanup;
	}
	if (memcmp(a, a_again, a_count * sizeof(*a)) != 0) {
		goto cleanup;
	}
	for (i = 0; i < a_count; ++i) {
		if (a[i] < 0 || a[i] >= DSTU9212_Q) {
			goto cleanup;
		}
	}

	failed = 0;

cleanup:
	free(a);
	free(a_again);
	return failed;
}

static int test_gen_key(void)
{
	uint8_t rho[DSTU9212_SEED_OCTETS];
	uint8_t rho1[DSTU9212_SEED_OCTETS];
	uint8_t key[DSTU9212_SEED_OCTETS];
	uint8_t pk[DSTU9212_PK_OCTETS];
	uint8_t sk[DSTU9212_SK_OCTETS];
	uint8_t pk_again[DSTU9212_PK_OCTETS];
	uint8_t sk_again[DSTU9212_SK_OCTETS];
	uint8_t unpacked_rho_pk[DSTU9212_SEED_OCTETS];
	uint8_t unpacked_rho_sk[DSTU9212_SEED_OCTETS];
	uint8_t unpacked_key[DSTU9212_SEED_OCTETS];
	uint8_t unpacked_tr[DSTU9212_HASH_OCTETS];
	uint8_t expected_tr[DSTU9212_HASH_OCTETS];
	int32_t *t1 = NULL;
	int32_t *s1 = NULL;
	int32_t *s2 = NULL;
	int32_t *t0 = NULL;
	size_t pk_len = 0;
	size_t sk_len = 0;
	size_t pk_again_len = 0;
	size_t sk_again_len = 0;
	size_t i;
	int failed = 1;

	for (i = 0; i < DSTU9212_SEED_OCTETS; ++i) {
		rho[i] = (uint8_t)(0x10U + i);
		rho1[i] = (uint8_t)(0x80U ^ (3U * i));
		key[i] = (uint8_t)(0xA0U + (5U * i));
	}

	t1 = calloc(dstu9212_s2_coeff_count(), sizeof(*t1));
	s1 = calloc(dstu9212_s1_coeff_count(), sizeof(*s1));
	s2 = calloc(dstu9212_s2_coeff_count(), sizeof(*s2));
	t0 = calloc(dstu9212_s2_coeff_count(), sizeof(*t0));
	if (t1 == NULL || s1 == NULL || s2 == NULL || t0 == NULL) {
		goto cleanup;
	}

	if (dstu9212_gen_key(
			rho, rho1, key, pk, sizeof(pk), &pk_len,
			sk, sizeof(sk), &sk_len) != DSTU9212_OK ||
		dstu9212_gen_key(
			rho, rho1, key, pk_again, sizeof(pk_again), &pk_again_len,
			sk_again, sizeof(sk_again), &sk_again_len) != DSTU9212_OK) {
		goto cleanup;
	}
	if (pk_len != DSTU9212_PK_OCTETS || sk_len != DSTU9212_SK_OCTETS ||
		pk_again_len != pk_len || sk_again_len != sk_len ||
		memcmp(pk, pk_again, pk_len) != 0 ||
		memcmp(sk, sk_again, sk_len) != 0) {
		goto cleanup;
	}
	if (dstu9212_unpack_pk(pk, pk_len, unpacked_rho_pk, t1) != DSTU9212_OK ||
		dstu9212_unpack_sk(
			sk, sk_len, unpacked_rho_sk, unpacked_key, unpacked_tr,
			s1, s2, t0) != DSTU9212_OK ||
		dstu9212_hash(pk, pk_len, expected_tr) != DSTU9212_OK) {
		goto cleanup;
	}
	if (memcmp(unpacked_rho_pk, rho, sizeof(rho)) != 0 ||
		memcmp(unpacked_rho_sk, rho, sizeof(rho)) != 0 ||
		memcmp(unpacked_key, key, sizeof(key)) != 0 ||
		memcmp(unpacked_tr, expected_tr, sizeof(expected_tr)) != 0) {
		goto cleanup;
	}
	if (dstu9212_gen_key(
			rho, rho1, key, pk, DSTU9212_PK_OCTETS - 1U, &pk_len,
			sk, sizeof(sk), &sk_len) != DSTU9212_ERROR) {
		goto cleanup;
	}

	failed = 0;

cleanup:
	free(t1);
	free(s1);
	free(s2);
	free(t0);
	return failed;
}

int main(void)
{
	if (test_gen_hl_base(1 << DSTU9212_D) != 0 ||
		test_gen_hl_base(2 * DSTU9212_GAMMA2) != 0 ||
		test_expand_s_values() != 0 ||
		test_expand_s() != 0 ||
		test_expand_matr() != 0 ||
		test_gen_key() != 0) {
		fprintf(stderr, "test_keygen failed\n");
		return 1;
	}

	return 0;
}
