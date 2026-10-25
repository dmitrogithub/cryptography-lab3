// SPDX-License-Identifier: Apache-2.0
#include <dstu9212/convert.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int fail(void)
{
	return 1;
}

static int32_t t0_base(void)
{
	return (int32_t)(1U << (DSTU9212_D - 1U));
}

static void fill_octets(uint8_t *out, size_t len, unsigned int seed)
{
	size_t i;

	for (i = 0; i < len; ++i) {
		out[i] = (uint8_t)((seed + 17U * i) & 0xffU);
	}
}

static void fill_unsigned_vec(int32_t *vec, size_t count, int32_t max_value)
{
	size_t i;

	for (i = 0; i < count; ++i) {
		vec[i] = (int32_t)((7U * i + 3U) % (size_t)(max_value + 1));
	}
}

static void fill_signed_vec(int32_t *vec, size_t count, int32_t base)
{
	size_t i;
	size_t span = (size_t)(2 * base + 1);

	for (i = 0; i < count; ++i) {
		vec[i] = (int32_t)((7U * i + 5U) % span) - base;
	}
}

static void fill_signature_z(int32_t *vec, size_t count)
{
	size_t i;
	size_t span = (size_t)(2 * DSTU9212_GAMMA1);

	for (i = 0; i < count; ++i) {
		vec[i] = (int32_t)((11U * i + 7U) % span) - DSTU9212_GAMMA1 + 1;
	}
}

static int equal_i32(const int32_t *a, const int32_t *b, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i) {
		if (a[i] != b[i]) {
			return 0;
		}
	}

	return 1;
}

static int test_vec_roundtrip(void)
{
	size_t count = DSTU9212_K * DSTU9212_N;
	size_t os_len = dstu9212_vec_os_len(DSTU9212_K, DSTU9212_Q_BITS - DSTU9212_D);
	int32_t *vec = calloc(count, sizeof(*vec));
	int32_t *decoded = calloc(count, sizeof(*decoded));
	uint8_t *os = calloc(os_len, sizeof(*os));
	size_t written = 0;
	int ok;

	if (vec == NULL || decoded == NULL || os == NULL) {
		free(vec);
		free(decoded);
		free(os);
		return fail();
	}

	fill_unsigned_vec(vec, count, (1 << (DSTU9212_Q_BITS - DSTU9212_D)) - 1);
	ok = dstu9212_pack_vec(vec, DSTU9212_K, DSTU9212_Q_BITS - DSTU9212_D,
						   0, os, os_len, &written) == DSTU9212_OK &&
		 written == os_len &&
		 dstu9212_unpack_vec(os, os_len, DSTU9212_K,
							 DSTU9212_Q_BITS - DSTU9212_D, 0, decoded) == DSTU9212_OK &&
		 equal_i32(vec, decoded, count);

	free(vec);
	free(decoded);
	free(os);
	return ok ? 0 : fail();
}

static int test_pk_roundtrip(void)
{
	uint8_t rho[DSTU9212_SEED_OCTETS];
	uint8_t rho2[DSTU9212_SEED_OCTETS];
	uint8_t pk[DSTU9212_PK_OCTETS];
	int32_t t1[DSTU9212_K * DSTU9212_N];
	int32_t t1_2[DSTU9212_K * DSTU9212_N];
	size_t pk_len = 0;

	fill_octets(rho, sizeof(rho), 11U);
	fill_unsigned_vec(t1, DSTU9212_K * DSTU9212_N,
					  (1 << (DSTU9212_Q_BITS - DSTU9212_D)) - 1);

	if (dstu9212_pack_pk(rho, t1, pk, sizeof(pk), &pk_len) != DSTU9212_OK ||
		pk_len != DSTU9212_PK_OCTETS) {
		return fail();
	}
	if (dstu9212_unpack_pk(pk, pk_len, rho2, t1_2) != DSTU9212_OK) {
		return fail();
	}
	if (memcmp(rho, rho2, sizeof(rho)) != 0 ||
		!equal_i32(t1, t1_2, DSTU9212_K * DSTU9212_N)) {
		return fail();
	}

	return 0;
}

static int test_sk_roundtrip(void)
{
	uint8_t rho[DSTU9212_SEED_OCTETS];
	uint8_t key[DSTU9212_SEED_OCTETS];
	uint8_t tr[DSTU9212_HASH_OCTETS];
	uint8_t rho2[DSTU9212_SEED_OCTETS];
	uint8_t key2[DSTU9212_SEED_OCTETS];
	uint8_t tr2[DSTU9212_HASH_OCTETS];
	uint8_t sk[DSTU9212_SK_OCTETS];
	int32_t s1[DSTU9212_L * DSTU9212_N];
	int32_t s2[DSTU9212_K * DSTU9212_N];
	int32_t t0[DSTU9212_K * DSTU9212_N];
	int32_t s1_2[DSTU9212_L * DSTU9212_N];
	int32_t s2_2[DSTU9212_K * DSTU9212_N];
	int32_t t0_2[DSTU9212_K * DSTU9212_N];
	size_t sk_len = 0;

	fill_octets(rho, sizeof(rho), 19U);
	fill_octets(key, sizeof(key), 23U);
	fill_octets(tr, sizeof(tr), 29U);
	fill_signed_vec(s1, DSTU9212_L * DSTU9212_N, DSTU9212_ETA);
	fill_signed_vec(s2, DSTU9212_K * DSTU9212_N, DSTU9212_ETA);
	fill_signed_vec(t0, DSTU9212_K * DSTU9212_N, t0_base());

	if (dstu9212_pack_sk(rho, key, tr, s1, s2, t0, sk, sizeof(sk), &sk_len) != DSTU9212_OK ||
		sk_len != DSTU9212_SK_OCTETS) {
		return fail();
	}
	if (dstu9212_unpack_sk(sk, sk_len, rho2, key2, tr2, s1_2, s2_2, t0_2) != DSTU9212_OK) {
		return fail();
	}
	if (memcmp(rho, rho2, sizeof(rho)) != 0 ||
		memcmp(key, key2, sizeof(key)) != 0 ||
		memcmp(tr, tr2, sizeof(tr)) != 0 ||
		!equal_i32(s1, s1_2, DSTU9212_L * DSTU9212_N) ||
		!equal_i32(s2, s2_2, DSTU9212_K * DSTU9212_N) ||
		!equal_i32(t0, t0_2, DSTU9212_K * DSTU9212_N)) {
		return fail();
	}

	return 0;
}

static void fill_hint(uint8_t *h)
{
	size_t i;

	memset(h, 0, DSTU9212_K * DSTU9212_N);
	for (i = 0; i < DSTU9212_K && i < DSTU9212_OMEGA; ++i) {
		h[i * DSTU9212_N + ((17U * i + 3U) % 256U)] = 1U;
		if (DSTU9212_N == 512 && 2U * i + 1U < DSTU9212_OMEGA) {
			h[i * DSTU9212_N + 256U + ((19U * i + 5U) % 256U)] = 1U;
		}
	}
}

static int test_ds_roundtrip(void)
{
	uint8_t seed[DSTU9212_SEED_OCTETS];
	uint8_t seed2[DSTU9212_SEED_OCTETS];
	uint8_t h[DSTU9212_K * DSTU9212_N];
	uint8_t h2[DSTU9212_K * DSTU9212_N];
	uint8_t ds[DSTU9212_DS_OCTETS];
	int32_t z[DSTU9212_L * DSTU9212_N];
	int32_t z2[DSTU9212_L * DSTU9212_N];
	size_t ds_len = 0;

	fill_octets(seed, sizeof(seed), 31U);
	fill_signature_z(z, DSTU9212_L * DSTU9212_N);
	fill_hint(h);

	if (dstu9212_pack_ds(seed, z, h, ds, sizeof(ds), &ds_len) != DSTU9212_OK ||
		ds_len != DSTU9212_DS_OCTETS) {
		return fail();
	}
	if (dstu9212_unpack_ds(ds, ds_len, seed2, z2, h2) != DSTU9212_OK) {
		return fail();
	}
	if (memcmp(seed, seed2, sizeof(seed)) != 0 ||
		memcmp(h, h2, sizeof(h)) != 0 ||
		!equal_i32(z, z2, DSTU9212_L * DSTU9212_N)) {
		return fail();
	}

	return 0;
}

int main(void)
{
	if (test_vec_roundtrip() != 0 ||
		test_pk_roundtrip() != 0 ||
		test_sk_roundtrip() != 0 ||
		test_ds_roundtrip() != 0) {
		return fail();
	}

	return 0;
}
