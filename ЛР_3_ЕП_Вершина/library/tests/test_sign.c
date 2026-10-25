// SPDX-License-Identifier: Apache-2.0
#include "dstu9212/sign.h"

#include "dstu7564/dstu7564.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if DSTU9212_MODE == DSTU9212_MODE_128_64
#define TEST_VECTOR_FILE "test_vectors/DSTU9212Mode1.txt"
#elif DSTU9212_MODE == DSTU9212_MODE_256_128
#define TEST_VECTOR_FILE "test_vectors/DSTU9212Mode2.txt"
#elif DSTU9212_MODE == DSTU9212_MODE_384_192
#define TEST_VECTOR_FILE "test_vectors/DSTU9212Mode3.txt"
#elif DSTU9212_MODE == DSTU9212_MODE_512_256
#define TEST_VECTOR_FILE "test_vectors/DSTU9212Mode4.txt"
#else
#error "Unsupported DSTU9212_MODE"
#endif

static char *read_file(const char *path)
{
	FILE *fp = fopen(path, "rb");
	char *buf = NULL;
	long len;

	if (fp == NULL) {
		return NULL;
	}
	if (fseek(fp, 0L, SEEK_END) != 0) {
		fclose(fp);
		return NULL;
	}
	len = ftell(fp);
	if (len < 0 || fseek(fp, 0L, SEEK_SET) != 0) {
		fclose(fp);
		return NULL;
	}

	buf = malloc((size_t)len + 1U);
	if (buf == NULL) {
		fclose(fp);
		return NULL;
	}
	if (fread(buf, 1U, (size_t)len, fp) != (size_t)len) {
		free(buf);
		fclose(fp);
		return NULL;
	}
	buf[len] = '\0';
	fclose(fp);
	return buf;
}

static int parse_byte_section(
	const char *text, const char *name, uint8_t *out, size_t expected_len)
{
	char header[96];
	const char *p;
	size_t count = 0;

	snprintf(header, sizeof(header), "%s (size ", name);
	p = strstr(text, header);
	if (p == NULL) {
		return 1;
	}
	p = strchr(p, ':');
	if (p == NULL) {
		return 1;
	}

	while (count < expected_len) {
		char *endptr;
		unsigned long value;

		p = strstr(p, "0x");
		if (p == NULL) {
			return 1;
		}
		value = strtoul(p + 2, &endptr, 16);
		if (endptr == p + 2 || value > 0xFFUL) {
			return 1;
		}
		out[count++] = (uint8_t)value;
		p = endptr;
	}

	return 0;
}

static int parse_int_section(
	const char *text, const char *name, int32_t *out, size_t expected_len)
{
	char header[96];
	const char *p;
	size_t count = 0;

	snprintf(header, sizeof(header), "%s (size ", name);
	p = strstr(text, header);
	if (p == NULL) {
		return 1;
	}
	p = strchr(p, ':');
	if (p == NULL) {
		return 1;
	}
	++p;

	while (count < expected_len) {
		char *endptr;
		long value;

		while (*p != '\0' && *p != '-' && (*p < '0' || *p > '9')) {
			++p;
		}
		if (*p == '\0') {
			return 1;
		}
		value = strtol(p, &endptr, 10);
		if (endptr == p) {
			return 1;
		}
		out[count++] = (int32_t)value;
		p = endptr;
	}

	return 0;
}

static int first_diff_i32(const int32_t *a, const int32_t *b, size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i) {
		if (a[i] != b[i]) {
			return (int)i;
		}
	}

	return -1;
}

static int first_diff_u8(const uint8_t *a, const uint8_t *b, size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i) {
		if (a[i] != b[i]) {
			return (int)i;
		}
	}

	return -1;
}

static int test_check_and_h(void)
{
	int32_t poly[DSTU9212_N];
	int32_t vec1[DSTU9212_K * DSTU9212_N];
	int32_t vec2[DSTU9212_K * DSTU9212_N];
	uint8_t h[DSTU9212_K * DSTU9212_N];
	size_t cnt = 0;
	size_t i;

	for (i = 0; i < DSTU9212_N; ++i) {
		poly[i] = 0;
	}
	poly[3] = DSTU9212_BETA - 1;
	if (dstu9212_check(poly, DSTU9212_BETA, DSTU9212_N) != DSTU9212_OK) {
		return 1;
	}
	poly[4] = -DSTU9212_BETA;
	if (dstu9212_check(poly, DSTU9212_BETA, DSTU9212_N) != DSTU9212_ERROR) {
		return 1;
	}
	poly[4] = 0;
	if (dstu9212_check(poly, (DSTU9212_Q - 1) / 8 + 1,
			DSTU9212_N) != DSTU9212_ERROR) {
		return 1;
	}

	for (i = 0; i < DSTU9212_K * DSTU9212_N; ++i) {
		vec1[i] = (int32_t)(i % 17U);
		vec2[i] = vec1[i];
	}
	vec2[0] += 1;
	vec2[DSTU9212_N + 5U] += 1;
	vec2[DSTU9212_K * DSTU9212_N - 1U] += 1;
	if (dstu9212_gen_h(vec1, vec2, h, sizeof(h), &cnt) != DSTU9212_OK || cnt != 3U) {
		return 1;
	}
	if (h[0] != 1U || h[DSTU9212_N + 5U] != 1U ||
		h[DSTU9212_K * DSTU9212_N - 1U] != 1U) {
		return 1;
	}

	return 0;
}

int main(void)
{
	char *text = NULL;
	uint8_t key[DSTU9212_SEED_OCTETS];
	uint8_t pk[DSTU9212_PK_OCTETS];
	uint8_t sk[DSTU9212_SK_OCTETS];
	uint8_t m[4];
	uint8_t mu[DSTU9212_HASH_OCTETS];
	uint8_t key_mu[DSTU9212_SEED_OCTETS + DSTU9212_HASH_OCTETS];
	uint8_t y_seed[DSTU9212_HASH_OCTETS];
	uint8_t expected_c_seed[DSTU9212_SEED_OCTETS];
	uint8_t c_seed[DSTU9212_SEED_OCTETS];
	uint8_t expected_ds[DSTU9212_DS_OCTETS];
	uint8_t randomized_ds[DSTU9212_DS_OCTETS];
	uint8_t ds[DSTU9212_DS_OCTETS];
	int32_t expected_c[DSTU9212_N];
	int32_t c[DSTU9212_N];
	int32_t expected_y[DSTU9212_L * DSTU9212_N];
	int32_t y[DSTU9212_L * DSTU9212_N];
	int32_t w1[DSTU9212_K * DSTU9212_N];
	size_t ds_len = 0;
	dstu8845_prng ctx;
	int diff;
	int failed = 1;

	text = read_file(TEST_VECTOR_FILE);
	if (text == NULL) {
		fprintf(stderr, "failed to read %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}
	if (parse_byte_section(text, "key", key, sizeof(key)) != 0 ||
		parse_byte_section(text, "pk", pk, sizeof(pk)) != 0 ||
		parse_byte_section(text, "sk", sk, sizeof(sk)) != 0 ||
		parse_byte_section(text, "m", m, sizeof(m)) != 0 ||
		parse_byte_section(text, "deterministic.ds", expected_ds, sizeof(expected_ds)) != 0 ||
		parse_byte_section(text, "randomized.ds", randomized_ds, sizeof(randomized_ds)) != 0 ||
		parse_byte_section(text, "deterministic.trace.mu", mu, sizeof(mu)) != 0 ||
		parse_byte_section(
			text, "deterministic.trace.c_seed",
			expected_c_seed, sizeof(expected_c_seed)) != 0 ||
		parse_int_section(text, "deterministic.trace.c", expected_c, DSTU9212_N) != 0 ||
		parse_int_section(
			text, "deterministic.trace.y", expected_y,
			DSTU9212_L * DSTU9212_N) != 0 ||
		parse_int_section(
			text, "deterministic.trace.w1", w1,
			DSTU9212_K * DSTU9212_N) != 0) {
		fprintf(stderr, "failed to parse %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}

	if (dstu9212_sign(m, sizeof(m), sk, sizeof(sk), 0, NULL,
					  ds, sizeof(ds), &ds_len) != DSTU9212_OK ||
		ds_len != sizeof(ds)) {
		fprintf(stderr, "dstu9212_sign failed for %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}
	diff = first_diff_u8(ds, expected_ds, sizeof(ds));
	if (diff >= 0) {
		fprintf(stderr, "deterministic ds mismatch for %s at byte %d\n",
			TEST_VECTOR_FILE, diff);
		goto cleanup;
	}

	if (dstu9212_verify(m, sizeof(m), pk, sizeof(pk),
						expected_ds, sizeof(expected_ds)) != DSTU9212_OK) {
		fprintf(stderr, "deterministic ds verify failed for %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}
	if (dstu9212_verify(m, sizeof(m), pk, sizeof(pk),
						randomized_ds, sizeof(randomized_ds)) != DSTU9212_OK) {
		fprintf(stderr, "randomized ds verify failed for %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}
	randomized_ds[sizeof(randomized_ds) - 1U] ^= 1U;
	if (dstu9212_verify(m, sizeof(m), pk, sizeof(pk),
						randomized_ds, sizeof(randomized_ds)) != DSTU9212_ERROR) {
		fprintf(stderr, "corrupted ds verify succeeded for %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}

	if (dstu9212_prepare_gen_c(mu, w1, c_seed) != DSTU9212_OK) {
		fprintf(stderr, "dstu9212_prepare_gen_c failed for %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}
	diff = first_diff_u8(c_seed, expected_c_seed, sizeof(c_seed));
	if (diff >= 0) {
		fprintf(stderr, "c_seed mismatch for %s at byte %d\n", TEST_VECTOR_FILE, diff);
		goto cleanup;
	}

	if (dstu9212_gen_c(c_seed, c, DSTU9212_N) != DSTU9212_OK) {
		fprintf(stderr, "dstu9212_gen_c failed for %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}
	diff = first_diff_i32(c, expected_c, DSTU9212_N);
	if (diff >= 0) {
		fprintf(stderr, "c mismatch for %s at coeff %d: got %d expected %d\n",
			TEST_VECTOR_FILE, diff, c[diff], expected_c[diff]);
		goto cleanup;
	}

	memcpy(key_mu, key, sizeof(key));
	memcpy(key_mu + sizeof(key), mu, sizeof(mu));
	if (dstu9212_hash(key_mu, sizeof(key_mu), y_seed) != DSTU9212_OK ||
		dstu8845_pseudo_random_init(&ctx, y_seed, sizeof(y_seed)) != DSTU9212_OK) {
		fprintf(stderr, "failed to initialize y prng for %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}
	if (dstu9212_gen_y(&ctx, y, DSTU9212_L * DSTU9212_N) != DSTU9212_OK) {
		dstu8845_prng_clear(&ctx);
		fprintf(stderr, "dstu9212_gen_y failed for %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}
	dstu8845_prng_clear(&ctx);
	diff = first_diff_i32(y, expected_y, DSTU9212_L * DSTU9212_N);
	if (diff >= 0) {
		fprintf(stderr, "y mismatch for %s at coeff %d: got %d expected %d\n",
			TEST_VECTOR_FILE, diff, y[diff], expected_y[diff]);
		goto cleanup;
	}

	if (test_check_and_h() != 0) {
		fprintf(stderr, "check/h tests failed for %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}

	failed = 0;

cleanup:
	free(text);
	return failed;
}
