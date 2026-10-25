// SPDX-License-Identifier: Apache-2.0
#include "dstu9212/keygen.h"

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
	char header[64];
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
		out[count] = (uint8_t)value;
		++count;
		p = endptr;
	}

	return 0;
}

static int first_diff(const uint8_t *a, const uint8_t *b, size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i) {
		if (a[i] != b[i]) {
			return (int)i;
		}
	}

	return -1;
}

int main(void)
{
	char *text = NULL;
	uint8_t rho[DSTU9212_SEED_OCTETS];
	uint8_t rho1[DSTU9212_SEED_OCTETS];
	uint8_t key[DSTU9212_SEED_OCTETS];
	uint8_t expected_pk[DSTU9212_PK_OCTETS];
	uint8_t expected_sk[DSTU9212_SK_OCTETS];
	uint8_t pk[DSTU9212_PK_OCTETS];
	uint8_t sk[DSTU9212_SK_OCTETS];
	size_t pk_len = 0;
	size_t sk_len = 0;
	int diff;
	int failed = 1;

	text = read_file(TEST_VECTOR_FILE);
	if (text == NULL) {
		fprintf(stderr, "failed to read %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}
	if (parse_byte_section(text, "rho", rho, sizeof(rho)) != 0 ||
		parse_byte_section(text, "rho1", rho1, sizeof(rho1)) != 0 ||
		parse_byte_section(text, "key", key, sizeof(key)) != 0 ||
		parse_byte_section(text, "pk", expected_pk, sizeof(expected_pk)) != 0 ||
		parse_byte_section(text, "sk", expected_sk, sizeof(expected_sk)) != 0) {
		fprintf(stderr, "failed to parse %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}

	if (dstu9212_gen_key(
			rho, rho1, key, pk, sizeof(pk), &pk_len,
			sk, sizeof(sk), &sk_len) != DSTU9212_OK) {
		fprintf(stderr, "dstu9212_gen_key failed for %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}
	if (pk_len != sizeof(pk) || sk_len != sizeof(sk)) {
		fprintf(stderr, "unexpected key lengths for %s\n", TEST_VECTOR_FILE);
		goto cleanup;
	}

	diff = first_diff(pk, expected_pk, sizeof(pk));
	if (diff >= 0) {
		fprintf(stderr, "pk mismatch for %s at byte %d: got 0x%02x expected 0x%02x\n",
			TEST_VECTOR_FILE, diff, pk[diff], expected_pk[diff]);
		goto cleanup;
	}

	diff = first_diff(sk, expected_sk, sizeof(sk));
	if (diff >= 0) {
		fprintf(stderr, "sk mismatch for %s at byte %d: got 0x%02x expected 0x%02x\n",
			TEST_VECTOR_FILE, diff, sk[diff], expected_sk[diff]);
		goto cleanup;
	}

	failed = 0;

cleanup:
	free(text);
	return failed;
}
