// SPDX-License-Identifier: Apache-2.0
#include "dstu9212/dstu9212.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static double elapsed_seconds(struct timespec start, struct timespec end)
{
	return (double)(end.tv_sec - start.tv_sec) +
		(double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
}

static int parse_iterations(const char *text, size_t *iterations)
{
	char *end = NULL;
	unsigned long value;

	if (text == NULL || iterations == NULL) {
		return 0;
	}
	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0' || value == 0U ||
		value > 1000000UL) {
		return 0;
	}
	*iterations = (size_t)value;
	return 1;
}

static void print_result(const char *operation, size_t iterations, double seconds)
{
	printf("%-8s %10.3f ms/op  %10.2f ops/s\n", operation,
		1000.0 * seconds / (double)iterations,
		(double)iterations / seconds);
}

int main(int argc, char **argv)
{
	uint8_t message[32] = "portable DSTU 9212 benchmark";
	uint8_t *pk = NULL;
	uint8_t *sk = NULL;
	uint8_t *sig = NULL;
	size_t sig_len = 0;
	size_t iterations = 10U;
	struct timespec start;
	struct timespec end;
	double keygen_seconds;
	double sign_det_seconds;
	double sign_rnd_seconds;
	double verify_seconds;
	size_t i;
	int result = EXIT_FAILURE;

	if (argc > 2 || (argc == 2 && !parse_iterations(argv[1], &iterations))) {
		fprintf(stderr, "usage: %s [iterations]\n", argv[0]);
		return EXIT_FAILURE;
	}

	pk = malloc(dstu9212_public_key_bytes());
	sk = malloc(dstu9212_secret_key_bytes());
	sig = malloc(dstu9212_signature_bytes());
	if (pk == NULL || sk == NULL || sig == NULL) {
		fprintf(stderr, "allocation failed\n");
		goto cleanup;
	}

	timespec_get(&start, TIME_UTC);
	for (i = 0; i < iterations; ++i) {
		if (dstu9212_keygen(pk, sk) != DSTU9212_OK) {
			fprintf(stderr, "key generation failed\n");
			goto cleanup;
		}
	}
	timespec_get(&end, TIME_UTC);
	keygen_seconds = elapsed_seconds(start, end);

	timespec_get(&start, TIME_UTC);
	for (i = 0; i < iterations; ++i) {
		size_t j;

		for (j = 0; j < sizeof(size_t); ++j) {
			message[j] = (uint8_t)(i >> (8U * j));
		}
		if (dstu9212_sign_deterministic(
				sig, dstu9212_signature_bytes(), &sig_len,
				sk, dstu9212_secret_key_bytes(), message,
				sizeof(message)) != DSTU9212_OK) {
			fprintf(stderr, "signing failed\n");
			goto cleanup;
		}
	}
	timespec_get(&end, TIME_UTC);
	sign_det_seconds = elapsed_seconds(start, end);

	timespec_get(&start, TIME_UTC);
	for (i = 0; i < iterations; ++i) {
		size_t j;

		for (j = 0; j < sizeof(size_t); ++j) {
			message[j] = (uint8_t)(i >> (8U * j));
		}
		if (dstu9212_sign_randomized(
				sig, dstu9212_signature_bytes(), &sig_len,
				sk, dstu9212_secret_key_bytes(), message,
				sizeof(message)) != DSTU9212_OK) {
			fprintf(stderr, "randomized signing failed\n");
			goto cleanup;
		}
	}
	timespec_get(&end, TIME_UTC);
	sign_rnd_seconds = elapsed_seconds(start, end);

	timespec_get(&start, TIME_UTC);
	for (i = 0; i < iterations; ++i) {
		if (dstu9212_verify_signature(
				pk, dstu9212_public_key_bytes(), sig, sig_len,
				message, sizeof(message)) != DSTU9212_OK) {
			fprintf(stderr, "verification failed\n");
			goto cleanup;
		}
	}
	timespec_get(&end, TIME_UTC);
	verify_seconds = elapsed_seconds(start, end);

	printf("%s, %zu iteration(s)\n", dstu9212_mode_name(), iterations);
	print_result("keygen", iterations, keygen_seconds);
	print_result("sign-det", iterations, sign_det_seconds);
	print_result("sign-rnd", iterations, sign_rnd_seconds);
	print_result("verify", iterations, verify_seconds);
	result = EXIT_SUCCESS;

cleanup:
	if (sk != NULL) {
		dstu9212_secure_zero(sk, dstu9212_secret_key_bytes());
	}
	free(sig);
	free(sk);
	free(pk);
	return result;
}
