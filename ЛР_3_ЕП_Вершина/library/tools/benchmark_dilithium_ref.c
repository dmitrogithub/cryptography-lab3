// SPDX-License-Identifier: Apache-2.0
/* Standalone wall-clock harness for the official CRYSTALS-Dilithium ref
 * implementation. Compile this file together with that implementation's
 * sources and define DILITHIUM_MODE to 2, 3, or 5. */
#include "api.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#if DILITHIUM_MODE == 2
#define BENCH_NAME "Dilithium2 ref"
#define BENCH_PK_BYTES pqcrystals_dilithium2_ref_PUBLICKEYBYTES
#define BENCH_SK_BYTES pqcrystals_dilithium2_ref_SECRETKEYBYTES
#define BENCH_SIG_BYTES pqcrystals_dilithium2_ref_BYTES
#define BENCH_KEYPAIR pqcrystals_dilithium2_ref_keypair
#define BENCH_SIGNATURE pqcrystals_dilithium2_ref_signature
#define BENCH_VERIFY pqcrystals_dilithium2_ref_verify
#elif DILITHIUM_MODE == 3
#define BENCH_NAME "Dilithium3 ref"
#define BENCH_PK_BYTES pqcrystals_dilithium3_ref_PUBLICKEYBYTES
#define BENCH_SK_BYTES pqcrystals_dilithium3_ref_SECRETKEYBYTES
#define BENCH_SIG_BYTES pqcrystals_dilithium3_ref_BYTES
#define BENCH_KEYPAIR pqcrystals_dilithium3_ref_keypair
#define BENCH_SIGNATURE pqcrystals_dilithium3_ref_signature
#define BENCH_VERIFY pqcrystals_dilithium3_ref_verify
#elif DILITHIUM_MODE == 5
#define BENCH_NAME "Dilithium5 ref"
#define BENCH_PK_BYTES pqcrystals_dilithium5_ref_PUBLICKEYBYTES
#define BENCH_SK_BYTES pqcrystals_dilithium5_ref_SECRETKEYBYTES
#define BENCH_SIG_BYTES pqcrystals_dilithium5_ref_BYTES
#define BENCH_KEYPAIR pqcrystals_dilithium5_ref_keypair
#define BENCH_SIGNATURE pqcrystals_dilithium5_ref_signature
#define BENCH_VERIFY pqcrystals_dilithium5_ref_verify
#else
#error "Define DILITHIUM_MODE as 2, 3, or 5"
#endif

static double elapsed_seconds(struct timespec start, struct timespec end)
{
	return (double)(end.tv_sec - start.tv_sec) +
		(double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
}

static int parse_iterations(const char *text, size_t *iterations)
{
	char *end = NULL;
	unsigned long value;

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
	uint8_t message[32] = "portable Dilithium benchmark";
	uint8_t pk[BENCH_PK_BYTES];
	uint8_t sk[BENCH_SK_BYTES];
	uint8_t sig[BENCH_SIG_BYTES];
	size_t sig_len = 0;
	size_t iterations = 1000U;
	struct timespec start;
	struct timespec end;
	double keygen_seconds;
	double sign_seconds;
	double verify_seconds;
	size_t i;

	if (argc > 2 || (argc == 2 && !parse_iterations(argv[1], &iterations))) {
		fprintf(stderr, "usage: %s [iterations]\n", argv[0]);
		return EXIT_FAILURE;
	}

	timespec_get(&start, TIME_UTC);
	for (i = 0; i < iterations; ++i) {
		if (BENCH_KEYPAIR(pk, sk) != 0) {
			return EXIT_FAILURE;
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
		if (BENCH_SIGNATURE(sig, &sig_len, message, sizeof(message),
				NULL, 0U, sk) != 0) {
			return EXIT_FAILURE;
		}
	}
	timespec_get(&end, TIME_UTC);
	sign_seconds = elapsed_seconds(start, end);

	timespec_get(&start, TIME_UTC);
	for (i = 0; i < iterations; ++i) {
		if (BENCH_VERIFY(sig, sig_len, message, sizeof(message),
				NULL, 0U, pk) != 0) {
			return EXIT_FAILURE;
		}
	}
	timespec_get(&end, TIME_UTC);
	verify_seconds = elapsed_seconds(start, end);

	printf("%s, %zu iteration(s)\n", BENCH_NAME, iterations);
	print_result("keygen", iterations, keygen_seconds);
	print_result("sign", iterations, sign_seconds);
	print_result("verify", iterations, verify_seconds);
	return EXIT_SUCCESS;
}
