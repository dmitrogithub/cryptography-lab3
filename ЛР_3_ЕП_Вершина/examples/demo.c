// SPDX-License-Identifier: Apache-2.0
#include <stdio.h>
#include <string.h>

#include <dstu9212/dstu9212.h>

int main(void)
{
	const uint8_t message[] = "DSTU 9212 API example";
	uint8_t pk[DSTU9212_API_PUBLIC_KEY_BYTES];
	uint8_t sk[DSTU9212_API_SECRET_KEY_BYTES];
	uint8_t sig[DSTU9212_API_SIGNATURE_BYTES];
	size_t sig_len = 0;

	printf("DSTU 9212 mode: %s (mode=%d)\n", dstu9212_mode_name(), DSTU9212_MODE);
	printf("pk=%zu sk=%zu signature=%zu\n",
		   dstu9212_public_key_bytes(),
		   dstu9212_secret_key_bytes(),
		   dstu9212_signature_bytes());

	if (dstu9212_keygen(pk, sk) != DSTU9212_OK) {
		fprintf(stderr, "key generation failed\n");
		return 1;
	}

	if (dstu9212_sign_randomized(
			sig, sizeof(sig), &sig_len,
			sk, sizeof(sk),
			message, strlen((const char *)message)) != DSTU9212_OK) {
		fprintf(stderr, "signing failed\n");
		return 1;
	}

	if (dstu9212_verify_signature(
			pk, sizeof(pk), sig, sig_len,
			message, strlen((const char *)message)) != DSTU9212_OK) {
		fprintf(stderr, "verification failed\n");
		return 1;
	}

	printf("signature verified, signature length=%zu\n", sig_len);
	return 0;
}
