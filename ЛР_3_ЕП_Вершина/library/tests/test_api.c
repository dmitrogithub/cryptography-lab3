// SPDX-License-Identifier: Apache-2.0
#include "dstu9212/api.h"

#include <string.h>

int main(void)
{
	const uint8_t message[] = "api test message";
	const uint8_t other_message[] = "api test messagd";
	uint8_t pk[DSTU9212_API_PUBLIC_KEY_BYTES];
	uint8_t sk[DSTU9212_API_SECRET_KEY_BYTES];
	uint8_t sig[DSTU9212_API_SIGNATURE_BYTES];
	size_t sig_len = 0;

	if (dstu9212_keygen(pk, sk) != DSTU9212_OK) {
		return 1;
	}

	if (dstu9212_sign_deterministic(
			sig, sizeof(sig), &sig_len,
			sk, sizeof(sk),
			message, strlen((const char *)message)) != DSTU9212_OK ||
		sig_len != sizeof(sig)) {
		return 1;
	}
	if (dstu9212_verify_signature(
			pk, sizeof(pk), sig, sig_len,
			message, strlen((const char *)message)) != DSTU9212_OK) {
		return 1;
	}
	if (dstu9212_verify_signature(
			pk, sizeof(pk), sig, sig_len,
			other_message, strlen((const char *)other_message)) != DSTU9212_ERROR) {
		return 1;
	}

	if (dstu9212_sign_randomized(
			sig, sizeof(sig), &sig_len,
			sk, sizeof(sk),
			message, strlen((const char *)message)) != DSTU9212_OK ||
		sig_len != sizeof(sig)) {
		return 1;
	}
	if (dstu9212_verify_signature(
			pk, sizeof(pk), sig, sig_len,
			message, strlen((const char *)message)) != DSTU9212_OK) {
		return 1;
	}

	return 0;
}
