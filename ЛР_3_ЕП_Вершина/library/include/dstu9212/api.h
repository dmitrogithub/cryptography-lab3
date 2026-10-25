// SPDX-License-Identifier: Apache-2.0
#ifndef DSTU9212_API_H
#define DSTU9212_API_H

#include <stddef.h>
#include <stdint.h>

#include "parameters.h"
#include "utils.h"

#define DSTU9212_API_PUBLIC_KEY_BYTES DSTU9212_PK_OCTETS
#define DSTU9212_API_SECRET_KEY_BYTES DSTU9212_SK_OCTETS
#define DSTU9212_API_SIGNATURE_BYTES DSTU9212_DS_OCTETS

#ifdef __cplusplus
extern "C" {
#endif

const char *dstu9212_mode_name(void);
size_t dstu9212_public_key_bytes(void);
size_t dstu9212_secret_key_bytes(void);
size_t dstu9212_signature_bytes(void);

dstu9212_status dstu9212_keygen(uint8_t *pk, uint8_t *sk);

dstu9212_status dstu9212_sign_deterministic(
	uint8_t *sig, size_t sig_capacity, size_t *sig_len,
	const uint8_t *sk, size_t sk_len,
	const uint8_t *m, size_t m_len);

dstu9212_status dstu9212_sign_randomized(
	uint8_t *sig, size_t sig_capacity, size_t *sig_len,
	const uint8_t *sk, size_t sk_len,
	const uint8_t *m, size_t m_len);

dstu9212_status dstu9212_verify_signature(
	const uint8_t *pk, size_t pk_len,
	const uint8_t *sig, size_t sig_len,
	const uint8_t *m, size_t m_len);

#ifdef __cplusplus
}
#endif

#endif
