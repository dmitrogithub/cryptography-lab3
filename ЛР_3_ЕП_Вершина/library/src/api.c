// SPDX-License-Identifier: Apache-2.0
#include <dstu9212/api.h>
#include <dstu9212/keygen.h>
#include <dstu9212/parameters.h>
#include <dstu9212/sign.h>
#include <dstu8845/dstu8845.h>

#include <limits.h>
#include <string.h>

#define DSTU9212_API_RANDOM_CHUNK_BYTES 4096U

#if DSTU9212_LAMBDA <= DSTU9212_256_LAMBDA
#define DSTU9212_API_PRNG_KEY_BYTES 32U
#else
#define DSTU9212_API_PRNG_KEY_BYTES 64U
#endif

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <stdlib.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#endif

static dstu9212_status system_random_bytes(uint8_t *out, size_t out_len)
{
	if (out == NULL && out_len != 0U) {
		return DSTU9212_ERROR;
	}
	if (out_len == 0U) {
		return DSTU9212_OK;
	}

#if defined(_WIN32)
	while (out_len > 0U) {
		ULONG chunk = out_len > (size_t)ULONG_MAX ? ULONG_MAX : (ULONG)out_len;

		if (BCryptGenRandom(NULL, out, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
			return DSTU9212_ERROR;
		}
		out += chunk;
		out_len -= chunk;
	}
	return DSTU9212_OK;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	arc4random_buf(out, out_len);
	return DSTU9212_OK;
#else
	{
		int fd = open("/dev/urandom", O_RDONLY);
		size_t offset = 0;

		if (fd < 0) {
			return DSTU9212_ERROR;
		}

		while (offset < out_len) {
			size_t remaining = out_len - offset;
			size_t chunk = remaining > DSTU9212_API_RANDOM_CHUNK_BYTES
							   ? DSTU9212_API_RANDOM_CHUNK_BYTES
							   : remaining;
			ssize_t got = read(fd, out + offset, chunk);

			if (got < 0) {
				if (errno == EINTR) {
					continue;
				}
				close(fd);
				return DSTU9212_ERROR;
			}
			if (got == 0) {
				close(fd);
				return DSTU9212_ERROR;
			}
			offset += (size_t)got;
		}

		close(fd);
		return DSTU9212_OK;
	}
#endif
}

static dstu9212_status init_system_prng(dstu8845_prng *ctx)
{
	uint8_t key[DSTU9212_API_PRNG_KEY_BYTES];
	uint8_t iv[DSTU8845_IV_BYTES];
	dstu9212_status status = DSTU9212_ERROR;

	if (ctx == NULL) {
		return DSTU9212_ERROR;
	}

	if (system_random_bytes(key, sizeof(key)) != DSTU9212_OK ||
		system_random_bytes(iv, sizeof(iv)) != DSTU9212_OK) {
		goto cleanup;
	}

	status = dstu8845_random_init(ctx, key, sizeof(key), iv);

cleanup:
	dstu9212_secure_zero(key, sizeof(key));
	dstu9212_secure_zero(iv, sizeof(iv));
	return status;
}

const char *dstu9212_mode_name(void)
{
	return DSTU9212_MODE_NAME;
}

size_t dstu9212_public_key_bytes(void)
{
	return DSTU9212_PK_OCTETS;
}

size_t dstu9212_secret_key_bytes(void)
{
	return DSTU9212_SK_OCTETS;
}

size_t dstu9212_signature_bytes(void)
{
	return DSTU9212_DS_OCTETS;
}

dstu9212_status dstu9212_keygen(uint8_t *pk, uint8_t *sk)
{
	uint8_t rho[DSTU9212_SEED_OCTETS];
	uint8_t rho1[DSTU9212_SEED_OCTETS];
	uint8_t key[DSTU9212_SEED_OCTETS];
	size_t pk_len = 0;
	size_t sk_len = 0;
	dstu9212_status status = DSTU9212_ERROR;

	if (pk == NULL || sk == NULL) {
		return DSTU9212_ERROR;
	}

	if (system_random_bytes(rho, sizeof(rho)) != DSTU9212_OK ||
		system_random_bytes(rho1, sizeof(rho1)) != DSTU9212_OK ||
		system_random_bytes(key, sizeof(key)) != DSTU9212_OK) {
		goto cleanup;
	}

	if (dstu9212_gen_key(
			rho, rho1, key,
			pk, DSTU9212_API_PUBLIC_KEY_BYTES, &pk_len,
			sk, DSTU9212_API_SECRET_KEY_BYTES, &sk_len) == DSTU9212_OK &&
		pk_len == DSTU9212_API_PUBLIC_KEY_BYTES &&
		sk_len == DSTU9212_API_SECRET_KEY_BYTES) {
		status = DSTU9212_OK;
	}

cleanup:
	dstu9212_secure_zero(rho, sizeof(rho));
	dstu9212_secure_zero(rho1, sizeof(rho1));
	dstu9212_secure_zero(key, sizeof(key));
	return status;
}

dstu9212_status dstu9212_sign_deterministic(
	uint8_t *sig, size_t sig_capacity, size_t *sig_len,
	const uint8_t *sk, size_t sk_len,
	const uint8_t *m, size_t m_len)
{
	if (sig_len == NULL) {
		return DSTU9212_ERROR;
	}
	*sig_len = 0;

	return dstu9212_sign(
		m, m_len, sk, sk_len, 0, NULL,
		sig, sig_capacity, sig_len);
}

dstu9212_status dstu9212_sign_randomized(
	uint8_t *sig, size_t sig_capacity, size_t *sig_len,
	const uint8_t *sk, size_t sk_len,
	const uint8_t *m, size_t m_len)
{
	dstu8845_prng ctx;
	dstu9212_status status;

	if (sig_len == NULL) {
		return DSTU9212_ERROR;
	}
	*sig_len = 0;

	if (init_system_prng(&ctx) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	status = dstu9212_sign(
		m, m_len, sk, sk_len, 1, &ctx,
		sig, sig_capacity, sig_len);
	dstu8845_prng_clear(&ctx);
	return status;
}

dstu9212_status dstu9212_verify_signature(
	const uint8_t *pk, size_t pk_len,
	const uint8_t *sig, size_t sig_len,
	const uint8_t *m, size_t m_len)
{
	return dstu9212_verify(m, m_len, pk, pk_len, sig, sig_len);
}
