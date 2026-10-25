// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "dstu7564/dstu7564.h"
#include "dstu8845/dstu8845.h"

static void test_hash(void)
{
	const uint8_t message[] = {'D', 'S', 'T', 'U', '9', '2', '1', '2'};
	uint8_t h_a[DSTU9212_HASH_OCTETS];
	uint8_t h_b[DSTU9212_HASH_OCTETS];
	uint8_t h_suffix[DSTU9212_HASH_OCTETS];

	assert(dstu9212_hash(message, sizeof(message), h_a) == DSTU9212_OK);
	assert(dstu9212_hash(message, sizeof(message), h_b) == DSTU9212_OK);
	assert(dstu9212_hash_with_byte(message, sizeof(message), 0U, h_suffix) == DSTU9212_OK);
	assert(memcmp(h_a, h_b, sizeof(h_a)) == 0);
	assert(memcmp(h_a, h_suffix, sizeof(h_a)) != 0);
	assert(dstu9212_hash(NULL, 1U, h_a) == DSTU9212_ERROR);
	assert(dstu9212_hash(NULL, 0U, h_a) == DSTU9212_OK);
	assert(dstu7564_hash_256(message, SIZE_MAX, h_a) == DSTU9212_ERROR);
}

static void hash_with_byte_256(const uint8_t *src, size_t src_len, uint8_t suffix,
							   uint8_t out[DSTU7564_HASH256_BYTES])
{
	uint8_t buf[64];

	assert(src_len + 1U <= sizeof(buf));
	memcpy(buf, src, src_len);
	buf[src_len] = suffix;
	assert(dstu7564_hash_256(buf, src_len + 1U, out) == DSTU9212_OK);
}

static void hash_with_byte_512(const uint8_t *src, size_t src_len, uint8_t suffix,
							   uint8_t out[DSTU7564_HASH512_BYTES])
{
	uint8_t buf[64];

	assert(src_len + 1U <= sizeof(buf));
	memcpy(buf, src, src_len);
	buf[src_len] = suffix;
	assert(dstu7564_hash_512(buf, src_len + 1U, out) == DSTU9212_OK);
}

static void test_prng(void)
{
	const uint8_t seed_a[] = {'s', 'e', 'e', 'd', '-', 'a'};
	const uint8_t seed_b[] = {'s', 'e', 'e', 'd', '-', 'b'};
	uint8_t key[DSTU8845_KEY_BYTES];
	uint8_t iv[DSTU8845_IV_BYTES];
	uint8_t full[300];
	uint8_t split[300];
	uint8_t manual[300];
	uint8_t other[300];
	uint8_t block[DSTU8845_BLOCK_BYTES];
	dstu8845_prng ctx1;
	dstu8845_prng ctx2;
	dstu8845_prng *allocated;
	size_t key_len = DSTU9212_LAMBDA <= DSTU9212_256_LAMBDA ? DSTU7564_HASH256_BYTES
															 : DSTU7564_HASH512_BYTES;

	assert(dstu8845_pseudo_random_init(&ctx1, seed_a, sizeof(seed_a)) == DSTU9212_OK);
	assert(dstu8845_prng_generate_octets(&ctx1, full, sizeof(full)) == DSTU9212_OK);
	dstu8845_prng_clear(&ctx1);

	assert(dstu8845_pseudo_random_init(&ctx1, seed_a, sizeof(seed_a)) == DSTU9212_OK);
	assert(dstu8845_prng_generate_octets(&ctx1, split, 17U) == DSTU9212_OK);
	assert(dstu8845_prng_generate_octets(&ctx1, split + 17U, 111U) == DSTU9212_OK);
	assert(dstu8845_prng_generate_octets(&ctx1, split + 128U, sizeof(split) - 128U) == DSTU9212_OK);
	assert(memcmp(full, split, sizeof(full)) == 0);

	if (key_len == DSTU7564_HASH256_BYTES) {
		hash_with_byte_256(seed_a, sizeof(seed_a), 0U, key);
	} else {
		hash_with_byte_512(seed_a, sizeof(seed_a), 0U, key);
	}
	hash_with_byte_256(seed_a, sizeof(seed_a), 1U, iv);
	assert(dstu8845_random_init(&ctx2, key, key_len, iv) == DSTU9212_OK);
	assert(dstu8845_prng_generate(&ctx2, manual, sizeof(manual)) == DSTU9212_OK);
	assert(memcmp(full, manual, sizeof(full)) == 0);
	dstu8845_prng_clear(&ctx2);

	assert(dstu8845_pseudo_random_init(&ctx2, seed_b, sizeof(seed_b)) == DSTU9212_OK);
	assert(dstu8845_prng_generate_octets(&ctx2, other, sizeof(other)) == DSTU9212_OK);
	assert(memcmp(full, other, sizeof(full)) != 0);

	allocated = dstu8845_prng_alloc();
	assert(allocated != NULL);
	assert(dstu8845_pseudo_random_init(allocated, seed_a, sizeof(seed_a)) == DSTU9212_OK);
	assert(dstu8845_prng_generate_blocks(allocated, block, 1U) == DSTU9212_OK);
	dstu8845_prng_free(allocated);

	assert(dstu8845_prng_generate_octets(&ctx1, NULL, 0U) == DSTU9212_OK);
	assert(dstu8845_prng_generate_octets(&ctx1, NULL, 1U) == DSTU9212_ERROR);
	assert(dstu8845_pseudo_random_init(NULL, seed_a, sizeof(seed_a)) == DSTU9212_ERROR);
	assert(dstu8845_pseudo_random_init(&ctx1, NULL, sizeof(seed_a)) == DSTU9212_ERROR);
	assert(dstu8845_pseudo_random_init(&ctx1, seed_a, 0U) == DSTU9212_ERROR);
	assert(dstu8845_random_init(&ctx1, key, key_len - 1U, iv) == DSTU9212_ERROR);

	dstu8845_prng_clear(&ctx1);
	dstu8845_prng_clear(&ctx2);
}

int main(void)
{
	test_hash();
	test_prng();
	return 0;
}
