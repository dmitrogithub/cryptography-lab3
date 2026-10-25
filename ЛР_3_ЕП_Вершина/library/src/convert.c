// SPDX-License-Identifier: Apache-2.0
#include "dstu9212/convert.h"

#include <string.h>

static size_t ceil_div_size(size_t a, size_t b)
{
	return (a + b - 1U) / b;
}

static int32_t t0_base(void)
{
	return (int32_t)(1U << (DSTU9212_D - 1U));
}

static dstu9212_status check_signature_z(const int32_t *z)
{
	size_t i;
	uint32_t invalid = 0U;

	if (z == NULL) {
		return DSTU9212_ERROR;
	}

	for (i = 0; i < DSTU9212_L * DSTU9212_N; ++i) {
		invalid |= (uint32_t)(z[i] < -DSTU9212_GAMMA1 + 1);
		invalid |= (uint32_t)(z[i] > DSTU9212_GAMMA1);
	}

	return invalid == 0U ? DSTU9212_OK : DSTU9212_ERROR;
}

static dstu9212_status check_size_width(size_t size, unsigned int width)
{
	if (size == 0 || width == 0 || width >= 32U) {
		return DSTU9212_ERROR;
	}
	if (DSTU9212_N > SIZE_MAX / width ||
		size > SIZE_MAX / ceil_div_size(DSTU9212_N * width, 8U)) {
		return DSTU9212_ERROR;
	}

	return DSTU9212_OK;
}

size_t dstu9212_vec_os_len(size_t size, unsigned int width)
{
	if (check_size_width(size, width) != DSTU9212_OK) {
		return 0;
	}

	return size * ceil_div_size(DSTU9212_N * width, 8U);
}

size_t dstu9212_public_key_os_len(void)
{
	return DSTU9212_PK_OCTETS;
}

size_t dstu9212_secret_key_os_len(void)
{
	return DSTU9212_SK_OCTETS;
}

size_t dstu9212_signature_os_len(void)
{
	return DSTU9212_DS_OCTETS;
}

size_t dstu9212_hint_os_len(void)
{
	return DSTU9212_HINT_OCTETS;
}

/*
 * Section 6.2.7.1, ds_pack_vec.
 */
dstu9212_status dstu9212_pack_vec(
	const int32_t *vec, size_t size, unsigned int width, int32_t base,
	uint8_t *os, size_t os_capacity, size_t *os_len)
{
	size_t needed;
	size_t coeff_count;
	uint32_t max_value;
	uint32_t invalid = 0U;
	uint64_t bit_buffer = 0U;
	unsigned int buffered_bits = 0U;
	size_t out_pos = 0U;
	size_t i;

	if (os_len == NULL) {
		return DSTU9212_ERROR;
	}
	*os_len = 0;

	needed = dstu9212_vec_os_len(size, width);
	if (vec == NULL || os == NULL || needed == 0 || os_capacity < needed) {
		return DSTU9212_ERROR;
	}

	coeff_count = size * DSTU9212_N;
	max_value = (uint32_t)((1ULL << width) - 1ULL);
	for (i = 0; i < coeff_count; ++i) {
		int64_t value = base == 0 ? vec[i] : (int64_t)base - vec[i];
		uint64_t unsigned_value = (uint64_t)value;

		invalid |= (uint32_t)(value < 0);
		invalid |= (uint32_t)(unsigned_value > max_value);
		if (base != 0) {
			invalid |= (uint32_t)(vec[i] < -base);
			invalid |= (uint32_t)(vec[i] > base);
		}

		bit_buffer |= (unsigned_value & max_value) << buffered_bits;
		buffered_bits += width;
		while (buffered_bits >= 8U) {
			os[out_pos++] = (uint8_t)bit_buffer;
			bit_buffer >>= 8U;
			buffered_bits -= 8U;
		}
	}

	if (buffered_bits != 0U)
		os[out_pos++] = (uint8_t)bit_buffer;
	if (invalid != 0U || out_pos != needed) {
		memset(os, 0, needed);
		return DSTU9212_ERROR;
	}
	*os_len = needed;
	return DSTU9212_OK;
}

/*
 * Section 6.2.7.2, ds_unpack_vec.
 */
dstu9212_status dstu9212_unpack_vec(
	const uint8_t *os, size_t os_len, size_t size,
	unsigned int width, int32_t base, int32_t *vec)
{
	size_t needed;
	size_t coeff_count;
	uint32_t invalid = 0U;
	uint64_t bit_buffer = 0U;
	unsigned int buffered_bits = 0U;
	size_t in_pos = 0U;
	size_t i;

	needed = dstu9212_vec_os_len(size, width);
	if (os == NULL || vec == NULL || needed == 0 || os_len < needed) {
		return DSTU9212_ERROR;
	}

	coeff_count = size * DSTU9212_N;
	for (i = 0; i < coeff_count; ++i) {
		uint32_t value;

		while (buffered_bits < width) {
			bit_buffer |= (uint64_t)os[in_pos++] << buffered_bits;
			buffered_bits += 8U;
		}
		value = (uint32_t)bit_buffer & (uint32_t)((UINT64_C(1) << width) - 1U);
		bit_buffer >>= width;
		buffered_bits -= width;

		vec[i] = base == 0 ? (int32_t)value : base - (int32_t)value;
		if (base != 0) {
			invalid |= (uint32_t)(vec[i] < -base);
			invalid |= (uint32_t)(vec[i] > base);
		}
	}

	return invalid == 0U && in_pos == needed ? DSTU9212_OK : DSTU9212_ERROR;
}

/*
 * Section 6.2.8, ds_pack_pk.
 */
dstu9212_status dstu9212_pack_pk(
	const uint8_t *rho, const int32_t *t1,
	uint8_t *pk, size_t pk_capacity, size_t *pk_len)
{
	size_t offset;
	size_t packed_len;

	if (pk_len == NULL) {
		return DSTU9212_ERROR;
	}
	*pk_len = 0;

	if (rho == NULL || t1 == NULL || pk == NULL || pk_capacity < DSTU9212_PK_OCTETS) {
		return DSTU9212_ERROR;
	}

	memcpy(pk, rho, DSTU9212_SEED_OCTETS);
	offset = DSTU9212_SEED_OCTETS;
	if (dstu9212_pack_vec(t1, DSTU9212_K, DSTU9212_Q_BITS - DSTU9212_D, 0,
						  pk + offset, pk_capacity - offset, &packed_len) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	*pk_len = offset + packed_len;
	return *pk_len == DSTU9212_PK_OCTETS ? DSTU9212_OK : DSTU9212_ERROR;
}

/*
 * Section 6.2.9, ds_unpack_pk.
 */
dstu9212_status dstu9212_unpack_pk(
	const uint8_t *pk, size_t pk_len,
	uint8_t *rho, int32_t *t1)
{
	size_t rest;

	if (pk == NULL || rho == NULL || t1 == NULL || pk_len != DSTU9212_PK_OCTETS) {
		return DSTU9212_ERROR;
	}

	memcpy(rho, pk, DSTU9212_SEED_OCTETS);
	rest = pk_len - DSTU9212_SEED_OCTETS;
	return dstu9212_unpack_vec(pk + DSTU9212_SEED_OCTETS, rest,
							   DSTU9212_K, DSTU9212_Q_BITS - DSTU9212_D, 0, t1);
}

/*
 * Section 6.2.10, ds_pack_sk.
 */
dstu9212_status dstu9212_pack_sk(
	const uint8_t *rho, const uint8_t *key, const uint8_t *tr,
	const int32_t *s1, const int32_t *s2, const int32_t *t0,
	uint8_t *sk, size_t sk_capacity, size_t *sk_len)
{
	size_t offset;
	size_t packed_len;

	if (sk_len == NULL) {
		return DSTU9212_ERROR;
	}
	*sk_len = 0;

	if (rho == NULL || key == NULL || tr == NULL || s1 == NULL || s2 == NULL ||
		t0 == NULL || sk == NULL || sk_capacity < DSTU9212_SK_OCTETS) {
		return DSTU9212_ERROR;
	}

	offset = 0;
	memcpy(sk + offset, rho, DSTU9212_SEED_OCTETS);
	offset += DSTU9212_SEED_OCTETS;
	memcpy(sk + offset, key, DSTU9212_SEED_OCTETS);
	offset += DSTU9212_SEED_OCTETS;
	memcpy(sk + offset, tr, DSTU9212_HASH_OCTETS);
	offset += DSTU9212_HASH_OCTETS;

	if (dstu9212_pack_vec(s1, DSTU9212_L, DSTU9212_LOG2_2ETA, DSTU9212_ETA,
						  sk + offset, sk_capacity - offset, &packed_len) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}
	offset += packed_len;
	if (dstu9212_pack_vec(s2, DSTU9212_K, DSTU9212_LOG2_2ETA, DSTU9212_ETA,
						  sk + offset, sk_capacity - offset, &packed_len) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}
	offset += packed_len;
	if (dstu9212_pack_vec(t0, DSTU9212_K, DSTU9212_D, t0_base(),
						  sk + offset, sk_capacity - offset, &packed_len) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}
	offset += packed_len;

	*sk_len = offset;
	return *sk_len == DSTU9212_SK_OCTETS ? DSTU9212_OK : DSTU9212_ERROR;
}

/*
 * Section 6.2.11, ds_unpack_sk.
 */
dstu9212_status dstu9212_unpack_sk(
	const uint8_t *sk, size_t sk_len,
	uint8_t *rho, uint8_t *key, uint8_t *tr,
	int32_t *s1, int32_t *s2, int32_t *t0)
{
	size_t offset;
	size_t s1_len;
	size_t s2_len;
	size_t t0_len;

	if (sk == NULL || rho == NULL || key == NULL || tr == NULL || s1 == NULL ||
		s2 == NULL || t0 == NULL || sk_len != DSTU9212_SK_OCTETS) {
		return DSTU9212_ERROR;
	}

	offset = 0;
	memcpy(rho, sk + offset, DSTU9212_SEED_OCTETS);
	offset += DSTU9212_SEED_OCTETS;
	memcpy(key, sk + offset, DSTU9212_SEED_OCTETS);
	offset += DSTU9212_SEED_OCTETS;
	memcpy(tr, sk + offset, DSTU9212_HASH_OCTETS);
	offset += DSTU9212_HASH_OCTETS;

	s1_len = dstu9212_vec_os_len(DSTU9212_L, DSTU9212_LOG2_2ETA);
	s2_len = dstu9212_vec_os_len(DSTU9212_K, DSTU9212_LOG2_2ETA);
	t0_len = dstu9212_vec_os_len(DSTU9212_K, DSTU9212_D);

	if (dstu9212_unpack_vec(sk + offset, s1_len, DSTU9212_L,
							DSTU9212_LOG2_2ETA, DSTU9212_ETA, s1) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}
	offset += s1_len;
	if (dstu9212_unpack_vec(sk + offset, s2_len, DSTU9212_K,
							DSTU9212_LOG2_2ETA, DSTU9212_ETA, s2) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}
	offset += s2_len;
	if (dstu9212_unpack_vec(sk + offset, t0_len, DSTU9212_K,
							DSTU9212_D, t0_base(), t0) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}

	return DSTU9212_OK;
}

/*
 * Section 7.2.6.3.1, ds_pack_matr_h.
 */
dstu9212_status dstu9212_pack_matr_h(
	const uint8_t *h, uint8_t *os, size_t os_capacity, size_t *os_len)
{
	size_t needed;
	size_t t = 0;
	size_t i;

	if (os_len == NULL) {
		return DSTU9212_ERROR;
	}
	*os_len = 0;

	needed = dstu9212_hint_os_len();
	if (h == NULL || os == NULL || os_capacity < needed) {
		return DSTU9212_ERROR;
	}

	memset(os, 0, needed);
	for (i = 0; i < DSTU9212_K; ++i) {
		size_t j;

		if (DSTU9212_N == 256) {
			for (j = 0; j < DSTU9212_N; ++j) {
				uint8_t value = h[i * DSTU9212_N + j];

				if (value > 1U) {
					return DSTU9212_ERROR;
				}
				if (value != 0U) {
					if (t >= DSTU9212_OMEGA) {
						return DSTU9212_ERROR;
					}
					os[t++] = (uint8_t)j;
				}
			}
			os[DSTU9212_OMEGA + i] = (uint8_t)t;
		} else {
			for (j = 0; j < 256U; ++j) {
				uint8_t value = h[i * DSTU9212_N + j];

				if (value > 1U) {
					return DSTU9212_ERROR;
				}
				if (value != 0U) {
					if (t >= DSTU9212_OMEGA) {
						return DSTU9212_ERROR;
					}
					os[t++] = (uint8_t)j;
				}
			}
			os[DSTU9212_OMEGA + 4U * i] = (uint8_t)(t & 0xffU);
			os[DSTU9212_OMEGA + 4U * i + 1U] = (uint8_t)(t >> 8);
			for (j = 256U; j < DSTU9212_N; ++j) {
				uint8_t value = h[i * DSTU9212_N + j];

				if (value > 1U) {
					return DSTU9212_ERROR;
				}
				if (value != 0U) {
					if (t >= DSTU9212_OMEGA) {
						return DSTU9212_ERROR;
					}
					os[t++] = (uint8_t)(j - 256U);
				}
			}
			os[DSTU9212_OMEGA + 4U * i + 2U] = (uint8_t)(t & 0xffU);
			os[DSTU9212_OMEGA + 4U * i + 3U] = (uint8_t)(t >> 8);
		}
	}

	*os_len = needed;
	return DSTU9212_OK;
}

/*
 * Section 7.2.6.3.2, ds_unpack_matr_h.
 */
dstu9212_status dstu9212_unpack_matr_h(
	const uint8_t *os, size_t os_len, uint8_t *h)
{
	uint16_t cnts[2U * DSTU9212_K];
	size_t cnts_len;
	size_t previous = 0;
	size_t i;
	size_t j;

	if (os == NULL || h == NULL || os_len != dstu9212_hint_os_len()) {
		return DSTU9212_ERROR;
	}

	memset(h, 0, DSTU9212_K * DSTU9212_N);
	cnts_len = DSTU9212_N == 256 ? DSTU9212_K : 2U * DSTU9212_K;

	for (i = 0; i < DSTU9212_K; ++i) {
		if (DSTU9212_N == 256) {
			cnts[i] = os[DSTU9212_OMEGA + i];
		} else {
			cnts[2U * i] = (uint16_t)(os[DSTU9212_OMEGA + 4U * i] |
				((uint16_t)os[DSTU9212_OMEGA + 4U * i + 1U] << 8));
			cnts[2U * i + 1U] = (uint16_t)(os[DSTU9212_OMEGA + 4U * i + 2U] |
				((uint16_t)os[DSTU9212_OMEGA + 4U * i + 3U] << 8));
		}
	}

	for (i = 0; i < cnts_len; ++i) {
		if (cnts[i] < previous || cnts[i] > DSTU9212_OMEGA) {
			return DSTU9212_ERROR;
		}
		previous = cnts[i];
	}
	for (j = previous; j < DSTU9212_OMEGA; ++j) {
		if (os[j] != 0U) {
			return DSTU9212_ERROR;
		}
	}

	j = 0;
	for (i = 0; i < DSTU9212_K; ++i) {
		if (DSTU9212_N == 256) {
			while (j < cnts[i]) {
				size_t pos = i * DSTU9212_N + os[j];

				if (h[pos] != 0U) {
					return DSTU9212_ERROR;
				}
				h[pos] = 1U;
				++j;
			}
		} else {
			while (j < cnts[2U * i]) {
				size_t pos = i * DSTU9212_N + os[j];

				if (h[pos] != 0U) {
					return DSTU9212_ERROR;
				}
				h[pos] = 1U;
				++j;
			}
			while (j < cnts[2U * i + 1U]) {
				size_t pos = i * DSTU9212_N + 256U + os[j];

				if (h[pos] != 0U) {
					return DSTU9212_ERROR;
				}
				h[pos] = 1U;
				++j;
			}
		}
	}

	return DSTU9212_OK;
}

/*
 * Section 7.2.6.1, ds_pack_ds.
 */
dstu9212_status dstu9212_pack_ds(
	const uint8_t *seed, const int32_t *z, const uint8_t *h,
	uint8_t *ds, size_t ds_capacity, size_t *ds_len)
{
	size_t offset;
	size_t packed_len;

	if (ds_len == NULL) {
		return DSTU9212_ERROR;
	}
	*ds_len = 0;

	if (seed == NULL || z == NULL || h == NULL || ds == NULL ||
		ds_capacity < DSTU9212_DS_OCTETS) {
		return DSTU9212_ERROR;
	}

	offset = 0;
	memcpy(ds + offset, seed, DSTU9212_SEED_OCTETS);
	offset += DSTU9212_SEED_OCTETS;

	if (check_signature_z(z) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}
	if (dstu9212_pack_vec(z, DSTU9212_L, DSTU9212_LOG2_Z, DSTU9212_GAMMA1,
						  ds + offset, ds_capacity - offset, &packed_len) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}
	offset += packed_len;
	if (dstu9212_pack_matr_h(h, ds + offset, ds_capacity - offset,
							 &packed_len) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}
	offset += packed_len;

	*ds_len = offset;
	return *ds_len == DSTU9212_DS_OCTETS ? DSTU9212_OK : DSTU9212_ERROR;
}

/*
 * Section 7.2.6.2, ds_unpack_ds.
 */
dstu9212_status dstu9212_unpack_ds(
	const uint8_t *ds, size_t ds_len,
	uint8_t *seed, int32_t *z, uint8_t *h)
{
	size_t offset;
	size_t z_len;

	if (ds == NULL || seed == NULL || z == NULL || h == NULL ||
		ds_len != DSTU9212_DS_OCTETS) {
		return DSTU9212_ERROR;
	}

	offset = 0;
	memcpy(seed, ds + offset, DSTU9212_SEED_OCTETS);
	offset += DSTU9212_SEED_OCTETS;

	z_len = dstu9212_vec_os_len(DSTU9212_L, DSTU9212_LOG2_Z);
	if (dstu9212_unpack_vec(ds + offset, z_len, DSTU9212_L,
							DSTU9212_LOG2_Z, DSTU9212_GAMMA1, z) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}
	if (check_signature_z(z) != DSTU9212_OK) {
		return DSTU9212_ERROR;
	}
	offset += z_len;

	return dstu9212_unpack_matr_h(ds + offset, ds_len - offset, h);
}
