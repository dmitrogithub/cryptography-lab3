// SPDX-License-Identifier: Apache-2.0
#include "dstu9212/utils.h"

void dstu9212_secure_zero(void *ptr, size_t len)
{
	volatile uint8_t *p = (volatile uint8_t *)ptr;

	if (ptr == NULL)
		return;
	while (len-- != 0U) {
		*p++ = 0U;
	}
}

int dstu9212_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
	uint32_t different = 0U;
	size_t i;

	if ((a == NULL || b == NULL) && len != 0U) {
		return 0;
	}
	for (i = 0; i < len; ++i) {
		different |= (uint32_t)(a[i] ^ b[i]);
	}

	/* different is at most 255, so its top bit after negation says whether
	 * any input byte differed. All arithmetic is deliberately unsigned. */
	return (int)(1U ^ ((different | (0U - different)) >> 31));
}
