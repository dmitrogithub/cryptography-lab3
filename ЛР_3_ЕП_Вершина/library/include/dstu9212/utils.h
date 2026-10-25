// SPDX-License-Identifier: Apache-2.0
#ifndef DSTU9212_UTILS_H
#define DSTU9212_UTILS_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
	DSTU9212_ERROR = 0,
	DSTU9212_OK = 1
} dstu9212_status;

#ifdef __cplusplus
extern "C" {
#endif

/* These helpers are implemented out of line so the compiler cannot elide
 * secret-data erasure and callers do not need platform-specific APIs. */
void dstu9212_secure_zero(void *ptr, size_t len);

/* Returns 1 when the byte strings are equal and 0 otherwise. */
int dstu9212_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif
