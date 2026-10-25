// SPDX-License-Identifier: Apache-2.0
#include "dstu9212/tables.h"

#include <stdio.h>

int main(void)
{
	if (DSTU9212_NTT_Z256_LEN != 256U ||
		DSTU9212_NTT_Z512_LEN != 512U ||
		DSTU9212_NTT_N256_INV != 8347681U ||
		DSTU9212_NTT_N512_INV != 8364049U) {
		fprintf(stderr, "test_tables constants failed\n");
		return 1;
	}

	if (dstu9212_ntt_z256[0] != 0U ||
		dstu9212_ntt_z256[1] != 4808194U ||
		dstu9212_ntt_z256[255] != 7648983U ||
		dstu9212_ntt_z256_inv[0] != 731434U ||
		dstu9212_ntt_z256_inv[255] != 8380416U) {
		fprintf(stderr, "test_tables z256 failed\n");
		return 1;
	}

	if (dstu9212_ntt_z512[0] != 0U ||
		dstu9212_ntt_z512[1] != 4808194U ||
		dstu9212_ntt_z512[511] != 3095209U ||
		dstu9212_ntt_z512_inv[0] != 5285208U ||
		dstu9212_ntt_z512_inv[511] != 8380416U) {
		fprintf(stderr, "test_tables z512 failed\n");
		return 1;
	}

	return 0;
}
