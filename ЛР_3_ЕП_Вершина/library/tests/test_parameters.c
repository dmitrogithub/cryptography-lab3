// SPDX-License-Identifier: Apache-2.0
#include <dstu9212/parameters.h>

#define STATIC_ASSERT(name_, expr_) typedef char static_assert_##name_[(expr_) ? 1 : -1]

STATIC_ASSERT(pk_size_matches_formula, DSTU9212_PK_OCTETS == DSTU9212_PK_OCTETS_COMPUTED);
STATIC_ASSERT(sk_size_matches_formula, DSTU9212_SK_OCTETS == DSTU9212_SK_OCTETS_COMPUTED);
STATIC_ASSERT(ds_size_matches_formula, DSTU9212_DS_OCTETS == DSTU9212_DS_OCTETS_COMPUTED);
STATIC_ASSERT(q_matches_standard, DSTU9212_Q == 8380417);
STATIC_ASSERT(gamma1_matches_standard, DSTU9212_GAMMA1 == 523776);
STATIC_ASSERT(gamma2_matches_standard, DSTU9212_GAMMA2 == 261888);

int main(void)
{
    return 0;
}
