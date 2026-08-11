/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Override: use standalone fips202_kyber (Keccak) instead of liboqs common
 * fips202. This avoids pulling in the full liboqs SHA3/fips202 common layer
 * on ESP32.
 *
 * Selected via MLD_CONFIG_FIPS202_CUSTOM_HEADER, set on the ml_dsa_65_ref
 * target in liboqs src/sig/ml_dsa/CMakeLists.txt. It replaces the upstream
 * integration/liboqs/fips202_glue.h, which maps to the OQS common SHA3.
 *
 * Only the single-stream API is provided, so the build must also define
 * MLD_CONFIG_SERIAL_FIPS202_ONLY; mldsa-native's symmetric.h then skips the
 * x4 header and matrix expansion runs serially through mld_xof128_*.
 */
#ifndef ESP_LIBOQS_MLD_FIPS202_GLUE_H
#define ESP_LIBOQS_MLD_FIPS202_GLUE_H

#include "fips202_kyber.h"

/* Map mldsa-native mld_* calls to fips202_kyber standalone Keccak */
#define mld_shake128ctx keccak_state
#define mld_shake128_init shake128_init
#define mld_shake128_absorb shake128_absorb
#define mld_shake128_finalize shake128_finalize
#define mld_shake128_squeeze shake128_squeeze
#define mld_shake128_release(CTX) ((void)(CTX))

#define mld_shake256ctx keccak_state
#define mld_shake256_init shake256_init
#define mld_shake256_absorb shake256_absorb
#define mld_shake256_finalize shake256_finalize
#define mld_shake256_squeeze shake256_squeeze
#define mld_shake256_release(CTX) ((void)(CTX))

#define mld_shake256 shake256

#endif /* !ESP_LIBOQS_MLD_FIPS202_GLUE_H */
