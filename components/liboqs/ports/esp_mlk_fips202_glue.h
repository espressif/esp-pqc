/*
 * SPDX-FileCopyrightText: The mlkem-native project authors
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * Override: use standalone fips202_kyber (Keccak) instead of liboqs common fips202.
 * This avoids pulling in the full liboqs SHA3/fips202 common layer on ESP32.
 *
 * Selected via MLK_CONFIG_FIPS202_CUSTOM_HEADER, set on the ml_kem_768_ref
 * target in liboqs src/kem/ml_kem/CMakeLists.txt.
 */
#ifndef ESP_LIBOQS_MLK_FIPS202_GLUE_H
#define ESP_LIBOQS_MLK_FIPS202_GLUE_H

#include "fips202_kyber.h"

/* Map mlkem-native mlk_* calls to fips202_kyber standalone Keccak */
#define mlk_shake128ctx keccak_state
#define mlk_shake128_absorb_once shake128_absorb_once
#define mlk_shake128_squeezeblocks shake128_squeezeblocks
#define mlk_shake128_init shake128_init
#define mlk_shake128_release(CTX) ((void)(CTX))
#define mlk_shake256 shake256
#define mlk_sha3_256 sha3_256
#define mlk_sha3_512 sha3_512

#endif /* !ESP_LIBOQS_MLK_FIPS202_GLUE_H */
