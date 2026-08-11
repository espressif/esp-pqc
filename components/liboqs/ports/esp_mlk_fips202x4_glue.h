/*
 * SPDX-FileCopyrightText: The mlkem-native project authors
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * Override: serial-only x4 implementation for ESP32.
 * Maps x4 calls to sequential single-stream fips202_kyber calls.
 *
 * Selected via MLK_CONFIG_FIPS202X4_CUSTOM_HEADER, set on the ml_kem_768_ref
 * target in liboqs src/kem/ml_kem/CMakeLists.txt.
 */
#ifndef ESP_LIBOQS_MLK_FIPS202X4_GLUE_H
#define ESP_LIBOQS_MLK_FIPS202X4_GLUE_H

#include "fips202_kyber.h"

/* x4 context: just 4 independent keccak states */
typedef struct {
    keccak_state s[4];
} mlk_shake128x4ctx;

static inline void mlk_shake128x4_init(mlk_shake128x4ctx *ctx) {
    for (int i = 0; i < 4; i++) shake128_init(&ctx->s[i]);
}

static inline void mlk_shake128x4_absorb_once(
    mlk_shake128x4ctx *ctx,
    const uint8_t *in0, const uint8_t *in1,
    const uint8_t *in2, const uint8_t *in3,
    size_t inlen) {
    shake128_absorb_once(&ctx->s[0], in0, inlen);
    shake128_absorb_once(&ctx->s[1], in1, inlen);
    shake128_absorb_once(&ctx->s[2], in2, inlen);
    shake128_absorb_once(&ctx->s[3], in3, inlen);
}

static inline void mlk_shake128x4_squeezeblocks(
    uint8_t *out0, uint8_t *out1,
    uint8_t *out2, uint8_t *out3,
    size_t nblocks, mlk_shake128x4ctx *ctx) {
    shake128_squeezeblocks(out0, nblocks, &ctx->s[0]);
    shake128_squeezeblocks(out1, nblocks, &ctx->s[1]);
    shake128_squeezeblocks(out2, nblocks, &ctx->s[2]);
    shake128_squeezeblocks(out3, nblocks, &ctx->s[3]);
}

static inline void mlk_shake128x4_release(mlk_shake128x4ctx *ctx) {
    (void)ctx;
}

static inline void mlk_shake256x4(
    uint8_t *out0, uint8_t *out1,
    uint8_t *out2, uint8_t *out3,
    size_t outlen,
    const uint8_t *in0, const uint8_t *in1,
    const uint8_t *in2, const uint8_t *in3,
    size_t inlen) {
    shake256(out0, outlen, in0, inlen);
    shake256(out1, outlen, in1, inlen);
    shake256(out2, outlen, in2, inlen);
    shake256(out3, outlen, in3, inlen);
}

#endif /* !ESP_LIBOQS_MLK_FIPS202X4_GLUE_H */
