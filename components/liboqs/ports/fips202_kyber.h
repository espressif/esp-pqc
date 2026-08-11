/* Declarations for the public domain FIPS 202 (Keccak) implementation from the
 * pq-crystals reference code: crypto_hash/keccakc512/simple/ from
 * http://bench.cr.yp.to/supercop.html by Ronny Van Keer, and "TweetFips202"
 * from https://twitter.com/tweetfips202 by Gilles Van Assche,
 * Daniel J. Bernstein, and Peter Schwabe */

/*
 * SPDX-FileCopyrightText: The pq-crystals Kyber authors
 *
 * SPDX-License-Identifier: (CC0-1.0 OR Apache-2.0) AND MIT
 *
 * SPDX-FileContributor: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * Taken from the Kyber reference implementation, ref/fips202.h:
 * https://github.com/pq-crystals/kyber/blob/4768bd37c02f9c40a46cb49d4d1f4d5e612bb882/ref/fips202.h
 *
 * The declarations, rates and namespace macro are unchanged from upstream. The
 * Espressif changes are the renamed include guard, the optional Keccak
 * permutation counters below, and the file name; see fips202_kyber.c for the
 * changes to the implementation.
 *
 * This standalone Keccak replaces the liboqs common SHA3/XKCP layer for
 * ML-KEM-768 and ML-DSA-65. It reaches those algorithms through liboqs's own
 * custom FIPS-202 header hook (MLK_CONFIG_FIPS202_CUSTOM_HEADER /
 * MLD_CONFIG_FIPS202_CUSTOM_HEADER), which the liboqs CMakeLists point at the
 * esp_ml{k,d}_fips202*_glue.h headers next to this file.
 */

#ifndef ESP_LIBOQS_FIPS202_KYBER_H
#define ESP_LIBOQS_FIPS202_KYBER_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72
/* Espressif addition: optional Keccak F1600 permutation counting for benchmark
 * analysis. Enabled by LIBOQS_DEBUG_INSTRUMENTATION (Kconfig, default off). */
#if defined(LIBOQS_DEBUG_INSTRUMENTATION) && !defined(MLD_KECCAK_COUNT_VERIFY)
#define MLD_KECCAK_COUNT_VERIFY 1
#endif
#define FIPS202_NAMESPACE(s) pqcrystals_kyber_fips202_ref_##s

typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

#define shake128_init FIPS202_NAMESPACE(shake128_init)
void shake128_init(keccak_state *state);
#define shake128_absorb FIPS202_NAMESPACE(shake128_absorb)
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake128_finalize FIPS202_NAMESPACE(shake128_finalize)
void shake128_finalize(keccak_state *state);
#define shake128_squeeze FIPS202_NAMESPACE(shake128_squeeze)
void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
#define shake128_absorb_once FIPS202_NAMESPACE(shake128_absorb_once)
void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake128_squeezeblocks FIPS202_NAMESPACE(shake128_squeezeblocks)
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);

#define shake256_init FIPS202_NAMESPACE(shake256_init)
void shake256_init(keccak_state *state);
#define shake256_absorb FIPS202_NAMESPACE(shake256_absorb)
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake256_finalize FIPS202_NAMESPACE(shake256_finalize)
void shake256_finalize(keccak_state *state);
#define shake256_squeeze FIPS202_NAMESPACE(shake256_squeeze)
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
#define shake256_absorb_once FIPS202_NAMESPACE(shake256_absorb_once)
void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake256_squeezeblocks FIPS202_NAMESPACE(shake256_squeezeblocks)
void shake256_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);

#define shake128 FIPS202_NAMESPACE(shake128)
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
#define shake256 FIPS202_NAMESPACE(shake256)
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
#define sha3_256 FIPS202_NAMESPACE(sha3_256)
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
#define sha3_512 FIPS202_NAMESPACE(sha3_512)
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);

#if defined(MLD_KECCAK_COUNT_VERIFY)
/* Espressif addition: count Keccak F1600 permutations (e.g. during
 * matrix_expand) for benchmark analysis. Define MLD_KECCAK_COUNT_VERIFY when
 * building. */
void mld_keccak_count_reset(void);
uint64_t mld_keccak_count_get(void);
uint64_t mld_keccak_squeeze_blocks_requested_get(void);
#endif

#endif
