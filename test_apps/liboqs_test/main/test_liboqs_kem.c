/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "oqs/oqs.h"
#include "unity.h"
#include <stdlib.h>
#include <string.h>

/* Allocate the four KEM buffers from the heap and free them. */
typedef struct {
  uint8_t *pk, *sk, *ct, *ss_e, *ss_d;
} kem_bufs_t;

static void kem_bufs_alloc(const OQS_KEM *kem, kem_bufs_t *b) {
  b->pk = malloc(kem->length_public_key);
  b->sk = malloc(kem->length_secret_key);
  b->ct = malloc(kem->length_ciphertext);
  b->ss_e = malloc(kem->length_shared_secret);
  b->ss_d = malloc(kem->length_shared_secret);
  TEST_ASSERT_NOT_NULL(b->pk);
  TEST_ASSERT_NOT_NULL(b->sk);
  TEST_ASSERT_NOT_NULL(b->ct);
  TEST_ASSERT_NOT_NULL(b->ss_e);
  TEST_ASSERT_NOT_NULL(b->ss_d);
}

static void kem_bufs_free(kem_bufs_t *b) {
  free(b->pk);
  free(b->sk);
  free(b->ct);
  free(b->ss_e);
  free(b->ss_d);
  memset(b, 0, sizeof(*b));
}

/* keypair -> encaps -> decaps, shared secrets must agree. */
TEST_CASE("ML-KEM-768 encaps/decaps round-trip", "[liboqs][kem]") {
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  TEST_ASSERT_NOT_NULL_MESSAGE(kem, "ML-KEM-768 not enabled in this build");

  kem_bufs_t b;
  kem_bufs_alloc(kem, &b);

  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_keypair(kem, b.pk, b.sk));
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_encaps(kem, b.ct, b.ss_e, b.pk));
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_decaps(kem, b.ss_d, b.ct, b.sk));

  TEST_ASSERT_EQUAL_HEX8_ARRAY(b.ss_e, b.ss_d, kem->length_shared_secret);

  kem_bufs_free(&b);
  OQS_KEM_free(kem);
}

/* Many random keypairs in a row — stresses the heap alloc/free balance in the
 * override's indcpa keygen/encaps/decaps and catches leaks or corruption. */
TEST_CASE("ML-KEM-768 round-trip x20 (heap stability)", "[liboqs][kem]") {
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  TEST_ASSERT_NOT_NULL(kem);

  kem_bufs_t b;
  kem_bufs_alloc(kem, &b);

  for (int i = 0; i < 20; i++) {
    TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_keypair(kem, b.pk, b.sk));
    TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_encaps(kem, b.ct, b.ss_e, b.pk));
    TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_decaps(kem, b.ss_d, b.ct, b.sk));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(b.ss_e, b.ss_d, kem->length_shared_secret);
  }

  kem_bufs_free(&b);
  OQS_KEM_free(kem);
}

/* Tampered ciphertext: ML-KEM has implicit rejection, so decaps still returns
 * OQS_SUCCESS but the recovered secret must NOT equal the encapsulated one. */
TEST_CASE("ML-KEM-768 tampered ciphertext is rejected", "[liboqs][kem]") {
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  TEST_ASSERT_NOT_NULL(kem);

  kem_bufs_t b;
  kem_bufs_alloc(kem, &b);

  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_keypair(kem, b.pk, b.sk));
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_encaps(kem, b.ct, b.ss_e, b.pk));

  b.ct[0] ^= 0xFF; /* corrupt one byte */
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_decaps(kem, b.ss_d, b.ct, b.sk));

  /* Implicit rejection => secrets differ. */
  TEST_ASSERT_NOT_EQUAL(0, memcmp(b.ss_e, b.ss_d, kem->length_shared_secret));

  kem_bufs_free(&b);
  OQS_KEM_free(kem);
}

/* Decapsulating with the wrong secret key yields a different shared secret. */
TEST_CASE("ML-KEM-768 wrong secret key yields different secret",
          "[liboqs][kem]") {
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  TEST_ASSERT_NOT_NULL(kem);

  kem_bufs_t b;
  kem_bufs_alloc(kem, &b);
  uint8_t *sk2 = malloc(kem->length_secret_key);
  uint8_t *pk2 = malloc(kem->length_public_key);
  TEST_ASSERT_NOT_NULL(sk2);
  TEST_ASSERT_NOT_NULL(pk2);

  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_keypair(kem, b.pk, b.sk));
  TEST_ASSERT_EQUAL(OQS_SUCCESS,
                    OQS_KEM_keypair(kem, pk2, sk2)); /* unrelated */
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_encaps(kem, b.ct, b.ss_e, b.pk));
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_decaps(kem, b.ss_d, b.ct, sk2));

  TEST_ASSERT_NOT_EQUAL(0, memcmp(b.ss_e, b.ss_d, kem->length_shared_secret));

  free(sk2);
  free(pk2);
  kem_bufs_free(&b);
  OQS_KEM_free(kem);
}
