/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "oqs/oqs.h"
#include "unity.h"
#include <stdlib.h>
#include <string.h>

static const uint8_t MESSAGE[] = "esp-liboqs ML-DSA-65 test vector — the quick "
                                 "brown fox jumps over 13 lazy dogs.";
#define MESSAGE_LEN (sizeof(MESSAGE) - 1)

typedef struct {
  uint8_t *pk, *sk, *sig;
  size_t sig_len;
} sig_bufs_t;

static void sig_bufs_alloc(const OQS_SIG *sig, sig_bufs_t *b) {
  b->pk = malloc(sig->length_public_key);
  b->sk = malloc(sig->length_secret_key);
  b->sig = malloc(sig->length_signature);
  b->sig_len = 0;
  TEST_ASSERT_NOT_NULL(b->pk);
  TEST_ASSERT_NOT_NULL(b->sk);
  TEST_ASSERT_NOT_NULL(b->sig);
}

static void sig_bufs_free(sig_bufs_t *b) {
  free(b->pk);
  free(b->sk);
  free(b->sig);
  memset(b, 0, sizeof(*b));
}

/* keypair -> sign -> verify, must succeed. */
TEST_CASE("ML-DSA-65 sign/verify round-trip", "[liboqs][sig]") {
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  TEST_ASSERT_NOT_NULL_MESSAGE(sig, "ML-DSA-65 not enabled in this build");

  sig_bufs_t b;
  sig_bufs_alloc(sig, &b);

  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_keypair(sig, b.pk, b.sk));
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_sign(sig, b.sig, &b.sig_len, MESSAGE,
                                              MESSAGE_LEN, b.sk));
  TEST_ASSERT_TRUE(b.sig_len > 0 && b.sig_len <= sig->length_signature);
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_verify(sig, MESSAGE, MESSAGE_LEN,
                                                b.sig, b.sig_len, b.pk));

  sig_bufs_free(&b);
  OQS_SIG_free(sig);
}

/* Repeated keygen/sign/verify — heap stability for the override's heap-backed
 * sign/verify scratch (alloc/free balance, zeroization, no corruption). */
TEST_CASE("ML-DSA-65 round-trip x20 (heap stability)", "[liboqs][sig]") {
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  TEST_ASSERT_NOT_NULL(sig);

  sig_bufs_t b;
  sig_bufs_alloc(sig, &b);

  for (int i = 0; i < 20; i++) {
    TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_keypair(sig, b.pk, b.sk));
    TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_sign(sig, b.sig, &b.sig_len, MESSAGE,
                                                MESSAGE_LEN, b.sk));
    TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_verify(sig, MESSAGE, MESSAGE_LEN,
                                                  b.sig, b.sig_len, b.pk));
  }

  sig_bufs_free(&b);
  OQS_SIG_free(sig);
}

/* A flipped signature byte must fail verification. */
TEST_CASE("ML-DSA-65 tampered signature fails verify", "[liboqs][sig]") {
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  TEST_ASSERT_NOT_NULL(sig);

  sig_bufs_t b;
  sig_bufs_alloc(sig, &b);

  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_keypair(sig, b.pk, b.sk));
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_sign(sig, b.sig, &b.sig_len, MESSAGE,
                                              MESSAGE_LEN, b.sk));

  b.sig[b.sig_len / 2] ^= 0x01; /* flip a bit in the middle of the signature */
  TEST_ASSERT_NOT_EQUAL(OQS_SUCCESS, OQS_SIG_verify(sig, MESSAGE, MESSAGE_LEN,
                                                    b.sig, b.sig_len, b.pk));

  sig_bufs_free(&b);
  OQS_SIG_free(sig);
}

/* A modified message must fail verification against the original signature. */
TEST_CASE("ML-DSA-65 tampered message fails verify", "[liboqs][sig]") {
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  TEST_ASSERT_NOT_NULL(sig);

  sig_bufs_t b;
  sig_bufs_alloc(sig, &b);

  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_keypair(sig, b.pk, b.sk));
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_sign(sig, b.sig, &b.sig_len, MESSAGE,
                                              MESSAGE_LEN, b.sk));

  uint8_t *bad_msg = malloc(MESSAGE_LEN);
  TEST_ASSERT_NOT_NULL(bad_msg);
  memcpy(bad_msg, MESSAGE, MESSAGE_LEN);
  bad_msg[0] ^= 0x01;

  TEST_ASSERT_NOT_EQUAL(OQS_SUCCESS, OQS_SIG_verify(sig, bad_msg, MESSAGE_LEN,
                                                    b.sig, b.sig_len, b.pk));

  free(bad_msg);
  sig_bufs_free(&b);
  OQS_SIG_free(sig);
}

/* Verifying against an unrelated public key must fail. */
TEST_CASE("ML-DSA-65 wrong public key fails verify", "[liboqs][sig]") {
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  TEST_ASSERT_NOT_NULL(sig);

  sig_bufs_t b;
  sig_bufs_alloc(sig, &b);
  uint8_t *pk2 = malloc(sig->length_public_key);
  uint8_t *sk2 = malloc(sig->length_secret_key);
  TEST_ASSERT_NOT_NULL(pk2);
  TEST_ASSERT_NOT_NULL(sk2);

  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_keypair(sig, b.pk, b.sk));
  TEST_ASSERT_EQUAL(OQS_SUCCESS,
                    OQS_SIG_keypair(sig, pk2, sk2)); /* unrelated */
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_sign(sig, b.sig, &b.sig_len, MESSAGE,
                                              MESSAGE_LEN, b.sk));

  TEST_ASSERT_NOT_EQUAL(OQS_SUCCESS, OQS_SIG_verify(sig, MESSAGE, MESSAGE_LEN,
                                                    b.sig, b.sig_len, pk2));

  free(pk2);
  free(sk2);
  sig_bufs_free(&b);
  OQS_SIG_free(sig);
}
