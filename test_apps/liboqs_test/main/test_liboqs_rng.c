/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "esp_liboqs.h"
#include "oqs/oqs.h"
#include "unity.h"
#include <string.h>

/* esp_liboqs_randombytes must fill the buffer and not leave it all-zero. */
TEST_CASE("esp_liboqs_randombytes fills buffer", "[liboqs][rng]") {
  uint8_t buf[64];
  memset(buf, 0, sizeof(buf));
  esp_liboqs_randombytes(buf, sizeof(buf));

  int nonzero = 0;
  for (size_t i = 0; i < sizeof(buf); i++) {
    if (buf[i] != 0) {
      nonzero++;
    }
  }
  /* All-zero from a 64-byte draw is astronomically unlikely. */
  TEST_ASSERT_GREATER_THAN(0, nonzero);
}

/* Two successive draws must differ (no static/repeating output). */
TEST_CASE("esp_liboqs_randombytes draws differ", "[liboqs][rng]") {
  uint8_t a[64], b[64];
  esp_liboqs_randombytes(a, sizeof(a));
  esp_liboqs_randombytes(b, sizeof(b));
  TEST_ASSERT_NOT_EQUAL(0, memcmp(a, b, sizeof(a)));
}

TEST_CASE("OQS_randombytes produces fresh output", "[liboqs][rng]") {
  uint8_t a[48], b[48];
  OQS_randombytes(a, sizeof(a));
  OQS_randombytes(b, sizeof(b));
  TEST_ASSERT_NOT_EQUAL(0, memcmp(a, b, sizeof(a)));
}
