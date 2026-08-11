/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "oqs/oqs.h"
#include "sdkconfig.h"
#include "unity.h"
#include <stdlib.h>
#include <string.h>

#define HEAP_SLACK 512

TEST_CASE("ML-KEM-768 frees its transient heap scratch", "[liboqs][mem]") {
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  TEST_ASSERT_NOT_NULL(kem);

  uint8_t *pk = malloc(kem->length_public_key);
  uint8_t *sk = malloc(kem->length_secret_key);
  uint8_t *ct = malloc(kem->length_ciphertext);
  uint8_t *ss_e = malloc(kem->length_shared_secret);
  uint8_t *ss_d = malloc(kem->length_shared_secret);
  TEST_ASSERT_NOT_NULL(pk);
  TEST_ASSERT_NOT_NULL(sk);
  TEST_ASSERT_NOT_NULL(ct);
  TEST_ASSERT_NOT_NULL(ss_e);
  TEST_ASSERT_NOT_NULL(ss_d);

  size_t before = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_keypair(kem, pk, sk));
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_encaps(kem, ct, ss_e, pk));
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_KEM_decaps(kem, ss_d, ct, sk));
  size_t after = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);

  TEST_ASSERT_INT_WITHIN_MESSAGE(HEAP_SLACK, before, after,
                                 "ML-KEM transient scratch not fully freed");

  free(pk);
  free(sk);
  free(ct);
  free(ss_e);
  free(ss_d);
  OQS_KEM_free(kem);
}

TEST_CASE("ML-DSA-65 frees its transient heap scratch", "[liboqs][mem]") {
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  TEST_ASSERT_NOT_NULL(sig);

  static const uint8_t msg[] = "heap-scratch-release-probe";
  uint8_t *pk = malloc(sig->length_public_key);
  uint8_t *sk = malloc(sig->length_secret_key);
  uint8_t *s = malloc(sig->length_signature);
  size_t slen = 0;
  TEST_ASSERT_NOT_NULL(pk);
  TEST_ASSERT_NOT_NULL(sk);
  TEST_ASSERT_NOT_NULL(s);

  size_t before = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
  TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_keypair(sig, pk, sk));
  TEST_ASSERT_EQUAL(OQS_SUCCESS,
                    OQS_SIG_sign(sig, s, &slen, msg, sizeof(msg) - 1, sk));
  TEST_ASSERT_EQUAL(OQS_SUCCESS,
                    OQS_SIG_verify(sig, msg, sizeof(msg) - 1, s, slen, pk));
  size_t after = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);

  TEST_ASSERT_INT_WITHIN_MESSAGE(HEAP_SLACK, before, after,
                                 "ML-DSA transient scratch not fully freed");

  free(pk);
  free(sk);
  free(s);
  OQS_SIG_free(sig);
}

#if defined(CONFIG_LIBOQS_MLD_HEAP_TEMPORARIES)
#define SMALL_STACK_TASK_BYTES (12 * 1024)

typedef struct {
  volatile int ret;
  volatile UBaseType_t hwm;
  SemaphoreHandle_t done;
} small_ctx_t;

static void mldsa_small_stack_task(void *arg) {
  small_ctx_t *c = (small_ctx_t *)arg;
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  if (sig) {
    static const uint8_t m[] = "small-stack-probe";
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *s = malloc(sig->length_signature);
    size_t slen = 0;
    if (pk && sk && s && OQS_SIG_keypair(sig, pk, sk) == OQS_SUCCESS &&
        OQS_SIG_sign(sig, s, &slen, m, sizeof(m) - 1, sk) == OQS_SUCCESS &&
        OQS_SIG_verify(sig, m, sizeof(m) - 1, s, slen, pk) == OQS_SUCCESS) {
      c->ret = 0;
    } else {
      c->ret = -1;
    }
    free(pk);
    free(sk);
    free(s);
    OQS_SIG_free(sig);
  } else {
    c->ret = -2;
  }
  c->hwm = uxTaskGetStackHighWaterMark(NULL);
  xSemaphoreGive(c->done);
  vTaskDelete(NULL);
}

TEST_CASE("ML-DSA-65 runs in a 12 KB task (heap-backed)", "[liboqs][mem]") {
  small_ctx_t c = {.ret = -99, .hwm = 0, .done = xSemaphoreCreateBinary()};
  TEST_ASSERT_NOT_NULL(c.done);

  BaseType_t ok = xTaskCreate(mldsa_small_stack_task, "mldsa_small",
                              SMALL_STACK_TASK_BYTES, &c, 5, NULL);
  TEST_ASSERT_EQUAL(pdPASS, ok);
  TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(c.done, pdMS_TO_TICKS(30000)));

  /* The worker called vTaskDelete(NULL); the idle task reclaims its TCB and
   * stack asynchronously. Yield so that memory is back before tearDown's
   * heap-leak check runs (otherwise it false-positives by
   * ~SMALL_STACK_TASK_BYTES). */
  vTaskDelay(pdMS_TO_TICKS(100));

  printf("ML-DSA-65 in %d-byte task: ret=%d, stack HWM=%u bytes free\n",
         SMALL_STACK_TASK_BYTES, c.ret,
         (unsigned)c.hwm * (unsigned)sizeof(StackType_t));
  TEST_ASSERT_EQUAL_MESSAGE(0, c.ret,
                            "ML-DSA-65 sign/verify failed in small task");
  TEST_ASSERT_GREATER_THAN_MESSAGE(0, c.hwm,
                                   "task came within a hair of overflow");

  vSemaphoreDelete(c.done);
}
#endif /* heap-backed */
