/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "signature_basic.h"
#include "bootloader_random.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "esp_liboqs.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/projdefs.h"
#include "freertos/task.h"
#include "portmacro.h"
#include "test_mbedtls_ecdsa.h"
#include "test_rsa.h"
#include <hal/cpu_hal.h>
#include <math.h>
#include <oqs/oqs.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char *TAG = "sig_example";
static const char *ANALYSIS = "analysis";
SemaphoreHandle_t xSemaphoreSequential;

#define ENABLE_STACK_MONITORING 1 // 1: log FreeRTOS stack high-water marks
#define ENABLE_HEAP_MONITORING 1  // 1: log heap usage around tasks/functions

#define SIG_TEST_TASK_STACK_BYTES (8 * 1024)
#define RSA_ECDSA_TASK_STACK_BYTES (16 * 1024)

#define KEYGEN                                                                 \
  1 // 1: include keypair generation in liboqs path when not using fixed keys
#define SIGN 1   // 1: benchmark OQS_SIG_sign
#define VERIFY 1 // 1: benchmark OQS_SIG_verify

#define USE_COMMON_TEST_KEYS                                                   \
  1 // 1: sig_fixed_vectors (ML-DSA-65); 0: random keypair + message

typedef struct {
  uint64_t total_time;
  uint32_t max_time;
  uint32_t min_time;
  uint64_t total_cycles;
  uint32_t max_cycles;
  uint32_t min_cycles;
  /* Iterations actually measured. Zero means the phase did not run, for
     example keygen when the fixed test keys are used. */
  uint32_t iterations;
} timings_pqc;

timings_pqc ml_dsa_metrics[3];

enum { PQC_PHASE_KEYGEN = 0, PQC_PHASE_SIGN, PQC_PHASE_VERIFY };

const int iterations = 20;
#if ENABLE_STACK_MONITORING
#define STACK_MONITOR_START(task_handle, task_name, stack_size)                \
  do {                                                                         \
    UBaseType_t _stack_high_water_start =                                      \
        uxTaskGetStackHighWaterMark(task_handle);                              \
    UBaseType_t _stack_size = (stack_size);                                    \
    UBaseType_t _stack_used_start = _stack_size - _stack_high_water_start;     \
    ESP_LOGI(ANALYSIS,                                                         \
             "[STACK] %s: Start - Used: %lu B, Free: %lu B, Total: %lu B",     \
             task_name, _stack_used_start, _stack_high_water_start,            \
             _stack_size);                                                     \
  } while (0)

#define STACK_MONITOR_END(task_handle, task_name, stack_size)                  \
  do {                                                                         \
    UBaseType_t _stack_free_end = uxTaskGetStackHighWaterMark(task_handle);    \
    UBaseType_t _stack_size = (stack_size);                                    \
    UBaseType_t _stack_used_end = _stack_size - _stack_free_end;               \
    ESP_LOGI(ANALYSIS,                                                         \
             "[STACK] %s: End - Total: %lu B, Used: %lu B, Free: %lu B",       \
             task_name, _stack_size, _stack_used_end, _stack_free_end);        \
  } while (0)

#define STACK_MONITOR_FUNCTION_START(func_name)                                \
  do {                                                                         \
    UBaseType_t _stack_high_water = uxTaskGetStackHighWaterMark(NULL);         \
    ESP_LOGI(ANALYSIS, "[STACK] %s: Entry - Free: %lu B", func_name,           \
             _stack_high_water);                                               \
  } while (0)

#define STACK_MONITOR_FUNCTION_END(func_name)                                  \
  do {                                                                         \
    UBaseType_t _stack_high_water = uxTaskGetStackHighWaterMark(NULL);         \
    ESP_LOGI(ANALYSIS, "[STACK] %s: Exit - Free: %lu B", func_name,            \
             _stack_high_water);                                               \
  } while (0)
#else
#define STACK_MONITOR_START(task_handle, task_name, stack_size)
#define STACK_MONITOR_END(task_handle, task_name, stack_size)
#define STACK_MONITOR_FUNCTION_START(func_name)
#define STACK_MONITOR_FUNCTION_END(func_name)
#endif

// Heap monitoring macros
#if ENABLE_HEAP_MONITORING
#define HEAP_MONITOR_START(task_name)                                          \
  do {                                                                         \
    size_t _heap_min_free_start = esp_get_minimum_free_heap_size();            \
    size_t _heap_total = heap_caps_get_total_size(MALLOC_CAP_DEFAULT);         \
    size_t _heap_free_caps = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);      \
    size_t _heap_largest =                                                     \
        heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);                  \
    size_t _heap_used_start = _heap_total - _heap_free_caps;                   \
    ESP_LOGI(ANALYSIS,                                                         \
             "[HEAP] %s: Start - Used: %zu B, Free: %zu B, Total: %zu B, "     \
             "Largest: %zu B, Min Free: %zu B",                                \
             task_name, _heap_used_start, _heap_free_caps, _heap_total,        \
             _heap_largest, _heap_min_free_start);                             \
  } while (0)

#define HEAP_MONITOR_END(task_name)                                            \
  do {                                                                         \
    size_t _heap_min_free_end = esp_get_minimum_free_heap_size();              \
    size_t _heap_total = heap_caps_get_total_size(MALLOC_CAP_DEFAULT);         \
    size_t _heap_free_caps = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);      \
    size_t _heap_largest =                                                     \
        heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);                  \
    size_t _heap_used_end = _heap_total - _heap_free_caps;                     \
    ESP_LOGI(ANALYSIS,                                                         \
             "[HEAP] %s: End - Used: %zu B, Free: %zu B, Total: %zu B, "       \
             "Largest: %zu B, Min Free: %zu B",                                \
             task_name, _heap_used_end, _heap_free_caps, _heap_total,          \
             _heap_largest, _heap_min_free_end);                               \
  } while (0)

#define HEAP_MONITOR_FUNCTION_START(func_name)                                 \
  do {                                                                         \
    size_t _heap_free = esp_get_minimum_free_heap_size();                      \
    size_t _heap_free_caps = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);      \
    ESP_LOGI(ANALYSIS, "[HEAP] %s: Entry - Free: %zu B (min: %zu B)",          \
             func_name, _heap_free_caps, _heap_free);                          \
  } while (0)

#define HEAP_MONITOR_FUNCTION_END(func_name)                                   \
  do {                                                                         \
    size_t _heap_free = esp_get_minimum_free_heap_size();                      \
    size_t _heap_free_caps = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);      \
    ESP_LOGI(ANALYSIS, "[HEAP] %s: Exit - Free: %zu B (min: %zu B)",           \
             func_name, _heap_free_caps, _heap_free);                          \
  } while (0)
#else
#define HEAP_MONITOR_START(task_name)
#define HEAP_MONITOR_END(task_name)
#define HEAP_MONITOR_FUNCTION_START(func_name)
#define HEAP_MONITOR_FUNCTION_END(func_name)
#endif

// Combined macros for convenience
#define MONITOR_TASK_START(task_handle, task_name, stack_size)                 \
  do {                                                                         \
    STACK_MONITOR_START(task_handle, task_name, stack_size);                   \
    HEAP_MONITOR_START(task_name);                                             \
  } while (0)

#define MONITOR_TASK_END(task_handle, task_name, stack_size)                   \
  do {                                                                         \
    STACK_MONITOR_END(task_handle, task_name, stack_size);                     \
    HEAP_MONITOR_END(task_name);                                               \
  } while (0)

#define MONITOR_FUNCTION_START(func_name)                                      \
  do {                                                                         \
    STACK_MONITOR_FUNCTION_START(func_name);                                   \
    HEAP_MONITOR_FUNCTION_START(func_name);                                    \
  } while (0)

#define MONITOR_FUNCTION_END(func_name)                                        \
  do {                                                                         \
    STACK_MONITOR_FUNCTION_END(func_name);                                     \
    HEAP_MONITOR_FUNCTION_END(func_name);                                      \
  } while (0)

/**
 * @brief Print a buffer as C array on one line: { 0xXX, 0xYY, ... }
 *        Copy-paste into static const uint8_t name[] = { ... };
 *        Array is printed in 1 line (no newlines between bytes).
 */
static void print_buffer_as_c_array(const char *array_name, const uint8_t *buf,
                                    size_t len) {
  printf("static const uint8_t %s[] = { ", array_name);
  for (size_t i = 0; i < len; i++) {
    printf("0x%02X,", (unsigned int)buf[i]);
    if (i + 1 < len)
      printf(" ");
  }
  printf(" };\n");
  printf("static const size_t %s_len = %zu;\n", array_name, len);
}

/**
 * @brief Print full public key, secret key, signature and message as C arrays.
 *        Run once with KEYGEN=1 and SIGN=1, copy the output into your code,
 *        then use those arrays for verify-only test (KEYGEN=0, SIGN=0,
 * VERIFY=1).
 */
static void __attribute__((unused)) print_signature_test_vectors(
    const char *alg_name, const uint8_t *message, size_t message_len,
    const uint8_t *public_key, size_t public_key_len, const uint8_t *secret_key,
    size_t secret_key_len, const uint8_t *signature, size_t signature_len) {
  (void)alg_name;
  printf("========== COPY BELOW FOR VERIFY-ONLY TEST ==========\n");
  print_buffer_as_c_array("test_message", message, message_len);
  print_buffer_as_c_array("test_public_key", public_key, public_key_len);
  print_buffer_as_c_array("test_secret_key", secret_key, secret_key_len);
  print_buffer_as_c_array("test_signature", signature, signature_len);
  printf("========== END (signature_len = %zu for verify) ==========\n",
         signature_len);
}

/**
 * @brief Display performance statistics after iterations complete
 *
 * A phase that did not run reports that instead of printing a table, because
 * its accumulators still hold the initial values.
 */
static void display_performance_statistics(const char *phase_name,
                                           const timings_pqc *metrics) {
  if (metrics->iterations == 0) {
    ESP_LOGI(ANALYSIS, "");
    ESP_LOGI(ANALYSIS, "=== %s not measured in this run ===", phase_name);
    return;
  }

  double avg_time = (double)metrics->total_time / metrics->iterations;
  double avg_cycles = (double)metrics->total_cycles / metrics->iterations;

  ESP_LOGI(ANALYSIS, "");
  ESP_LOGI(ANALYSIS, "=== %s Performance Statistics (%lu iterations) ===",
           phase_name, (unsigned long)metrics->iterations);
  ESP_LOGI(ANALYSIS, "+------------------+---------------+------------------+");
  ESP_LOGI(ANALYSIS, "| Metric           | Time (ms)     | Cycles           |");
  ESP_LOGI(ANALYSIS, "+------------------+---------------+------------------+");
  ESP_LOGI(ANALYSIS, "| Average          | %13.2f | %16.0f |", avg_time,
           avg_cycles);
  ESP_LOGI(ANALYSIS, "| Maximum          | %13u | %16u |", metrics->max_time,
           metrics->max_cycles);
  ESP_LOGI(ANALYSIS, "| Minimum          | %13u | %16u |", metrics->min_time,
           metrics->min_cycles);
  ESP_LOGI(ANALYSIS, "+------------------+---------------+------------------+");
  ESP_LOGI(ANALYSIS, "");
}

/**
 * @brief Test a signature algorithm
 */
void test_signature(const char *alg_name) {
  // Reset metrics for this test
  memset(&ml_dsa_metrics, 0, sizeof(ml_dsa_metrics));

  ESP_LOGI(TAG, "========================================");
  ESP_LOGI(TAG, "Testing signature: %s", alg_name);
  ESP_LOGI(TAG, "========================================");

  /* Use OQS_SIG_new(alg_name) so this path works for any enabled liboqs
   * signature (not only ML-DSA-65). */
  OQS_SIG *sig = OQS_SIG_new(alg_name);
  if (sig == NULL) {
    ESP_LOGE(TAG, "Failed to create signature instance for %s", alg_name);
    return;
  }

  // Log sizes
  ESP_LOGI(TAG, "Public key:    %zu bytes", sig->length_public_key);
  ESP_LOGI(TAG, "Secret key:    %zu bytes", sig->length_secret_key);
  ESP_LOGI(TAG, "Signature:     %zu bytes", sig->length_signature);

#if USE_COMMON_TEST_KEYS
  const size_t message_len = test_message_len;
#else
  const size_t message_len = 100;
#endif

  // Allocate buffers
  uint8_t *public_key = malloc(sig->length_public_key);
  uint8_t *secret_key = malloc(sig->length_secret_key);
  uint8_t *message = malloc(message_len);
  uint8_t *signature = malloc(sig->length_signature);

  if (!public_key || !secret_key || !message || !signature) {
    ESP_LOGE(TAG, "Memory allocation failed!");
    goto cleanup;
  }

#if USE_COMMON_TEST_KEYS
  memcpy(public_key, test_public_key, test_public_key_len);
  memcpy(secret_key, test_secret_key, test_secret_key_len);
  memcpy(message, test_message, test_message_len);
#endif

  // Start from a clean slate so a second call does not accumulate on the first,
  // with the minimums seeded high.
  memset(ml_dsa_metrics, 0, sizeof(ml_dsa_metrics));
  for (int phase = 0; phase < 3; phase++) {
    ml_dsa_metrics[phase].min_time = UINT32_MAX;
    ml_dsa_metrics[phase].min_cycles = UINT32_MAX;
  }

  for (int i = 0; i < iterations; i++) {

    // ESP_LOGI(TAG, "Step 1: Generating keypair...");

    uint64_t start = esp_timer_get_time();
    uint32_t start_gen_key = esp_cpu_get_cycle_count();
#if KEYGEN && !USE_COMMON_TEST_KEYS
    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
      ESP_LOGE(TAG, "Keypair generation failed");
      goto cleanup;
    }
#endif
#if USE_COMMON_TEST_KEYS
    memcpy(public_key, test_public_key, test_public_key_len);
    memcpy(secret_key, test_secret_key, test_secret_key_len);
    memcpy(message, test_message, test_message_len);
#endif

    uint32_t end_gen_key = esp_cpu_get_cycle_count();
    uint32_t keypair_cycles = end_gen_key - start_gen_key;
    uint32_t keypair_time = (esp_timer_get_time() - start) / 1000;

#if !USE_COMMON_TEST_KEYS
    ml_dsa_metrics[PQC_PHASE_KEYGEN].total_time += keypair_time;
    ml_dsa_metrics[PQC_PHASE_KEYGEN].total_cycles += keypair_cycles;
    ml_dsa_metrics[PQC_PHASE_KEYGEN].max_cycles =
        fmax(ml_dsa_metrics[PQC_PHASE_KEYGEN].max_cycles, keypair_cycles);
    ml_dsa_metrics[PQC_PHASE_KEYGEN].min_cycles =
        fmin(ml_dsa_metrics[PQC_PHASE_KEYGEN].min_cycles, keypair_cycles);
    ml_dsa_metrics[PQC_PHASE_KEYGEN].max_time =
        fmax(ml_dsa_metrics[PQC_PHASE_KEYGEN].max_time, keypair_time);
    ml_dsa_metrics[PQC_PHASE_KEYGEN].min_time =
        fmin(ml_dsa_metrics[PQC_PHASE_KEYGEN].min_time, keypair_time);
    ml_dsa_metrics[PQC_PHASE_KEYGEN].iterations++;
#else
    (void)keypair_cycles;
    (void)keypair_time;
#endif

    // ESP_LOGI(TAG, "  Keypair generated in %lu ms and %d cycles", keypair_time
    // , end_gen_key - start_gen_key); print_hex("  Public key", public_key,
    // sig->length_public_key);

#if !USE_COMMON_TEST_KEYS
    // Generate random test message
    OQS_randombytes(message, message_len);
#endif
    // print_hex("  Test message", message, message_len);

    // Step 2: Sign message
    // ESP_LOGI(TAG, "Step 2: Signing message...");

    start = esp_timer_get_time();
    uint32_t start_sign = esp_cpu_get_cycle_count();
    size_t signature_len = 0;
#if SIGN
    if (OQS_SIG_sign(sig, signature, &signature_len, message, message_len,
                     secret_key) != OQS_SUCCESS) {
      ESP_LOGE(TAG, "Signing failed");
      goto cleanup;
    }
#endif
    uint32_t stop_sign = esp_cpu_get_cycle_count();
    uint32_t sign_cycles = stop_sign - start_sign;
    uint32_t sign_time = (esp_timer_get_time() - start) / 1000;

    // ESP_LOGI(TAG, "  Signed in %lu ms and %d cycles", sign_time , stop_sign -
    // start_sign); ESP_LOGI(TAG, "  Signature length: %zu bytes",
    // signature_len); print_hex("  Signature", signature, signature_len);

    ml_dsa_metrics[PQC_PHASE_SIGN].total_cycles += sign_cycles;
    ml_dsa_metrics[PQC_PHASE_SIGN].total_time += sign_time;

    ml_dsa_metrics[PQC_PHASE_SIGN].max_cycles =
        fmax(ml_dsa_metrics[PQC_PHASE_SIGN].max_cycles, sign_cycles);
    ml_dsa_metrics[PQC_PHASE_SIGN].min_cycles =
        fmin(ml_dsa_metrics[PQC_PHASE_SIGN].min_cycles, sign_cycles);

    ml_dsa_metrics[PQC_PHASE_SIGN].max_time =
        fmax(ml_dsa_metrics[PQC_PHASE_SIGN].max_time, sign_time);
    ml_dsa_metrics[PQC_PHASE_SIGN].min_time =
        fmin(ml_dsa_metrics[PQC_PHASE_SIGN].min_time, sign_time);
    ml_dsa_metrics[PQC_PHASE_SIGN].iterations++;

    // Step 3: Verify signature (should succeed)
    // ESP_LOGI(TAG, "Step 3: Verifying valid signature...");

    start = esp_timer_get_time();
    uint32_t start_veri = esp_cpu_get_cycle_count();
#if VERIFY
    if (OQS_SIG_verify(sig, message, message_len, signature, signature_len,
                       public_key) != OQS_SUCCESS) {
      ESP_LOGE(TAG, "  ✗ FAILURE: Valid signature verification failed!");
      goto cleanup;
    }
    // ESP_LOGI(TAG , "Verification Successful");
#endif
    uint32_t stop_veri = esp_cpu_get_cycle_count();
    uint32_t veri_cycles = stop_veri - start_veri;
    uint32_t verify_time = (esp_timer_get_time() - start) / 1000;

    // ESP_LOGI(TAG, "  ✓ SUCCESS: Signature is valid!");

    ml_dsa_metrics[PQC_PHASE_VERIFY].total_cycles += veri_cycles;
    ml_dsa_metrics[PQC_PHASE_VERIFY].total_time += verify_time;

    ml_dsa_metrics[PQC_PHASE_VERIFY].max_cycles =
        fmax(ml_dsa_metrics[PQC_PHASE_VERIFY].max_cycles, veri_cycles);
    ml_dsa_metrics[PQC_PHASE_VERIFY].min_cycles =
        fmin(ml_dsa_metrics[PQC_PHASE_VERIFY].min_cycles, veri_cycles);

    ml_dsa_metrics[PQC_PHASE_VERIFY].max_time =
        fmax(ml_dsa_metrics[PQC_PHASE_VERIFY].max_time, verify_time);
    ml_dsa_metrics[PQC_PHASE_VERIFY].min_time =
        fmin(ml_dsa_metrics[PQC_PHASE_VERIFY].min_time, verify_time);
    ml_dsa_metrics[PQC_PHASE_VERIFY].iterations++;

#if SIGN
    // ESP_LOGI(TAG, "Step 4: Verifying corrupted signature (should fail)...");

    // Save original signature for later
    uint8_t *original_signature = malloc(signature_len);
    if (original_signature) {
      memcpy(original_signature, signature, signature_len);
    }

    // Corrupt the signature
    OQS_randombytes(signature, signature_len);

    if (OQS_SIG_verify(sig, message, message_len, signature, signature_len,
                       public_key) == OQS_SUCCESS) {
      ESP_LOGE(TAG,
               "  ✗ FAILURE: Corrupted signature should have been rejected!");
      if (original_signature)
        OQS_MEM_insecure_free(original_signature);
      goto cleanup;
    }

    // ESP_LOGI(TAG, "  ✓ SUCCESS: Corrupted signature correctly rejected!");

    if (original_signature) {
      OQS_MEM_insecure_free(original_signature);
    }
#endif
  }

  // Display performance statistics for all phases
  ESP_LOGI(TAG, "");
  ESP_LOGI(TAG, "========================================");
  ESP_LOGI(TAG, "Performance Analysis Summary for %s", alg_name);
  ESP_LOGI(TAG, "========================================");

  display_performance_statistics("KEYGEN", &ml_dsa_metrics[PQC_PHASE_KEYGEN]);
  display_performance_statistics("SIGN", &ml_dsa_metrics[PQC_PHASE_SIGN]);
  display_performance_statistics("VERIFY", &ml_dsa_metrics[PQC_PHASE_VERIFY]);

cleanup:
  // Securely free sensitive data
  if (secret_key) {
    OQS_MEM_secure_free(secret_key, sig->length_secret_key);
  }

  // Free non-sensitive data
  if (public_key) {
    OQS_MEM_insecure_free(public_key);
  }
  if (message) {
    OQS_MEM_insecure_free(message);
  }
  if (signature) {
    OQS_MEM_insecure_free(signature);
  }

  OQS_SIG_free(sig);
  ESP_LOGI(TAG, "cleanup done!!");
}

/**
 * @brief Task that runs signature tests
 */
static void signature_test_task(void *pvParameters) {

  const char *task_name = "signature_test_task";
  const UBaseType_t stack_size = SIG_TEST_TASK_STACK_BYTES;

  MONITOR_TASK_START(NULL, task_name, stack_size);

  ESP_LOGI(TAG, "Signature test task started");
  ESP_LOGI(TAG, "Total signature algorithms available: %zu",
           OQS_SIG_alg_count());
  ESP_LOGI(TAG, "");

  // Default: ML-DSA-65 (documented benchmark). Change the string or add calls
  // below for ML-DSA-44, ML-DSA-87, Falcon-512, SNOVA_24_5_4,
  // cross-rsdp-128-small, …
  if (OQS_SIG_alg_is_enabled("ML-DSA-65")) {
    test_signature("ML-DSA-65");
  } else {
    ESP_LOGW(TAG, "ML-DSA-65 not enabled in build");
    ESP_LOGW(TAG, "Enable via: idf.py menuconfig → Component config → liboqs");
  }

  vTaskDelay(pdMS_TO_TICKS(2000));

  /* Other liboqs signatures — enable in menuconfig, set USE_COMMON_TEST_KEYS 0
   * unless you supply matching vectors in sig_fixed_vectors. */
  // if (OQS_SIG_alg_is_enabled("ML-DSA-44")) {
  //   test_signature("ML-DSA-44");
  // }
  // vTaskDelay(pdMS_TO_TICKS(2000));
  // if (OQS_SIG_alg_is_enabled("ML-DSA-87")) {
  //   test_signature("ML-DSA-87");
  // }
  // vTaskDelay(pdMS_TO_TICKS(2000));
  // if (OQS_SIG_alg_is_enabled("Falcon-512")) {
  //   test_signature("Falcon-512");
  // }
  // vTaskDelay(pdMS_TO_TICKS(2000));
  // if (OQS_SIG_alg_is_enabled("SNOVA_24_5_4")) {
  //   test_signature("SNOVA_24_5_4");
  // }

  vTaskDelay(pdMS_TO_TICKS(2000));

  // ESP_LOGI(TAG, "========================================");
  // ESP_LOGI(TAG, "Example complete!");
  // ESP_LOGI(TAG, "========================================");

#ifdef CONFIG_LIBOQS_ENABLE_PROFILING
  // Print profiling results
  ESP_LOGI(TAG, "");
  ESP_LOGI(TAG, "========================================");
  ESP_LOGI(TAG, "PROFILING RESULTS");
  ESP_LOGI(TAG, "========================================");
  esp_liboqs_profile_print();
  ESP_LOGI(TAG, "");
#endif

  ESP_LOGI(TAG, "Signature test task completed, deleting task");

  MONITOR_TASK_END(NULL, task_name, stack_size);

  xSemaphoreGive(xSemaphoreSequential);
  vTaskDelete(NULL);
}

static void classical_rsa_ecdsa_task(void *pvParameters) {
  (void)pvParameters;
  const char *task_name = "rsa_ecdsa_classical";
  const UBaseType_t stack_size = RSA_ECDSA_TASK_STACK_BYTES;

  if (xSemaphoreTake(xSemaphoreSequential, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "classical_rsa_ecdsa_task: Failed to take semaphore");
    vTaskDelete(NULL);
    return;
  }

  vTaskDelay(pdMS_TO_TICKS(100));

  MONITOR_TASK_START(NULL, task_name, stack_size);

  ESP_LOGI(TAG, "Running RSA-2048 key generation test...");
  run_mbedtls_rsa_gen_key_test(2048);
  vTaskDelay(pdMS_TO_TICKS(500));

  ESP_LOGI(TAG, "Running RSA-3072 key generation test...");
  run_mbedtls_rsa_gen_key_test(3072);
  vTaskDelay(pdMS_TO_TICKS(500));

  ESP_LOGI(TAG, "Running RSA performance test (PSA)...");
  rsa_key_operations_psa(2048, true, true);
  vTaskDelay(pdMS_TO_TICKS(1000));

  ESP_LOGI(TAG, "Running ECDSA verify tests (PSA API)...");
  MONITOR_FUNCTION_START("test_case_192");
  test_case_192();
  MONITOR_FUNCTION_END("test_case_192");
  vTaskDelay(pdMS_TO_TICKS(1000));

  MONITOR_FUNCTION_START("test_case_256");
  test_case_256();
  MONITOR_FUNCTION_END("test_case_256");

  MONITOR_TASK_END(NULL, task_name, stack_size);
  ESP_LOGI(TAG, "Classical RSA/ECDSA comparison task done");

  bootloader_random_disable();

  vTaskDelay(pdMS_TO_TICKS(500));
  xSemaphoreGive(xSemaphoreSequential);
  vTaskDelete(NULL);
}

void app_main(void) {
  vTaskDelay(pdMS_TO_TICKS(1000));

  xSemaphoreSequential = xSemaphoreCreateBinary();
  if (xSemaphoreSequential == NULL) {
    ESP_LOGE(TAG, "Failed to create semaphore");
    return;
  }

  ESP_LOGI(TAG, "========================================");
  ESP_LOGI(TAG, "liboqs Signature Example for ESP-IDF");
  ESP_LOGI(TAG, "========================================");
  ESP_LOGI(TAG, "liboqs version: %s", OQS_version());
  ESP_LOGI(TAG, "Chip: %s", CONFIG_IDF_TARGET);
  ESP_LOGI(TAG, "");

  // Note: If CONFIG_LIBOQS_AUTO_INIT_RNG=y, RNG is already initialized
  // Otherwise, you must call esp_liboqs_rng_init() here

  /* No radio here, so enable the ADC entropy source; disabled in the last task. */
  bootloader_random_enable();

  TaskHandle_t sig_task_handle = NULL;
  BaseType_t result =
      xTaskCreate(signature_test_task, "sig_test", SIG_TEST_TASK_STACK_BYTES,
                  NULL, 5, &sig_task_handle);

  if (result != pdPASS) {
    ESP_LOGE(TAG, "Failed to create signature test task");
    return;
  }

  xTaskCreate(classical_rsa_ecdsa_task, "rsa_ecdsa_classical",
              RSA_ECDSA_TASK_STACK_BYTES, NULL, 5, NULL);
}
