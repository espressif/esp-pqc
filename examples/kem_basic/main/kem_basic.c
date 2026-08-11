/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bootloader_random.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/projdefs.h"
#include "freertos/task.h"
#include <oqs/oqs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEM_TEST_TASK_STACK_BYTES (12 * 1024)

/* Include ML-KEM timing header */
#include "kem.h"

static const char *TAG = "kem_example";
static const char *ANALYSIS = "analysis";
SemaphoreHandle_t xSemaphoreSequential;

/**
 * @brief Performance metrics structure
 */
typedef struct {
  const char *operation_name;
  uint64_t total_time_us;
  uint64_t total_cycles;
  uint64_t max_time_us;
  uint64_t min_time_us;
  uint64_t max_cycles;
  uint64_t min_cycles;
  uint32_t iteration_count;
} perf_metrics_t;

/**
 * @brief Initialize performance metrics structure
 */
static void perf_metrics_init(perf_metrics_t *metrics,
                              const char *operation_name) {
  metrics->operation_name = operation_name;
  metrics->total_time_us = 0;
  metrics->total_cycles = 0;
  metrics->max_time_us = 0;
  metrics->min_time_us = UINT64_MAX;
  metrics->max_cycles = 0;
  metrics->min_cycles = UINT64_MAX;
  metrics->iteration_count = 0;
}

static void perf_metrics_update(perf_metrics_t *metrics, uint64_t time_us,
                                uint64_t cycles) {
  metrics->total_time_us += time_us;
  metrics->total_cycles += cycles;

  if (time_us > metrics->max_time_us) {
    metrics->max_time_us = time_us;
  }
  if (time_us < metrics->min_time_us) {
    metrics->min_time_us = time_us;
  }

  if (cycles > metrics->max_cycles) {
    metrics->max_cycles = cycles;
  }
  if (cycles < metrics->min_cycles) {
    metrics->min_cycles = cycles;
  }

  metrics->iteration_count++;
}

#define ENABLE_HEAP_MONITORING 1  // 1: log heap usage around tasks/functions
#define ENABLE_STACK_MONITORING 1 // 1: log FreeRTOS stack high-water marks

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
    UBaseType_t _stack_high_water_end =                                        \
        uxTaskGetStackHighWaterMark(task_handle);                              \
    UBaseType_t _stack_size = (stack_size);                                    \
    UBaseType_t _stack_used_end = _stack_size - _stack_high_water_end;         \
    UBaseType_t _stack_peak = _stack_size - _stack_high_water_end;             \
    ESP_LOGI(ANALYSIS,                                                         \
             "[STACK] %s: End - Used: %lu B, Free: %lu B, Peak: %lu B",        \
             task_name, _stack_used_end, _stack_high_water_end, _stack_peak);  \
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

// Combined macros for overall measurements
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

static void test_kem(const char *alg_name) {

  const char *task_name = "test_kem_task";
  const UBaseType_t stack_size_ = KEM_TEST_TASK_STACK_BYTES;
  const int NUM_ITERATIONS = 20;

  // Memory tracking - start
  size_t heap_start = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
  size_t heap_total = heap_caps_get_total_size(MALLOC_CAP_DEFAULT);
  UBaseType_t stack_start = uxTaskGetStackHighWaterMark(NULL);

  MONITOR_TASK_START(NULL, task_name, stack_size_);

  ESP_LOGI(TAG, "========================================");
  ESP_LOGI(TAG, "Testing KEM: %s (%d iterations)", alg_name, NUM_ITERATIONS);
  ESP_LOGI(TAG, "========================================");

  // Initialize performance metrics
  perf_metrics_t keypair_metrics, encaps_metrics, decaps_metrics;
  perf_metrics_init(&keypair_metrics, alg_name);
  perf_metrics_init(&encaps_metrics, alg_name);
  perf_metrics_init(&decaps_metrics, alg_name);

  // Create KEM instance
  OQS_KEM *kem = OQS_KEM_new(alg_name);
  if (kem == NULL) {
    ESP_LOGE(TAG, "Failed to create KEM instance for %s", alg_name);
    return;
  }

  // Log sizes in parseable format
  ESP_LOGI(ANALYSIS,
           "[KEM_SIZE] algorithm=%s | public_key=%zu | secret_key=%zu | "
           "ciphertext=%zu | shared_secret=%zu",
           alg_name, kem->length_public_key, kem->length_secret_key,
           kem->length_ciphertext, kem->length_shared_secret);

  // Allocate buffers
  uint8_t *public_key = malloc(kem->length_public_key);
  uint8_t *secret_key = malloc(kem->length_secret_key);
  uint8_t *ciphertext = malloc(kem->length_ciphertext);
  uint8_t *shared_secret_e = malloc(kem->length_shared_secret);
  uint8_t *shared_secret_d = malloc(kem->length_shared_secret);

  if (!public_key || !secret_key || !ciphertext || !shared_secret_e ||
      !shared_secret_d) {
    ESP_LOGE(TAG, "Memory allocation failed!");
    goto cleanup;
  }

  /* Generate keypair once and use for all iterations (guarantees valid key
   * pair) */
  if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
    ESP_LOGE(TAG, "Keypair generation failed");
    goto cleanup;
  }
  ESP_LOGI(TAG,
           "Generated keypair once; using same keys for all %d encaps/decaps "
           "iterations",
           NUM_ITERATIONS);

  ESP_LOGI(TAG, "Running %d iterations...", NUM_ITERATIONS);

  mlkem_timing_data_t mlkem_accum;
  memset(&mlkem_accum, 0, sizeof(mlkem_accum));

  // Run multiple iterations (encaps + decaps only; keys are fixed)
  for (int iter = 0; iter < NUM_ITERATIONS; iter++) {
    // Step 1: Encapsulation (sender side)
    uint64_t start_time = esp_timer_get_time();
    uint64_t start_cycles = esp_cpu_get_cycle_count();

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key) !=
        OQS_SUCCESS) {
      ESP_LOGE(TAG, "Encapsulation failed at iteration %d", iter + 1);
      goto cleanup;
    }

    uint64_t end_cycles = esp_cpu_get_cycle_count();
    uint64_t end_time = esp_timer_get_time();

    uint64_t encaps_time_us = end_time - start_time;
    uint64_t encaps_cycles = end_cycles - start_cycles;
    perf_metrics_update(&encaps_metrics, encaps_time_us, encaps_cycles);

    // Step 2: Decapsulation (receiver side)
    start_time = esp_timer_get_time();
    start_cycles = esp_cpu_get_cycle_count();

    int decaps_rc =
        OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
    if (decaps_rc != OQS_SUCCESS) {
      ESP_LOGE(TAG, "Decapsulation failed at iteration %d (rc=%d)", iter + 1,
               decaps_rc);
      goto cleanup;
    }

    end_cycles = esp_cpu_get_cycle_count();
    end_time = esp_timer_get_time();

    uint64_t decaps_time_us = end_time - start_time;
    uint64_t decaps_cycles = end_cycles - start_cycles;
    perf_metrics_update(&decaps_metrics, decaps_time_us, decaps_cycles);

    // Verify shared secrets match
    if (memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret) !=
        0) {
      ESP_LOGE(TAG, "  ✗ FAILURE: Shared secrets do not match at iteration %d!",
               iter + 1);
      goto cleanup;
    }
  }

  ESP_LOGI(TAG, "✓ All %d iterations completed successfully!", NUM_ITERATIONS);

  // Collect final memory statistics
  size_t heap_end = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
  UBaseType_t stack_end = uxTaskGetStackHighWaterMark(NULL);

  size_t heap_used = heap_start - heap_end;
  size_t stack_used = (stack_start - stack_end) * sizeof(StackType_t);
  size_t stack_available = stack_end * sizeof(StackType_t);

  // Log memory statistics in parseable format
  ESP_LOGI(ANALYSIS,
           "[MEMORY] algorithm=%s | heap_total=%zu | heap_used=%zu | "
           "heap_free=%zu | stack_size=%lu | stack_used=%zu | stack_free=%zu",
           alg_name, heap_total, heap_used, heap_end, stack_size_, stack_used,
           stack_available);

  // Display human-readable statistics table
  uint64_t avg_encaps_time =
      encaps_metrics.iteration_count
          ? encaps_metrics.total_time_us / encaps_metrics.iteration_count
          : 0;
  uint64_t avg_encaps_cycles =
      encaps_metrics.iteration_count
          ? encaps_metrics.total_cycles / encaps_metrics.iteration_count
          : 0;
  uint64_t avg_decaps_time =
      decaps_metrics.iteration_count
          ? decaps_metrics.total_time_us / decaps_metrics.iteration_count
          : 0;
  uint64_t avg_decaps_cycles =
      decaps_metrics.iteration_count
          ? decaps_metrics.total_cycles / decaps_metrics.iteration_count
          : 0;

  ESP_LOGI(TAG, "");
  ESP_LOGI(
      TAG,
      "Performance Statistics Summary (%d iterations, encaps+decaps only):",
      NUM_ITERATIONS);
  ESP_LOGI(TAG, "+------------------+----------+----------+----------+---------"
                "---+------------+------------+");
  ESP_LOGI(TAG, "| Operation        | Avg (us) | Min (us) | Max (us) | Avg "
                "Cycles | Min Cycles | Max Cycles |");
  ESP_LOGI(TAG, "+------------------+----------+----------+----------+---------"
                "---+------------+------------+");
  if (keypair_metrics.iteration_count > 0) {
    uint64_t avg_keypair_time =
        keypair_metrics.total_time_us / keypair_metrics.iteration_count;
    uint64_t avg_keypair_cycles =
        keypair_metrics.total_cycles / keypair_metrics.iteration_count;
    ESP_LOGI(TAG,
             "| Keypair          | %8llu | %8llu | %8llu | %10llu | %10llu | "
             "%10llu |",
             avg_keypair_time, keypair_metrics.min_time_us,
             keypair_metrics.max_time_us, avg_keypair_cycles,
             keypair_metrics.min_cycles, keypair_metrics.max_cycles);
  }
  ESP_LOGI(
      TAG,
      "| Encapsulation    | %8llu | %8llu | %8llu | %10llu | %10llu | %10llu |",
      avg_encaps_time, encaps_metrics.min_time_us, encaps_metrics.max_time_us,
      avg_encaps_cycles, encaps_metrics.min_cycles, encaps_metrics.max_cycles);
  ESP_LOGI(
      TAG,
      "| Decapsulation    | %8llu | %8llu | %8llu | %10llu | %10llu | %10llu |",
      avg_decaps_time, decaps_metrics.min_time_us, decaps_metrics.max_time_us,
      avg_decaps_cycles, decaps_metrics.min_cycles, decaps_metrics.max_cycles);
  ESP_LOGI(TAG, "+------------------+----------+----------+----------+---------"
                "---+------------+------------+");
  ESP_LOGI(TAG, "");
  ESP_LOGI(TAG, "Memory Statistics:");
  ESP_LOGI(TAG, "+------------------+------------------+");
  ESP_LOGI(TAG, "| Metric           | Value            |");
  ESP_LOGI(TAG, "+------------------+------------------+");
  ESP_LOGI(TAG, "| Heap used        | %10zu B     |", heap_used);
  ESP_LOGI(TAG, "| Heap free        | %10zu B     |", heap_end);
  ESP_LOGI(TAG, "| Stack used       | %10zu B     |", stack_used);
  ESP_LOGI(TAG, "| Stack free       | %10zu B     |", stack_available);
  ESP_LOGI(TAG, "+------------------+------------------+");

cleanup:
  // Securely free sensitive data
  if (secret_key) {
    OQS_MEM_secure_free(secret_key, kem->length_secret_key);
  }
  if (shared_secret_e) {
    OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
  }
  if (shared_secret_d) {
    OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
  }

  // Free non-sensitive data
  if (public_key) {
    OQS_MEM_insecure_free(public_key);
  }
  if (ciphertext) {
    OQS_MEM_insecure_free(ciphertext);
  }

  OQS_KEM_free(kem);
  MONITOR_TASK_END(NULL, task_name, stack_size_);
  ESP_LOGI(TAG, "");
}

/**
 * @brief Task that runs KEM tests
 */
static void kem_test_task(void *pvParameters) {

  ESP_LOGI(TAG, "KEM test task created successfully");
  /* No radio here, so enable the ADC entropy source for key generation. */
  bootloader_random_enable();

  ESP_LOGI(TAG, "KEM test task started");
  ESP_LOGI(TAG, "Total KEM algorithms available: %zu", OQS_KEM_alg_count());
  ESP_LOGI(TAG, "");

  /* Primary benchmark (documented in README). Swap or add test_kem("…") calls
   * for any enabled liboqs KEM — see file header comment. */
  if (OQS_KEM_alg_is_enabled("ML-KEM-768")) {
    test_kem("ML-KEM-768");
  } else {
    ESP_LOGW(TAG, "ML-KEM-768 not enabled in build");
    ESP_LOGW(TAG, "Enable via: idf.py menuconfig → Component config → liboqs");
  }

  // if (OQS_KEM_alg_is_enabled("ML-KEM-512")) {
  //   test_kem("ML-KEM-512");
  // }
  // if (OQS_KEM_alg_is_enabled("ML-KEM-1024")) {
  //   test_kem("ML-KEM-1024");
  // }
  // if (OQS_KEM_alg_is_enabled("BIKE-L1")) {
  //   test_kem("BIKE-L1");
  // }
  // if (OQS_KEM_alg_is_enabled("Kyber768")) {
  //   test_kem("Kyber768");
  // }

  bootloader_random_disable();

  ESP_LOGI(TAG, "========================================");
  ESP_LOGI(TAG, "Example complete!");
  ESP_LOGI(TAG, "========================================");

  ESP_LOGI(TAG, "KEM test task completed, deleting task");
  xSemaphoreGive(xSemaphoreSequential);
  vTaskDelete(NULL);
}

void app_main(void) {
  xSemaphoreSequential = xSemaphoreCreateBinary();
  ESP_LOGI(TAG, "========================================");
  ESP_LOGI(TAG, "liboqs KEM Example for ESP-IDF");
  ESP_LOGI(TAG, "========================================");
  ESP_LOGI(TAG, "liboqs version: %s", OQS_version());
  ESP_LOGI(TAG, "Chip: %s", CONFIG_IDF_TARGET);
  ESP_LOGI(TAG, "");

  // Note: If CONFIG_LIBOQS_AUTO_INIT_RNG=y, RNG is already initialized
  // Otherwise, you must call esp_liboqs_rng_init() here

  TaskHandle_t kem_task_handle = NULL;
  BaseType_t result =
      xTaskCreate(kem_test_task, "kem_test", KEM_TEST_TASK_STACK_BYTES, NULL, 5,
                  &kem_task_handle);

  if (result != pdPASS) {
    ESP_LOGE(TAG, "Failed to create KEM test task");
    return;
  }
}
