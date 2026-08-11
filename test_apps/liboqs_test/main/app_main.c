/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 *
 * Unity runner for the esp-liboqs test suite. Mirrors the structure of
 * ESP-IDF's components/mbedtls/test_apps so it behaves the same under
 * `idf.py monitor` (interactive menu) and pytest (run_all_single_board_cases).
 */
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "unity.h"
#include "unity_test_runner.h"

/* Per-test heap guard: liboqs (and our heap-backed ML-DSA/ML-KEM temporaries)
 * must not leak or corrupt the heap. setUp records, tearDown checks. */
static size_t s_free_before;

void setUp(void) {
  s_free_before = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
}

void tearDown(void) {
  /* Allow a small slack for lazily-initialized RTOS/driver state. */
  const size_t slack = 1024;
  size_t free_after = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);

  TEST_ASSERT_MESSAGE(heap_caps_check_integrity_all(true),
                      "Heap corrupted during test");

  if (free_after + slack < s_free_before) {
    printf("WARNING: possible leak: before=%u after=%u (delta=%d)\n",
           (unsigned)s_free_before, (unsigned)free_after,
           (int)s_free_before - (int)free_after);
  }
}

/* CI marker: printed once every registered case has run. ci/emu_run.py keys
 * its PASS on this line and its FAIL on Unity's own ":FAIL" / "N Failures". */
#define LIBOQS_TEST_DONE_MARKER "esp-liboqs Unity test suite: DONE"

static void test_task(void *pvParameters) {
  (void)pvParameters;
  vTaskDelay(2); /* let the main task be deleted first */
#if CONFIG_LIBOQS_TEST_RUN_ALL_ON_BOOT
  /* Non-interactive: run every case once (UNITY_BEGIN/END inside), then emit
   * the completion marker for the emulator harness. */
  unity_run_all_tests();
  printf("\n%s\n", LIBOQS_TEST_DONE_MARKER);
  vTaskDelete(NULL);
#else
  unity_run_menu(); /* interactive menu for idf.py monitor / pytest */
#endif
}

void app_main(void) {
  printf("\n\nesp-liboqs Unity test suite\n");
  xTaskCreatePinnedToCore(test_task, "testTask",
                          CONFIG_LIBOQS_TEST_TASK_STACK_SIZE, NULL, 5, NULL,
                          tskNO_AFFINITY);
}
