/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include <oqs/oqs.h>

static const char *TAG = "liboqs";

// Forward declaration from esp_rand_adapter.c
extern esp_err_t esp_liboqs_rng_init(void);

#ifdef CONFIG_LIBOQS_ENABLE_PROFILING
#include "esp_liboqs_profile.h"
#endif

/**
 * @brief Auto-initialize liboqs at startup
 *
 * Called automatically before app_main() if CONFIG_LIBOQS_AUTO_INIT_RNG is enabled.
 * Uses constructor attribute to run before main().
 *
 * This function:
 * 1. Initializes liboqs via OQS_init()
 * 2. Sets up the hardware RNG callback
 * 3. Logs enabled algorithms
 * 4. Checks available heap
 */
void esp_liboqs_init(void) __attribute__((constructor));

void esp_liboqs_init(void)
{
#ifdef CONFIG_LIBOQS_ENABLED
#ifdef CONFIG_LIBOQS_AUTO_INIT_RNG
    ESP_LOGI(TAG, "liboqs v%s initializing...", OQS_version());

    // Initialize OQS
    OQS_init();

    // Set up RNG callback
    if (esp_liboqs_rng_init() != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize RNG");
        return;
    }

#ifdef CONFIG_LIBOQS_ENABLE_PROFILING
#ifdef CONFIG_LIBOQS_PROFILE_AUTO_INIT
    // Initialize profiling system
    esp_liboqs_profile_init();
    ESP_LOGI(TAG, "Profiling system initialized");
#endif
#endif

    // Log enabled algorithms
    ESP_LOGI(TAG, "Enabled KEMs: %zu, Signatures: %zu",
             OQS_KEM_alg_count(), OQS_SIG_alg_count());

#ifdef CONFIG_LIBOQS_VERBOSE_LOGGING
    // Log specific enabled algorithms
    ESP_LOGI(TAG, "Available KEM algorithms:");
    for (size_t i = 0; i < OQS_KEM_alg_count(); i++) {
        const char *alg_name = OQS_KEM_alg_identifier(i);
        if (OQS_KEM_alg_is_enabled(alg_name)) {
            ESP_LOGI(TAG, "  - %s", alg_name);
        }
    }

    ESP_LOGI(TAG, "Available Signature algorithms:");
    for (size_t i = 0; i < OQS_SIG_alg_count(); i++) {
        const char *alg_name = OQS_SIG_alg_identifier(i);
        if (OQS_SIG_alg_is_enabled(alg_name)) {
            ESP_LOGI(TAG, "  - %s", alg_name);
        }
    }
#endif

    // Check available heap
    uint32_t free_heap = esp_get_free_heap_size();
    ESP_LOGI(TAG, "Free heap after init: %lu bytes (%.1f KB)",
             free_heap, free_heap / 1024.0);

#ifdef CONFIG_LIBOQS_HEAP_SIZE_WARNING_KB
    if (free_heap < (CONFIG_LIBOQS_HEAP_SIZE_WARNING_KB * 1024)) {
        ESP_LOGW(TAG, "Low heap warning: only %lu bytes (%.1f KB) remaining",
                 free_heap, free_heap / 1024.0);
        ESP_LOGW(TAG, "Threshold: %d KB", CONFIG_LIBOQS_HEAP_SIZE_WARNING_KB);
    }
#endif

    ESP_LOGI(TAG, "Initialization complete");

#endif // CONFIG_LIBOQS_AUTO_INIT_RNG
#endif // CONFIG_LIBOQS_ENABLED
}

void esp_liboqs_init_include_impl(void)
{
    // Linker hook, exists for no other purpose
}
