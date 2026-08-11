/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include "esp_random.h"
#include "esp_log.h"
#include "esp_err.h"
#include <oqs/oqs.h>

static const char *TAG = "liboqs_rng";

/**
 * @brief Custom RNG callback using ESP-IDF's hardware RNG
 *
 * This function uses esp_fill_random() which provides cryptographically
 * secure random data from the hardware RNG on ESP32.
 *
 * Based on liboqs/zephyr/samples/KEMs/src/main.c:24-28
 *
 * @param random_array  Buffer to fill with random bytes
 * @param bytes_to_read Number of bytes to generate
 */
void esp_liboqs_randombytes(uint8_t *random_array, size_t bytes_to_read)
{
    if (random_array == NULL || bytes_to_read == 0) {
        ESP_LOGE(TAG, "Invalid parameters to RNG callback");
        return;
    }

    // esp_fill_random uses hardware RNG and is cryptographically secure
    esp_fill_random(random_array, bytes_to_read);

#ifdef CONFIG_LIBOQS_VERBOSE_LOGGING
    ESP_LOGD(TAG, "Generated %zu random bytes", bytes_to_read);
#endif
}

/**
 * @brief Initialize liboqs RNG with ESP-IDF hardware RNG
 *
 * Must be called before any liboqs cryptographic operations.
 * If CONFIG_LIBOQS_AUTO_INIT_RNG is enabled, this is called automatically
 * at startup via esp_liboqs_init().
 *
 * @return ESP_OK on success
 */
esp_err_t esp_liboqs_rng_init(void)
{
    ESP_LOGI(TAG, "Initializing liboqs with ESP32 hardware RNG");

    // Register our custom RNG callback with liboqs
    // From liboqs/src/common/rand/rand.c:58-59
    OQS_randombytes_custom_algorithm(&esp_liboqs_randombytes);

    // Test the RNG with a small request to verify it works
    uint8_t test[8];
    OQS_randombytes(test, sizeof(test));

    ESP_LOGI(TAG, "RNG initialized successfully");
    return ESP_OK;
}
