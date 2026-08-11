/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize liboqs RNG with ESP-IDF hardware RNG
 *
 * This function registers ESP-IDF's hardware RNG (esp_fill_random) as the
 * random number generator for liboqs.
 *
 * @note If CONFIG_LIBOQS_AUTO_INIT_RNG is enabled, this is called automatically
 *       at startup and you don't need to call it manually.
 *
 * @return ESP_OK on success
 */
esp_err_t esp_liboqs_rng_init(void);

/**
 * @brief Custom RNG callback for liboqs using ESP32 hardware RNG
 *
 * This is the callback function registered with liboqs. It uses esp_fill_random()
 * to generate cryptographically secure random numbers.
 *
 * @param random_array Buffer to fill with random bytes
 * @param bytes_to_read Number of random bytes to generate
 */
void esp_liboqs_randombytes(uint8_t *random_array, size_t bytes_to_read);

#ifdef __cplusplus
}
#endif
