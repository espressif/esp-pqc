/* SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 * SPDX-License-Identifier: Apache-2.0 */

#ifndef PQC_BOOTLOADER_VERIFY_H
#define PQC_BOOTLOADER_VERIFY_H

#include "esp_err.h"
#include "pqc_sig_block.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Verify ML-DSA-65 PQC block; digest = SHA-256([image_start, pqc_block)). */
esp_err_t pqc_bootloader_verify(uint32_t pqc_block_flash_addr,
                                uint32_t image_start_addr);

#ifdef __cplusplus
}
#endif

#endif /* PQC_BOOTLOADER_VERIFY_H */
