# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
idf_component_register(SRCS "kem_basic.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES esp_timer bootloader_support
                    REQUIRES esp-pqc)
