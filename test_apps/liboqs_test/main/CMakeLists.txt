# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
idf_component_register(
    SRCS "app_main.c"
         "test_liboqs_kem.c"
         "test_liboqs_sig.c"
         "test_liboqs_rng.c"
         "test_liboqs_mem.c"
    PRIV_INCLUDE_DIRS "."
    PRIV_REQUIRES esp-pqc unity esp_timer
    WHOLE_ARCHIVE)
