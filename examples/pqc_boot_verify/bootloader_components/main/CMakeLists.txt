# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# Override the default ESP-IDF bootloader main component to use our custom linker script.
# bootloader_start.c is referenced from IDF — no local copy needed.

set(IDF_BOOT_MAIN "${IDF_PATH}/components/bootloader/subproject/main")

idf_component_register(SRCS "${IDF_BOOT_MAIN}/bootloader_start.c"
                    REQUIRES bootloader bootloader_support)

# The custom linker script is applied via project_include.cmake which
# overrides LD_DEFAULT_PATH. The BOOTLOADER_LINKER_SCRIPT property
# from IDF is not set, so we skip that here.

target_link_libraries(${COMPONENT_LIB} INTERFACE "-u bootloader_hooks_include")
