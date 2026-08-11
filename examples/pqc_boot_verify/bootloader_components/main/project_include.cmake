# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# Override the bootloader linker script: ESP-IDF's project() is a macro, so this project_include.cmake runs in the same scope and can override LD_DEFAULT_PATH before project() uses it, pointing at our custom bootloader.ld.in.
set(LD_DEFAULT_PATH "${CMAKE_CURRENT_LIST_DIR}/ld/${IDF_TARGET}")
message(STATUS "PQC: Using custom bootloader linker script from ${LD_DEFAULT_PATH}")

# Register PQC bootloader components in the COMPONENTS whitelist so the subproject builds them (EXTRA_COMPONENT_DIRS only locates them, doesn't include them).
list(APPEND COMPONENTS bootloader_support esp-pqc main my_boot_hooks)
message(STATUS "PQC: Added bootloader components to COMPONENTS list")
