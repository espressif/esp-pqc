# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# Use custom bootloader linker script from bootloader_extra_dir instead of
# ${IDF_PATH}/components/bootloader/subproject/main/ld/esp32c5/bootloader.ld.in
get_filename_component(_bootloader_ld "${CMAKE_CURRENT_LIST_DIR}/../../bootloader_extra_dir/bootloader.ld.in" ABSOLUTE)
if(EXISTS "${_bootloader_ld}")
    set(CUSTOM_BOOTLOADER_LD_SCRIPT "${_bootloader_ld}" CACHE PATH "Custom bootloader linker script")
endif()
unset(_bootloader_ld)
