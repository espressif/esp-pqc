# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# Resolves IDF paths and dependencies that differ between IDF versions. Included from each esp-pqc bootloader component.

set(PQC_IDF_VER "${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}.${IDF_VERSION_PATCH}")
set(PQC_IDF_BS  "${IDF_PATH}/components/bootloader_support")

# Locate the component that owns bootloader_sha.c, esp_image_format.c and secure_boot_v{1,2}/ on this IDF.
if(PQC_IDF_VER VERSION_GREATER_EQUAL "6.2.0"
   AND EXISTS "${IDF_PATH}/components/esp_image_verify/src/bootloader_sha.c")
    set(PQC_HAS_ESP_IMAGE_VERIFY 1)
    set(PQC_IDF_IV "${IDF_PATH}/components/esp_image_verify")
else()
    set(PQC_HAS_ESP_IMAGE_VERIFY 0)
    set(PQC_IDF_IV "${PQC_IDF_BS}")
endif()

# Appends each IDF component to <list-var>, skipping any this IDF does not ship.
function(pqc_require_if_present list_var)
    set(_out "${${list_var}}")
    foreach(_comp IN LISTS ARGN)
        if(EXISTS "${IDF_PATH}/components/${_comp}/CMakeLists.txt"
           OR EXISTS "${IDF_PATH}/components/bootloader/subproject/components/${_comp}/CMakeLists.txt")
            list(APPEND _out "${_comp}")
        else()
            message(STATUS "PQC: skipping absent IDF component '${_comp}' (IDF ${PQC_IDF_VER})")
        endif()
    endforeach()
    set(${list_var} "${_out}" PARENT_SCOPE)
endfunction()

message(STATUS "PQC: IDF ${PQC_IDF_VER}, esp_image_verify_split=${PQC_HAS_ESP_IMAGE_VERIFY}, image-verify sources from ${PQC_IDF_IV}")
