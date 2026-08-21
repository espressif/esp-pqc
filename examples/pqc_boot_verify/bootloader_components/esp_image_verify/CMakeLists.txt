# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# esp-pqc's PQC-modified image verifier. Overrides the default ESP-IDF esp_image_verify where that component exists, and is an extra bootloader component where it does not.

idf_build_get_property(target IDF_TARGET)

if(${target} STREQUAL "linux")
    idf_component_register()
    return()
endif()

include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/pqc_idf_layout.cmake")

# src/esp_image_format.c is our fork; the rest is taken from IDF.
set(srcs
    "src/esp_image_format.c"
    "${PQC_IDF_IV}/src/bootloader_sha.c"
)

# Only a separate translation unit on IDF that has the split.
if(PQC_HAS_ESP_IMAGE_VERIFY)
    list(APPEND srcs "${PQC_IDF_IV}/src/bootloader_sha_flash.c")
endif()

if(CONFIG_SECURE_SIGNED_ON_BOOT)
    if(CONFIG_SECURE_SIGNED_APPS_ECDSA_SCHEME)
        list(APPEND srcs
            "${PQC_IDF_IV}/src/secure_boot_v1/secure_boot_signatures_bootloader.c")
    endif()
    if(CONFIG_SECURE_BOOT_V1_ENABLED)
        list(APPEND srcs "${PQC_IDF_IV}/src/secure_boot_v1/secure_boot.c")
    endif()
    if(CONFIG_SECURE_BOOT_V2_ENABLED)
        list(APPEND srcs
            "${PQC_IDF_IV}/src/secure_boot_v2/secure_boot_signatures_bootloader.c"
            "${PQC_IDF_IV}/src/secure_boot_v2/secure_boot.c")
    endif()
endif()

if(CONFIG_PQC_SECURE_BOOT_ENABLED)
    list(APPEND srcs
        "src/pqc_bootloader_verify.c"
        "src/pqc_stack.S")
endif()

# Both dirs are listed because our esp_image_format.c includes private headers from each.
set(priv_include_dirs
    "${PQC_IDF_IV}/private_include"
    "${PQC_IDF_BS}/private_include"
)

set(requires bootloader_support)

set(priv_requires "")
pqc_require_if_present(priv_requires
    spi_flash efuse esptool_py esp_app_format esp_bootloader_format
    micro-ecc esp_hal_security)

if(CONFIG_PQC_SECURE_BOOT_ENABLED)
    list(APPEND priv_requires esp-pqc)
endif()

idf_component_register(
    SRCS              "${srcs}"
    INCLUDE_DIRS      "include"
    PRIV_INCLUDE_DIRS "${priv_include_dirs}"
    REQUIRES          "${requires}"
    PRIV_REQUIRES     "${priv_requires}"
)

if(CONFIG_PQC_SECURE_BOOT_ENABLED)
    idf_component_get_property(liboqs_lib esp-pqc COMPONENT_LIB)
    target_include_directories(${COMPONENT_LIB} PRIVATE
        $<TARGET_PROPERTY:${liboqs_lib},INTERFACE_INCLUDE_DIRECTORIES>)

    target_link_options(${COMPONENT_LIB} INTERFACE
        "LINKER:--undefined=OQS_SIG_ml_dsa_65_new")

    target_sources(${COMPONENT_LIB} PRIVATE
        "${IDF_PATH}/components/heap/tlsf/tlsf.c")
    set_source_files_properties("${IDF_PATH}/components/heap/tlsf/tlsf.c"
        PROPERTIES COMPILE_DEFINITIONS "printf=esp_rom_printf")
    target_include_directories(${COMPONENT_LIB} PRIVATE
        "${IDF_PATH}/components/heap/tlsf"
        "${IDF_PATH}/components/heap/tlsf/include")
endif()

# Linker script placement depends on object file names, which LTO does not preserve.
idf_component_set_property(${COMPONENT_NAME} NO_LTO 1)
