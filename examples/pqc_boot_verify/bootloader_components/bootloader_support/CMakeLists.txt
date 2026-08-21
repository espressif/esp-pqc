# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# esp-pqc's override of the default ESP-IDF bootloader_support. Carries no local sources: it compiles the default ESP-IDF bootloader_support without the image-verification files, which esp-pqc's esp_image_verify owns instead.

idf_build_get_property(target IDF_TARGET)
idf_build_get_property(esp_tee_build ESP_TEE_BUILD)

if(${target} STREQUAL "linux")
    return()
endif()

include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/pqc_idf_layout.cmake")
set(IDF_BS "${PQC_IDF_BS}")

if(esp_tee_build)
    set(tee_inc_dirs "${IDF_BS}/include"
                     "${IDF_BS}/private_include"
                     "${IDF_BS}/bootloader_flash/include")

    set(tee_srcs "${IDF_BS}/src/flash_partitions.c"
                 "${IDF_BS}/src/bootloader_common_loader.c"
                 "${IDF_BS}/src/bootloader_utility.c"
                 "${IDF_BS}/src/bootloader_utility_tee.c"
                 "${IDF_BS}/bootloader_flash/src/bootloader_flash.c")

    if(CONFIG_SECURE_BOOT_V2_ENABLED)
        if(CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME OR CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME)
            list(APPEND tee_srcs "${IDF_BS}/src/${IDF_TARGET}/secure_boot_secure_features.c")
        endif()
    endif()

    set(tee_priv_requires esp_image_verify)
    pqc_require_if_present(tee_priv_requires efuse esp_app_format esptool_py esp_hal_security)

    idf_component_register(SRCS ${tee_srcs}
                           INCLUDE_DIRS ${tee_inc_dirs}
                           PRIV_REQUIRES ${tee_priv_requires})
    return()
endif()

# ── Base sources (always compiled) ──────────────────────────────────────────
set(srcs
    "${IDF_BS}/src/bootloader_common.c"
    "${IDF_BS}/src/bootloader_common_loader.c"
    "${IDF_BS}/src/bootloader_clock_init.c"
    "${IDF_BS}/src/bootloader_mem.c"
    "${IDF_BS}/src/bootloader_random.c"
    "${IDF_BS}/src/bootloader_efuse.c"
    "${IDF_BS}/src/flash_encrypt.c"
    "${IDF_BS}/src/secure_boot.c"
)

if(NOT CONFIG_ESP_BRINGUP_BYPASS_RANDOM_SETTING)
    list(APPEND srcs "${IDF_BS}/src/bootloader_random_${IDF_TARGET}.c")
endif()

if(NOT CONFIG_APP_BUILD_TYPE_PURE_RAM_APP)
    list(APPEND srcs
        "${IDF_BS}/bootloader_flash/src/bootloader_flash.c"
        "${IDF_BS}/bootloader_flash/src/flash_qio_mode.c"
        "${IDF_BS}/bootloader_flash/src/bootloader_flash_config_${IDF_TARGET}.c")
endif()

# esp_image_format.c is omitted here; esp-pqc's esp_image_verify compiles our fork.
if(CONFIG_APP_BUILD_TYPE_APP_2NDBOOT)
    list(APPEND srcs
        "${IDF_BS}/src/bootloader_utility.c"
        "${IDF_BS}/src/flash_partitions.c")
endif()

if(CONFIG_ESP_ROM_REV0_HAS_NO_ECDSA_INTERFACE)
    list(APPEND srcs "${IDF_BS}/src/${IDF_TARGET}/bootloader_ecdsa.c")
endif()

if(BOOTLOADER_BUILD OR CONFIG_APP_BUILD_TYPE_RAM)
    set(priv_include_dirs)
    set(include_dirs "${IDF_BS}/include" "${IDF_BS}/bootloader_flash/include"
                     "${IDF_BS}/private_include")
    set(priv_requires "")
    pqc_require_if_present(priv_requires spi_flash efuse esp_bootloader_format esp_app_format esptool_py)
    # micro-ecc lives in the bootloader subproject, so it is bootloader-build only.
    if(BOOTLOADER_BUILD)
        list(APPEND priv_requires esp_image_verify)
        pqc_require_if_present(priv_requires micro-ecc)
    endif()
    pqc_require_if_present(priv_requires esp_hal_wdt esp_hal_gpio esp_hal_uart esp_hal_ana_conv
                           esp_hal_rtc_timer esp_hal_clock esp_hal_security esp_hal_debug_assist)
    # Present from IDF v6.1 onwards.
    if(EXISTS "${IDF_BS}/src/bootloader_reset_common.c")
        list(APPEND srcs "${IDF_BS}/src/bootloader_reset_common.c")
    endif()
    list(APPEND srcs
        "${IDF_BS}/src/bootloader_init.c"
        "${IDF_BS}/src/bootloader_clock_loader.c"
        "${IDF_BS}/src/bootloader_console.c"
        "${IDF_BS}/src/bootloader_console_loader.c"
        "${IDF_BS}/src/${IDF_TARGET}/bootloader_soc.c"
        "${IDF_BS}/src/${IDF_TARGET}/bootloader_${IDF_TARGET}.c"
    )
    if(CONFIG_SECURE_ENABLE_TEE)
        list(APPEND srcs "${IDF_BS}/src/bootloader_utility_tee.c")
    endif()
else()
    set(include_dirs "${IDF_BS}/include" "${IDF_BS}/bootloader_flash/include")
    set(priv_include_dirs "${IDF_BS}/private_include")
    set(priv_requires "")
    # heap is required for `heap_memory_layout.h`.
    pqc_require_if_present(priv_requires spi_flash efuse heap esp_bootloader_format esp_app_format esptool_py)
    if(NOT PQC_HAS_ESP_IMAGE_VERIFY)
        pqc_require_if_present(priv_requires mbedtls)
    endif()
    pqc_require_if_present(priv_requires esp_hal_wdt esp_hal_gpio esp_hal_uart esp_hal_ana_conv
                           esp_hal_rtc_timer esp_hal_clock esp_hal_security esp_hal_debug_assist)
endif()

# Needed by flash_encrypt.c on SOC_KEY_MANAGER_SUPPORTED targets, which is always in srcs.
pqc_require_if_present(priv_requires esp_security)

if(BOOTLOADER_BUILD)
    list(APPEND srcs "${IDF_BS}/src/bootloader_panic.c")

    if(CONFIG_SECURE_FLASH_ENC_ENABLED)
        list(APPEND srcs
            "${IDF_BS}/src/flash_encryption/flash_encrypt.c"
            "${IDF_BS}/src/${IDF_TARGET}/flash_encryption_secure_features.c")
    endif()

    # The secure_boot_v{1,2} sources belong to esp-pqc's esp_image_verify.
    if(CONFIG_SECURE_SIGNED_ON_BOOT)
        if(CONFIG_SECURE_BOOT_V1_ENABLED OR CONFIG_SECURE_BOOT_V2_ENABLED)
            list(APPEND srcs "${IDF_BS}/src/${IDF_TARGET}/secure_boot_secure_features.c")
        endif()
    endif()
else()
    if(CONFIG_SOC_SECURE_BOOT_SUPPORTED)
        list(APPEND srcs "${IDF_BS}/src/${IDF_TARGET}/secure_boot_secure_features.c")
    endif()
endif()

set(requires soc)

idf_component_register(
    SRCS            "${srcs}"
    INCLUDE_DIRS    "${include_dirs}"
    PRIV_INCLUDE_DIRS "${priv_include_dirs}"
    REQUIRES        "${requires}"
    PRIV_REQUIRES   "${priv_requires}"
)

# Command only exists from IDF v6.2.
if(COMMAND idf_define_esp_err_codes)
    idf_define_esp_err_codes(HEADERS "${IDF_BS}/include/esp_image_format.h")
endif()

if(CONFIG_SECURE_SIGNED_APPS AND
   (CONFIG_SECURE_BOOT_V1_ENABLED OR CONFIG_SECURE_SIGNED_APPS_ECDSA_SCHEME))
    idf_component_get_property(espsecure_py_cmd esptool_py ESPSECUREPY_CMD)
    if(BOOTLOADER_BUILD)
        if(CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES)
            get_filename_component(secure_boot_signing_key
                "${SECURE_BOOT_SIGNING_KEY}" ABSOLUTE BASE_DIR "${project_dir}")
            get_filename_component(secure_boot_verification_key
                "signature_verification_key.bin" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_BINARY_DIR}")
            add_custom_command(OUTPUT "${secure_boot_verification_key}"
                COMMAND ${espsecure_py_cmd}
                    extract-public-key --keyfile "${secure_boot_signing_key}"
                    "${secure_boot_verification_key}"
                DEPENDS ${secure_boot_signing_key}
                VERBATIM)
        else()
            get_filename_component(secure_boot_verification_key
                ${SECURE_BOOT_VERIFICATION_KEY} ABSOLUTE BASE_DIR "${project_dir}")
        endif()
    else()
        idf_build_get_property(project_dir PROJECT_DIR)
        if(CONFIG_SECURE_BOOT_VERIFICATION_KEY)
            set(secure_boot_verification_key ${CONFIG_SECURE_BOOT_VERIFICATION_KEY})
            get_filename_component(secure_boot_verification_key
                ${secure_boot_verification_key} ABSOLUTE BASE_DIR "${project_dir}")
        else()
            set(secure_boot_verification_key "${CMAKE_BINARY_DIR}/signature_verification_key.bin")
            get_filename_component(secure_boot_signing_key
                ${CONFIG_SECURE_BOOT_SIGNING_KEY} ABSOLUTE BASE_DIR "${project_dir}")
            add_custom_command(OUTPUT "${secure_boot_verification_key}"
                COMMAND ${espsecure_py_cmd}
                    extract-public-key --keyfile "${secure_boot_signing_key}"
                    "${secure_boot_verification_key}"
                WORKING_DIRECTORY ${project_dir}
                DEPENDS ${secure_boot_signing_key}
                VERBATIM)
        endif()
    endif()

    target_add_binary_data(${COMPONENT_LIB} "${secure_boot_verification_key}" "BINARY"
        RENAME_TO signature_verification_key_bin)
    set_property(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        APPEND PROPERTY ADDITIONAL_CLEAN_FILES "${secure_boot_verification_key}")
endif()

if(BOOTLOADER_BUILD)
    target_link_libraries(${COMPONENT_LIB} INTERFACE "-u abort")
    target_link_libraries(${COMPONENT_LIB} INTERFACE "-u esp_bootloader_desc")
endif()

# Linker script placement depends on object file names, which LTO does not preserve.
idf_component_set_property(${COMPONENT_NAME} NO_LTO 1)
