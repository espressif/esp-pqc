# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# Shadow component: overrides IDF's bootloader_support to inject PQC verification.

idf_build_get_property(target IDF_TARGET)
idf_build_get_property(esp_tee_build ESP_TEE_BUILD)

set(IDF_BS "${IDF_PATH}/components/bootloader_support")

if(${target} STREQUAL "linux")
    return()
endif()

if(esp_tee_build)
    set(tee_inc_dirs "${IDF_BS}/include"
                     "${IDF_BS}/private_include"
                     "${IDF_BS}/bootloader_flash/include")

    set(tee_srcs "${IDF_BS}/src/flash_partitions.c"
                 "${IDF_BS}/src/bootloader_sha.c"
                 "${IDF_BS}/src/bootloader_common_loader.c"
                 "src/esp_image_format.c"
                 "${IDF_BS}/src/bootloader_utility.c"
                 "${IDF_BS}/src/bootloader_utility_tee.c"
                 "${IDF_BS}/bootloader_flash/src/bootloader_flash.c")

    if(CONFIG_SECURE_BOOT_V2_ENABLED)
        if(CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME OR CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME)
            list(APPEND tee_srcs
                "${IDF_BS}/src/secure_boot_v2/secure_boot_signatures_bootloader.c"
                "${IDF_BS}/src/secure_boot_v2/secure_boot.c"
                "${IDF_BS}/src/${IDF_TARGET}/secure_boot_secure_features.c")
        endif()
    endif()

    idf_component_register(SRCS ${tee_srcs}
                           INCLUDE_DIRS ${tee_inc_dirs}
                           PRIV_REQUIRES efuse esp_app_format esptool_py esp_hal_security)
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

if(CONFIG_APP_BUILD_TYPE_APP_2NDBOOT)
    list(APPEND srcs
        "${IDF_BS}/src/bootloader_utility.c"
        "${IDF_BS}/src/flash_partitions.c"
        "src/esp_image_format.c"       # ← local modified version (PQC + ECDSA)
    )
endif()

list(APPEND srcs "${IDF_BS}/src/bootloader_sha.c")

if(CONFIG_ESP_ROM_REV0_HAS_NO_ECDSA_INTERFACE)
    list(APPEND srcs "${IDF_BS}/src/${IDF_TARGET}/bootloader_ecdsa.c")
endif()

if(BOOTLOADER_BUILD OR CONFIG_APP_BUILD_TYPE_RAM)
    set(include_dirs "${IDF_BS}/include" "${IDF_BS}/bootloader_flash/include"
                     "${IDF_BS}/private_include")
    set(priv_requires micro-ecc spi_flash efuse esp_bootloader_format esp_app_format esptool_py)
    list(APPEND priv_requires esp_hal_wdt esp_hal_gpio esp_hal_uart esp_hal_ana_conv
         esp_hal_rtc_timer esp_hal_clock esp_hal_security)
    # bootloader_reset_common.c (bootloader_check_reset) only exists from IDF 6.2, and
    # only that IDF's bootloader_start.c calls it, so gate it on the file being there.
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
    set(priv_requires spi_flash mbedtls efuse heap esp_bootloader_format esp_app_format esptool_py)
    list(APPEND priv_requires esp_hal_wdt esp_hal_gpio esp_hal_uart esp_hal_ana_conv
         esp_hal_rtc_timer esp_hal_clock esp_hal_security)
endif()

if(BOOTLOADER_BUILD)
    list(APPEND srcs "${IDF_BS}/src/bootloader_panic.c")
    list(APPEND priv_requires esp_security)

    if(CONFIG_SECURE_FLASH_ENC_ENABLED)
        list(APPEND srcs
            "${IDF_BS}/src/flash_encryption/flash_encrypt.c"
            "${IDF_BS}/src/${IDF_TARGET}/flash_encryption_secure_features.c")
    endif()

    if(CONFIG_SECURE_SIGNED_ON_BOOT)
        if(CONFIG_SECURE_SIGNED_APPS_ECDSA_SCHEME)
            list(APPEND srcs
                "${IDF_BS}/src/secure_boot_v1/secure_boot_signatures_bootloader.c")
        endif()
        if(CONFIG_SECURE_BOOT_V1_ENABLED)
            list(APPEND srcs
                "${IDF_BS}/src/secure_boot_v1/secure_boot.c"
                "${IDF_BS}/src/${IDF_TARGET}/secure_boot_secure_features.c")
        endif()
        if(CONFIG_SECURE_BOOT_V2_ENABLED)
            list(APPEND srcs
                "${IDF_BS}/src/secure_boot_v2/secure_boot_signatures_bootloader.c"
                "${IDF_BS}/src/secure_boot_v2/secure_boot.c"
                "${IDF_BS}/src/${IDF_TARGET}/secure_boot_secure_features.c")
        endif()
    endif()

    # ── PQC verification sources (only in bootloader build) ─────────────────
    if(CONFIG_PQC_SECURE_BOOT_ENABLED)
        list(APPEND srcs
            "src/pqc_bootloader_verify.c"
            "src/pqc_stack.S")
        list(APPEND priv_requires esp-pqc)
    endif()

else()
    if(CONFIG_SOC_SECURE_BOOT_SUPPORTED)
        list(APPEND srcs "${IDF_BS}/src/${IDF_TARGET}/secure_boot_secure_features.c")
    endif()

    if(CONFIG_SECURE_SIGNED_ON_UPDATE)
        if(CONFIG_SECURE_SIGNED_APPS_ECDSA_SCHEME)
            list(APPEND srcs "${IDF_BS}/src/secure_boot_v1/secure_boot_signatures_app.c")
        endif()
        if(CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME)
            list(APPEND srcs
                "${IDF_BS}/src/secure_boot_v2/secure_boot_signatures_app.c"
                "${IDF_BS}/src/secure_boot_v2/secure_boot_rsa_signature.c")
        endif()
        if(CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME)
            list(APPEND srcs
                "${IDF_BS}/src/secure_boot_v2/secure_boot_signatures_app.c"
                "${IDF_BS}/src/secure_boot_v2/secure_boot_ecdsa_signature.c")
        endif()
    endif()
endif()

set(requires soc)

if(CONFIG_PQC_SECURE_BOOT_ENABLED AND BOOTLOADER_BUILD)
    list(APPEND priv_requires esp-pqc)
endif()

idf_component_register(
    SRCS            "${srcs}"
    INCLUDE_DIRS    "${include_dirs}"
    PRIV_INCLUDE_DIRS "${priv_include_dirs}"
    REQUIRES        "${requires}"
    PRIV_REQUIRES   "${priv_requires}"
)


# ── PQC header search path (only needed when PQC is enabled) ────────────────
if(CONFIG_PQC_SECURE_BOOT_ENABLED AND BOOTLOADER_BUILD)
    target_include_directories(${COMPONENT_LIB} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include")

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

if(NOT BOOTLOADER_BUILD)
    if(CONFIG_SECURE_SIGNED_ON_UPDATE)
        if(CONFIG_SECURE_SIGNED_APPS_ECDSA_SCHEME OR CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME OR
           CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME)
            target_link_libraries(${COMPONENT_LIB} PRIVATE idf::app_update)
        endif()
    endif()
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
