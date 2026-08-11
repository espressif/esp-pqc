# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
#
# esp-pqc is the PQC component: it builds liboqs directly from components/liboqs (submodule + ESP-IDF ports) so consumers only need "REQUIRES esp-pqc", and ships the hybrid-PQC mbedTLS override via its manifest (CONFIG_MBEDTLS_USE_BUNDLED_PQC picks bundled vs default).
# Every option this component owns — CONFIG_LIBOQS_* and the esp-pqc CONFIG_MBEDTLS_* — is defined in the root Kconfig; components/mbedtls/Kconfig only re-exposes the default IDF mbedTLS options.
# The same component serves the bootloader: when IDF sets BOOTLOADER_BUILD (a project pulls esp-pqc in via BOOTLOADER_EXTRA_COMPONENT_DIRS) we register the minimal verify-only liboqs and return, skipping the full app-side build below.
if(BOOTLOADER_BUILD)
    include("${CMAKE_CURRENT_LIST_DIR}/components/liboqs/cmake/bootloader_liboqs.cmake")
    return()
endif()

set(LIBOQS_DIR "${CMAKE_CURRENT_LIST_DIR}/components/liboqs")

# With CONFIG_LIBOQS_ENABLED=n the component registers empty so projects can keep esp-pqc in REQUIRES while building a liboqs-free configuration.
if(CONFIG_LIBOQS_ENABLED)
    set(ESP_LIBOQS_SRCS "${LIBOQS_DIR}/ports/esp_rand_adapter.c"
                        "${LIBOQS_DIR}/ports/esp_liboqs_init.c")
else()
    set(ESP_LIBOQS_SRCS "")
endif()

idf_component_register(
    SRCS ${ESP_LIBOQS_SRCS}
    INCLUDE_DIRS "components/liboqs/include"
    REQUIRES esp_hw_support esp_timer mbedtls
    PRIV_REQUIRES esp_system
)

if(CONFIG_LIBOQS_ENABLED)
    target_link_libraries(${COMPONENT_LIB} PRIVATE "-u esp_liboqs_init_include_impl")
endif()

# Only build liboqs if enabled in Kconfig
if(CONFIG_LIBOQS_ENABLED)

    message(STATUS "liboqs: Enabled for ${IDF_TARGET}")

    # ESP-IDF liboqs config + Kconfig algorithm selection (no _OQS_OPT_FORCE -> "set if not already cached").
    include("${LIBOQS_DIR}/cmake/oqs_kconfig_options.cmake")

    # ML-DSA/ML-KEM heap-backed temporaries: forward Kconfig choices via cache as a DEFINED OFF (an unset bool is undefined, which the liboqs if(DEFINED ... AND NOT ...) checks would miss).
    if(DEFINED CONFIG_LIBOQS_MLD_HEAP_TEMPORARIES AND NOT CONFIG_LIBOQS_MLD_HEAP_TEMPORARIES)
        set(CONFIG_LIBOQS_MLD_HEAP_TEMPORARIES OFF CACHE BOOL "From Kconfig" FORCE)
    else()
        set(CONFIG_LIBOQS_MLD_HEAP_TEMPORARIES ON CACHE BOOL "From Kconfig" FORCE)
    endif()

    if(DEFINED CONFIG_LIBOQS_MLK_HEAP_TEMPORARIES AND NOT CONFIG_LIBOQS_MLK_HEAP_TEMPORARIES)
        set(CONFIG_LIBOQS_MLK_HEAP_TEMPORARIES OFF CACHE BOOL "From Kconfig" FORCE)
    else()
        set(CONFIG_LIBOQS_MLK_HEAP_TEMPORARIES ON CACHE BOOL "From Kconfig" FORCE)
    endif()

    # Override install() and export() commands to prevent liboqs from trying to install
    macro(install)
    endmacro()

    macro(export)
    endmacro()

    # Make ESP32 headers available to all liboqs sub-targets. The ports dir carries
    # fips202_kyber.h and the FIPS-202 glue headers that the ML-KEM-768 / ML-DSA-65
    # custom-header hooks resolve by name; it stays out of the component's public
    # INCLUDE_DIRS so applications do not inherit those generic Keccak names.
    include_directories("${LIBOQS_DIR}/include" "${LIBOQS_DIR}/ports")

    # Disable position independent code for ALL liboqs targets recursively
    function(disable_pic_for_all_targets dir)
        get_directory_property(subdirs DIRECTORY ${dir} SUBDIRECTORIES)
        foreach(subdir ${subdirs})
            disable_pic_for_all_targets(${subdir})
        endforeach()

        get_directory_property(targets DIRECTORY ${dir} BUILDSYSTEM_TARGETS)
        foreach(target ${targets})
            if(TARGET ${target})
                get_target_property(target_type ${target} TYPE)
                if(NOT target_type STREQUAL "UTILITY")
                    set_target_properties(${target} PROPERTIES POSITION_INDEPENDENT_CODE OFF)
                    target_compile_options(${target} PRIVATE -fno-pic)
                endif()
            endif()
        endforeach()
    endfunction()

    if(NOT EXISTS "${LIBOQS_DIR}/liboqs/CMakeLists.txt")
        message(FATAL_ERROR "liboqs submodule not found at "
            "${LIBOQS_DIR}/liboqs — run "
            "'git submodule update --init --recursive'.")
    endif()
    add_subdirectory("${LIBOQS_DIR}/liboqs" liboqs_build EXCLUDE_FROM_ALL)
    disable_pic_for_all_targets("${LIBOQS_DIR}/liboqs")

    # Restore install() and export() commands
    macro(install)
        _install(${ARGV})
    endmacro()

    macro(export)
        _export(${ARGV})
    endmacro()

    # Add liboqs include directory to the component
    target_include_directories(${COMPONENT_LIB} PUBLIC
        "${CMAKE_CURRENT_BINARY_DIR}/liboqs_build/include"
    )

    # Link liboqs to the component
    target_link_libraries(${COMPONENT_LIB} PUBLIC oqs)

    # Make liboqs build before this component
    add_dependencies(${COMPONENT_LIB} oqs)


    if(CONFIG_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768 OR
       CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65)

        if(NOT TARGET mbedtls)
            message(FATAL_ERROR
                "liboqs: hybrid PQC TLS is enabled but the mbedTLS library "
                "targets do not exist yet. The application must list 'mbedtls' "
                "before 'esp-pqc' in its REQUIRES so mbedtls is processed first "
                "(and the mbedtls override must build the bundled PQC tree: "
                "CONFIG_MBEDTLS_USE_BUNDLED_PQC=y).")
        endif()

        # liboqs public headers (oqs/oqs.h), produced by this component's build.
        set(_oqs_inc "${CMAKE_CURRENT_BINARY_DIR}/liboqs_build/include")

        # Feature macros gating the mbedTLS PQC sources (each CONFIG symbol maps to the mbedTLS macro of the same name).
        set(_pqc_defs "")
        if(CONFIG_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768)
            list(APPEND _pqc_defs MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768)
        endif()
        if(CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65)
            list(APPEND _pqc_defs MBEDTLS_SSL_TLS1_3_SIG_MLDSA65)
        endif()

        foreach(_t mbedtls tfpsacrypto mbedx509 builtin extras)
            if(TARGET ${_t})
                target_include_directories(${_t} PRIVATE "${_oqs_inc}")
                target_compile_definitions(${_t} PUBLIC ${_pqc_defs})
            endif()
        endforeach()

        message(STATUS "liboqs: Hybrid PQC TLS wiring injected onto mbedTLS targets")
    endif()

    # Apply ESP-IDF compiler flags to liboqs
    target_compile_options(oqs PRIVATE
        ${CONFIG_COMPILER_OPTIMIZATION_LEVEL}
    )

    message(STATUS "liboqs: Build configuration complete")

endif()
