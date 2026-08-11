# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
#
# Bootloader-side liboqs build recipe (verify-only ML-DSA-65), included by the root esp-pqc CMakeLists.txt in its BOOTLOADER_BUILD branch (a project pulls esp-pqc into the bootloader via BOOTLOADER_EXTRA_COMPONENT_DIRS — no bootloader_components shim).

# This component's root is the parent of this cmake/ dir, independent of who includes us.
get_filename_component(UPSTREAM "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

if(NOT EXISTS "${UPSTREAM}/liboqs/CMakeLists.txt")
    message(FATAL_ERROR "liboqs submodule not found at ${UPSTREAM}/liboqs — "
        "run 'git submodule update --init --recursive'.")
endif()

idf_component_register(
    SRCS "${UPSTREAM}/ports/esp_rand_adapter.c"
         "${UPSTREAM}/ports/esp_liboqs_init.c"
    INCLUDE_DIRS "${UPSTREAM}/include"
    REQUIRES esp_hw_support
    PRIV_REQUIRES esp_system
)

target_link_libraries(${COMPONENT_LIB} PRIVATE "-u esp_liboqs_init_include_impl")

# Only build liboqs if enabled in Kconfig
if(CONFIG_LIBOQS_ENABLED)

    message(STATUS "liboqs: Enabled for ${IDF_TARGET}")

    # Only TLSF mode consumes pqc_mld_alloc.h (see the CONFIG_PQC_MEM_TLSF -include below), so require the project's bootloader_support include dir (forwarded via EXTRA_CMAKE_ARGS -DPQC_BOOTLOADER_SUPPORT_INCLUDE) only in that mode.
    if(CONFIG_PQC_MEM_TLSF)
        if(NOT DEFINED PQC_BOOTLOADER_SUPPORT_INCLUDE OR
           NOT EXISTS "${PQC_BOOTLOADER_SUPPORT_INCLUDE}/pqc_mld_alloc.h")
            message(FATAL_ERROR "CONFIG_PQC_MEM_TLSF is set but "
                "PQC_BOOTLOADER_SUPPORT_INCLUDE does not point at a "
                "bootloader_support include dir providing pqc_mld_alloc.h "
                "(got '${PQC_BOOTLOADER_SUPPORT_INCLUDE}'). Set it via "
                "EXTRA_CMAKE_ARGS in the project's top-level CMakeLists.txt.")
        endif()
    endif()

    # ESP-IDF liboqs config + Kconfig algorithm selection; FORCE so the bootloader subproject cache always reflects current Kconfig.
    set(_OQS_OPT_FORCE "FORCE")
    include("${UPSTREAM}/cmake/oqs_kconfig_options.cmake")

    macro(install)
    endmacro()

    macro(export)
    endmacro()

    # Same as the app-side build: the ports dir carries fips202_kyber.h and the
    # FIPS-202 glue headers the ML-DSA-65 custom-header hook resolves by name.
    include_directories("${UPSTREAM}/include" "${UPSTREAM}/ports")

    # ── Build the liboqs submodule directly ──────────────────────────
    add_subdirectory("${UPSTREAM}/liboqs" "${CMAKE_CURRENT_BINARY_DIR}/liboqs_build" EXCLUDE_FROM_ALL)

    # Disable PIC for all liboqs targets recursively
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

    disable_pic_for_all_targets("${UPSTREAM}/liboqs")

    # Restore install() and export()
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

    # Compile liboqs with -O2 regardless of project optimization level
    target_compile_options(oqs PRIVATE -O2)

    # Apply PQC-specific compile flags to ALL liboqs sub-targets (liboqs's internal object libs don't inherit from `oqs`).
    function(apply_pqc_flags_to_all_targets dir)
        get_directory_property(subdirs DIRECTORY ${dir} SUBDIRECTORIES)
        foreach(subdir ${subdirs})
            apply_pqc_flags_to_all_targets(${subdir})
        endforeach()
        get_directory_property(targets DIRECTORY ${dir} BUILDSYSTEM_TARGETS)
        foreach(target ${targets})
            if(TARGET ${target})
                get_target_property(target_type ${target} TYPE)
                if(NOT target_type STREQUAL "UTILITY")
                    # Bootloader only verifies: compile out ML-DSA-65 keygen/sign.
                    target_compile_definitions(${target} PRIVATE LIBOQS_MLD_VERIFY_ONLY)
                    if(CONFIG_PQC_MEM_TLSF)
                        # Route large ML-DSA temporaries through the TLSF pool: LIBOQS_MLD_EXTERNAL_ALLOC defers the allocator to us, pqc_mld_alloc.h supplies MLD_CUSTOM_ALLOC/FREE.
                        target_compile_definitions(${target} PRIVATE
                            LIBOQS_MLD_EXTERNAL_ALLOC MLD_CONFIG_CUSTOM_ALLOC_FREE)
                        target_compile_options(${target} PRIVATE
                            -include "${PQC_BOOTLOADER_SUPPORT_INCLUDE}/pqc_mld_alloc.h"
                        )
                    else()
                        # Stack-only: disable config_c.h's heap/malloc temporaries.
                        target_compile_definitions(${target} PRIVATE MLD_HEAP_TEMPORARIES=0)
                    endif()
                    # REDUCE_RAM: use row-buffer matrix (30KB → 5KB) and serial FIPS-202
                    if(CONFIG_PQC_MLD_REDUCE_RAM)
                        target_compile_definitions(${target} PRIVATE MLD_CONFIG_REDUCE_RAM)
                    endif()
                endif()
            endif()
        endforeach()
    endfunction()
    apply_pqc_flags_to_all_targets("${UPSTREAM}/liboqs")

    # Status summary
    set(_mem_mode "Stack")
    if(CONFIG_PQC_MEM_TLSF)
        set(_mem_mode "TLSF heap")
    endif()
    set(_reduce "OFF")
    if(CONFIG_PQC_MLD_REDUCE_RAM)
        set(_reduce "ON")
    endif()
    message(STATUS "liboqs: memory=${_mem_mode}, REDUCE_RAM=${_reduce} (all sub-targets)")

    message(STATUS "liboqs: Build configuration complete")

endif()
