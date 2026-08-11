# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
#
# Project-level override of the builtin ESP-IDF `mbedtls` component.
#

idf_component_get_property(_idf_mbedtls_dir mbedtls COMPONENT_OVERRIDEN_DIR)
get_filename_component(_this_dir "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
set(_ovr_dir "")
if(_idf_mbedtls_dir)
    get_filename_component(_ovr_dir "${_idf_mbedtls_dir}" ABSOLUTE)
endif()
if(NOT _idf_mbedtls_dir OR _ovr_dir STREQUAL _this_dir)
    set(_idf_mbedtls_dir "$ENV{IDF_PATH}/components/mbedtls")
endif()

# ── Which mbedTLS source tree does this override compile? ─────────────────
# CONFIG_MBEDTLS_USE_BUNDLED_PQC (default y) selects it. The option is defined
# in the root esp-pqc Kconfig, under "Post-Quantum Cryptography (esp-pqc)" ->
# "mbedTLS", not in this dir's Kconfig:
#
#   y -> the local hybrid-PQC submodule (this dir's mbedtls/). This is the tree
#        that carries the TLS 1.3 hybrid PQC additions (X25519MLKEM768, ML-DSA-65).
#   n -> default ESP-IDF mbedTLS: the overridden $IDF_PATH/components/mbedtls tree,
#        exactly as if this override component did not exist.
#
if(CONFIG_MBEDTLS_USE_BUNDLED_PQC)
    if(NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/mbedtls/CMakeLists.txt")
        message(FATAL_ERROR
            "mbedtls override: CONFIG_MBEDTLS_USE_BUNDLED_PQC=y but the PQC mbedTLS "
            "submodule is missing at ${CMAKE_CURRENT_LIST_DIR}/mbedtls. "
            "Run: git submodule update --init --recursive")
    endif()
    message(STATUS "mbedtls: building BUNDLED hybrid-PQC submodule "
                   "(${CMAKE_CURRENT_LIST_DIR}/mbedtls)")

    set(_saved_component_dir "${COMPONENT_DIR}")
    set(COMPONENT_DIR "${_idf_mbedtls_dir}")
    include("${_idf_mbedtls_dir}/CMakeLists.txt")
    set(COMPONENT_DIR "${_saved_component_dir}")
else()
    message(STATUS "mbedtls: building DEFAULT ESP-IDF mbedTLS "
                   "(${_idf_mbedtls_dir}/mbedtls); PQC additions disabled")

    # Read at call time by the macro; safe to (re)set on every pass.
    set(_pqc_idf_submodule "${_idf_mbedtls_dir}/mbedtls")

    get_property(_pqc_asd_overridden GLOBAL PROPERTY _pqc_mbedtls_add_subdir_overridden)
    if(NOT _pqc_asd_overridden)
        set_property(GLOBAL PROPERTY _pqc_mbedtls_add_subdir_overridden TRUE)
        macro(add_subdirectory _srcdir)
            get_filename_component(_pqc_leaf "${_srcdir}" NAME)
            if(_pqc_leaf STREQUAL "mbedtls")
                # Out-of-tree source needs an explicit binary dir; reuse the
                # caller's extra args if any, else default the binary dir.
                if("${ARGN}" STREQUAL "")
                    _add_subdirectory("${_pqc_idf_submodule}" "mbedtls")
                else()
                    _add_subdirectory("${_pqc_idf_submodule}" ${ARGN})
                endif()
            else()
                _add_subdirectory("${_srcdir}" ${ARGN})
            endif()
        endmacro()
    endif()

    set(_saved_component_dir "${COMPONENT_DIR}")
    set(COMPONENT_DIR "${_idf_mbedtls_dir}")
    include("${_idf_mbedtls_dir}/CMakeLists.txt")
    set(COMPONENT_DIR "${_saved_component_dir}")
endif()
