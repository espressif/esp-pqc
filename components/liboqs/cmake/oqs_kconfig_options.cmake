# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
#
# Shared ESP-IDF liboqs build configuration: architecture translation, core OQS
# options, unavailable-platform-feature disables, and the CONFIG_LIBOQS_ENABLE_*
# -> OQS_ENABLE_* algorithm selection.
#
# Included by both the app-side component (components/liboqs/CMakeLists.txt) and
# the bootloader-side wrapper
# (examples/pqc_boot_verify/bootloader_components/liboqs/CMakeLists.txt) so the
# algorithm on/off mapping lives in ONE place.
#
# Before include(), set _OQS_OPT_FORCE to "FORCE" to make the cache writes
# overwrite any existing values (the bootloader subproject needs this); leave it
# unset/empty for the default "set only if not already cached" behaviour.

if(NOT DEFINED _OQS_OPT_FORCE)
    set(_OQS_OPT_FORCE "")
endif()

# Port directory (this file lives in components/liboqs/cmake/). The liboqs build
# reads it to compile the standalone Keccak, ports/fips202_kyber.c, into the
# common object library; the algorithm CMakeLists point mlkem-native and
# mldsa-native at the glue headers next to it through their custom FIPS-202
# header hooks. Callers must also put this directory on the include path.
get_filename_component(ESP_LIBOQS_PORTS_DIR "${CMAKE_CURRENT_LIST_DIR}/../ports" ABSOLUTE)
if(NOT EXISTS "${ESP_LIBOQS_PORTS_DIR}/fips202_kyber.c")
    message(FATAL_ERROR "liboqs: port directory is missing fips202_kyber.c "
        "(looked in ${ESP_LIBOQS_PORTS_DIR}).")
endif()

# Turn on every Espressif-specific change in the liboqs tree. This is the single
# switch the submodule keys all of its ESP32 overrides off: standalone Keccak
# from ESP_LIBOQS_PORTS_DIR, heap-backed ML-KEM/ML-DSA temporaries, the
# verify-only ML-DSA surface, and the weak oqs_platform_* allocator hooks.
# With it OFF (the liboqs default) the submodule builds exactly like upstream
# and never references this ports directory, so liboqs can be built standalone.
set(OQS_ESP32_BUILD ON CACHE BOOL "Espressif ESP-IDF port" ${_OQS_OPT_FORCE})

# Architecture translation for ESP32 variants
if(CONFIG_IDF_TARGET_ARCH_XTENSA)
    # Xtensa is not natively supported by liboqs; treat it as a generic
    # embedded target and use the reference implementations.
    message(STATUS "liboqs: Xtensa architecture - using reference implementations")
    set(OQS_PERMIT_UNSUPPORTED_ARCHITECTURE ON)
    set(CMAKE_SYSTEM_PROCESSOR "generic")
elseif(CONFIG_IDF_TARGET_ARCH_RISCV)
    message(STATUS "liboqs: RISC-V architecture - optimizations available")
    # All ESP32 RISC-V variants are 32-bit
    set(CMAKE_SYSTEM_PROCESSOR "riscv32")
endif()

# Pointer size (all ESP32 variants are 32-bit)
set(CMAKE_SIZEOF_VOID_P 4)

# Core liboqs configuration
set(OQS_DIST_BUILD OFF CACHE BOOL "")
set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "")
set(OQS_USE_OPENSSL OFF CACHE BOOL "")
set(OQS_EMBEDDED_BUILD ON CACHE BOOL "")
set(CMAKE_CROSSCOMPILING ON)
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY TRUE)
set(SKIP_INSTALL_ALL TRUE)

# Disable platform features not available in ESP-IDF
set(CMAKE_HAVE_GETENTROPY OFF)
set(CMAKE_HAVE_ALIGNED_ALLOC OFF)
set(CMAKE_HAVE_POSIX_MEMALIGN OFF)
set(CMAKE_HAVE_MEMALIGN OFF)
set(CMAKE_HAVE_EXPLICIT_BZERO OFF)
set(CMAKE_HAVE_MEMSET_S OFF)
set(CC_SUPPORTS_WA_NOEXECSTACK OFF)
set(LD_SUPPORTS_WL_Z_NOEXECSTACK OFF)

# Algorithm selection via Kconfig
# KEMs
if(CONFIG_LIBOQS_ENABLE_KEM_ML_KEM)
    set(OQS_ENABLE_KEM_ML_KEM ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_KEM_ML_KEM OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

if(CONFIG_LIBOQS_ENABLE_KEM_BIKE)
    set(OQS_ENABLE_KEM_BIKE ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_KEM_BIKE OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

if(CONFIG_LIBOQS_ENABLE_KEM_FRODOKEM)
    set(OQS_ENABLE_KEM_FRODOKEM ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_KEM_FRODOKEM OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

if(CONFIG_LIBOQS_ENABLE_KEM_NTRUPRIME)
    set(OQS_ENABLE_KEM_NTRUPRIME ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_KEM_NTRUPRIME OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

if(CONFIG_LIBOQS_ENABLE_KEM_CLASSIC_MCELIECE)
    set(OQS_ENABLE_KEM_CLASSIC_MCELIECE ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_KEM_CLASSIC_MCELIECE OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

if(CONFIG_LIBOQS_ENABLE_KEM_HQC)
    set(OQS_ENABLE_KEM_HQC ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_KEM_HQC OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

if(CONFIG_LIBOQS_ENABLE_KEM_KYBER)
    set(OQS_ENABLE_KEM_KYBER ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_KEM_KYBER OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

if(CONFIG_LIBOQS_ENABLE_KEM_NTRU)
    set(OQS_ENABLE_KEM_NTRU ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_KEM_NTRU OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

# Signatures
if(CONFIG_LIBOQS_ENABLE_SIG_ML_DSA)
    set(OQS_ENABLE_SIG_ML_DSA ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_SIG_ML_DSA OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

if(CONFIG_LIBOQS_ENABLE_SIG_FALCON)
    set(OQS_ENABLE_SIG_FALCON ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_SIG_FALCON OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

if(CONFIG_LIBOQS_ENABLE_SIG_MAYO)
    set(OQS_ENABLE_SIG_MAYO ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_mayo_5 OFF CACHE BOOL "" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_SIG_MAYO OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

if(CONFIG_LIBOQS_ENABLE_SIG_UOV)
    set(OQS_ENABLE_SIG_UOV ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_SIG_UOV OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

if(CONFIG_LIBOQS_ENABLE_SIG_CROSS)
    set(OQS_ENABLE_SIG_CROSS ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_cross_rsdp_128_small OFF CACHE BOOL "" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_cross_rsdp_192_small OFF CACHE BOOL "" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_cross_rsdp_256_balanced OFF CACHE BOOL "" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_cross_rsdp_256_small OFF CACHE BOOL "" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_cross_rsdpg_192_small OFF CACHE BOOL "" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_cross_rsdpg_256_small OFF CACHE BOOL "" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_SIG_CROSS OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

if(CONFIG_LIBOQS_ENABLE_SIG_SNOVA)
    set(OQS_ENABLE_SIG_SNOVA ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_snova_SNOVA_56_25_2 OFF CACHE BOOL "" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_snova_SNOVA_49_11_3 OFF CACHE BOOL "" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_snova_SNOVA_37_8_4 OFF CACHE BOOL "" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_snova_SNOVA_60_10_4 OFF CACHE BOOL "" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_snova_SNOVA_24_5_5 OFF CACHE BOOL "" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_snova_SNOVA_29_6_5 OFF CACHE BOOL "" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_SIG_SNOVA OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

if(CONFIG_LIBOQS_ENABLE_SIG_SLH_DSA)
    set(OQS_ENABLE_SIG_SLH_DSA ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
else()
    set(OQS_ENABLE_SIG_SLH_DSA OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()

# MQOM (new in liboqs 0.16.0) always off: needs the 4-way SHAKE API the embedded SHA3 layer lacks.
set(OQS_ENABLE_SIG_MQOM OFF CACHE BOOL "Not supported on ESP targets" ${_OQS_OPT_FORCE})

# Minimal common: exclude SHA3/SHA2/fips202 from common layer
if(CONFIG_LIBOQS_MINIMAL_COMMON)
    set(OQS_EMBEDDED_MINIMAL_COMMON ON CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
    message(STATUS "liboqs: Minimal common layer (SHA3/fips202 excluded)")
    # Only ML-KEM-768 and ML-DSA-65 carry the standalone fips202_kyber Keccak.
    # The other variants still call the common SHA3 layer that this option
    # removes, so they cannot link and are disabled here.
    set(OQS_ENABLE_KEM_ml_kem_512 OFF CACHE BOOL "needs common SHA3" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_KEM_ml_kem_1024 OFF CACHE BOOL "needs common SHA3" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_ml_dsa_44 OFF CACHE BOOL "needs common SHA3" ${_OQS_OPT_FORCE})
    set(OQS_ENABLE_SIG_ml_dsa_87 OFF CACHE BOOL "needs common SHA3" ${_OQS_OPT_FORCE})
else()
    set(OQS_EMBEDDED_MINIMAL_COMMON OFF CACHE BOOL "From Kconfig" ${_OQS_OPT_FORCE})
endif()
