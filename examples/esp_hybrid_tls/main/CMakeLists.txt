# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
set(TLS_TEST_SERVER_IP "" CACHE STRING "Mac LAN IP for OpenSSL server")

# Defaults matter: the early-expansion pass runs before sdkconfig is regenerated,
# so on the first build after a Kconfig change no CONFIG_EXAMPLE_TLS_PROFILE_* is
# set yet. Only SRCS/REQUIRES are read in that pass, so falling back here is safe.
set(EXAMPLE_PROFILE_NAME "full PQC (X25519MLKEM768 + ML-DSA-65)")
set(EXAMPLE_CA_CRT ../certs/mldsa65/test_ca.crt)

if(CONFIG_EXAMPLE_TLS_PROFILE_CLASSICAL)
    set(EXAMPLE_PROFILE_NAME "classical (X25519 + ECDSA-P256)")
    set(EXAMPLE_CA_CRT ../certs/ecdsa/test_ca.crt)
elseif(CONFIG_EXAMPLE_TLS_PROFILE_HYBRID_KEM)
    set(EXAMPLE_PROFILE_NAME "hybrid KEM (X25519MLKEM768 + ECDSA-P256)")
    set(EXAMPLE_CA_CRT ../certs/ecdsa/test_ca.crt)
elseif(CONFIG_EXAMPLE_TLS_PROFILE_FULL_PQC AND CONFIG_EXAMPLE_USE_TEST_CERTS)
    set(EXAMPLE_CA_CRT ../certs/test/test_ca.crt)
endif()

# Kconfig cannot force a symbol OFF from another menu, so the profile is enforced here.
# A silent mismatch is otherwise invisible: OpenSSL's default groups include X25519MLKEM768,
# so a "classical" build with the PQC group left on negotiates hybrid and still reports success.
if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    if(CONFIG_EXAMPLE_TLS_PROFILE_CLASSICAL AND CONFIG_LIBOQS_ENABLED)
        message(FATAL_ERROR
            "TLS profile is ${EXAMPLE_PROFILE_NAME}, but liboqs is enabled.\n"
            "Set CONFIG_LIBOQS_ENABLED=n. That one switch also drops both PQC TLS\n"
            "options and keeps liboqs out of the binary, so the footprint number\n"
            "is meaningful.\n"
            "  menuconfig: Component config -> Post-Quantum Cryptography (esp-pqc) -> liboqs")
    endif()

    if(CONFIG_EXAMPLE_TLS_PROFILE_HYBRID_KEM)
        if(NOT CONFIG_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768)
            message(FATAL_ERROR
                "TLS profile is ${EXAMPLE_PROFILE_NAME}, but the hybrid KEM group is off.\n"
                "Set CONFIG_LIBOQS_ENABLED=y, CONFIG_LIBOQS_ENABLE_KEM_ML_KEM=y and\n"
                "CONFIG_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768=y.")
        endif()
        if(CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65)
            message(FATAL_ERROR
                "TLS profile is ${EXAMPLE_PROFILE_NAME}, but ML-DSA-65 signatures are on.\n"
                "Set CONFIG_LIBOQS_ENABLE_SIG_ML_DSA=n, which disables\n"
                "CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65 with it and reclaims the flash.\n"
                "  menuconfig: Component config -> Post-Quantum Cryptography (esp-pqc)\n"
                "              -> liboqs -> Algorithm Selection")
        endif()
    endif()

    if(CONFIG_EXAMPLE_TLS_PROFILE_FULL_PQC
       AND (NOT CONFIG_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768
            OR NOT CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65))
        message(FATAL_ERROR
            "TLS profile is ${EXAMPLE_PROFILE_NAME}, but the PQC options are not both on.\n"
            "Set CONFIG_LIBOQS_ENABLED=y, CONFIG_LIBOQS_ENABLE_KEM_ML_KEM=y,\n"
            "CONFIG_LIBOQS_ENABLE_SIG_ML_DSA=y, and then both\n"
            "CONFIG_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768=y and\n"
            "CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65=y.\n"
            "  menuconfig: Component config -> Post-Quantum Cryptography (esp-pqc)")
    endif()

    message(STATUS "esp_hybrid_tls: TLS profile  = ${EXAMPLE_PROFILE_NAME}")
    message(STATUS "esp_hybrid_tls: trust anchor = ${EXAMPLE_CA_CRT}")
endif()

idf_component_register(SRCS "esp_hybrid_tls.c"
                    INCLUDE_DIRS "."
                    REQUIRES esp-pqc
                    PRIV_REQUIRES esp_event esp_netif nvs_flash protocol_examples_common
                    EMBED_TXTFILES ${EXAMPLE_CA_CRT}
)
if(TLS_TEST_SERVER_IP)
    target_compile_options(${COMPONENT_LIB} PRIVATE
        -DLOCALHOST_TESTING
        "-DWEB_SERVER_STR=\"${TLS_TEST_SERVER_IP}\"")
endif()
