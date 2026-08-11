# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

set(TEST_CRTS "crts/server_cert_chain.pem"
              "crts/prvtkey.pem"
              "crts/server_cert_bundle"
              "crts/bad_md_crt.pem"
              "crts/wrong_sig_crt_esp32_com.pem"
              "crts/correct_sig_crt_esp32_com.pem")

idf_component_register(SRCS "signature_basic.c"
    "sig_fixed_vectors.c"
    "test_rsa.c" "test_mbedtls_ecdsa.c"
                    PRIV_INCLUDE_DIRS "."
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES efuse cmock mbedtls esp_timer spi_flash esp_psram esp_security bootloader_support
                    REQUIRES esp-pqc
                    EMBED_TXTFILES ${TEST_CRTS}
                    WHOLE_ARCHIVE)

idf_component_get_property(mbedtls mbedtls COMPONENT_LIB)
target_compile_definitions(${mbedtls} INTERFACE "-DMBEDTLS_DEPRECATED_WARNING")
target_compile_definitions(mbedtls PUBLIC "-DMBEDTLS_DEPRECATED_WARNING")
# target_compile_definitions(mbedcrypto PUBLIC "-DMBEDTLS_DEPRECATED_WARNING")
target_compile_definitions(mbedx509 PUBLIC "-DMBEDTLS_DEPRECATED_WARNING")

target_link_options(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=esp_ds_finish_sign,--wrap=esp_ds_start_sign") 
