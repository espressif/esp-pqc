/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

void rsa_key_operations_psa(int keysize, bool check_performance,
                            bool generate_new_rsa);
// RSA Key Generation Test
void run_mbedtls_rsa_gen_key_test(int keysize);
