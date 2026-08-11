/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
//
// Declarations for ML-DSA-65 test message, public/secret keys, and reference
// signature bytes (definitions in sig_fixed_vectors.c).

#pragma once

#include <stddef.h>
#include <stdint.h>

#define SIG_FIXED_MLDSA65_MESSAGE_LEN 100
#define SIG_FIXED_MLDSA65_PUBLIC_KEY_LEN 1952
#define SIG_FIXED_MLDSA65_SECRET_KEY_LEN 4032
#define SIG_FIXED_MLDSA65_SIGNATURE_LEN 3309

extern const uint8_t test_message[];
extern const size_t test_message_len;
extern const uint8_t test_public_key[];
extern const size_t test_public_key_len;
extern const uint8_t test_secret_key[];
extern const size_t test_secret_key_len;
extern const uint8_t test_signature_array[];
extern const size_t test_signature_len;
