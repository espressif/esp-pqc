/* SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 * SPDX-License-Identifier: Apache-2.0
 * 8KB PQC sector after the 4KB V2 ECDSA sector; digest = SHA-256(image + ECDSA). */

#ifndef PQC_SIG_BLOCK_H
#define PQC_SIG_BLOCK_H

#include "esp_assert.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQC_SIGNATURE_MAGIC 0xE8
#define PQC_SIGNATURE_VERSION 0x01

#define PQC_SIG_BLOCK_SIZE 8192
#define PQC_FLASH_SECTOR_SIZE 4096

#define PQC_MLDSA65_PK_LEN 1952
#define PQC_MLDSA65_SIG_LEN 3309
#define PQC_MLDSA65_SK_LEN 4032

#define PQC_MLDSA44_PK_LEN 1312
#define PQC_MLDSA44_SIG_LEN 2420

#define PQC_MLDSA87_PK_LEN 2592
#define PQC_MLDSA87_SIG_LEN 4627

#define PQC_MAX_PK_LEN 2592
#define PQC_MAX_SIG_LEN 4627
#define PQC_IMAGE_DIGEST_LEN 32

typedef enum {
  PQC_ALG_ML_DSA_44 = 1,
  PQC_ALG_ML_DSA_65 = 2,
  PQC_ALG_ML_DSA_87 = 3,
} pqc_algorithm_id_t;

#define PQC_CRC_COVER_LEN (offsetof(pqc_sig_block_t, block_crc))

struct __attribute__((packed)) pqc_sig_block {
  uint8_t magic_byte;
  uint8_t version;
  uint8_t algorithm_id;
  uint8_t flags;
  uint8_t image_digest[PQC_IMAGE_DIGEST_LEN];
  uint32_t public_key_len;
  uint32_t signature_len;
  uint8_t public_key[PQC_MAX_PK_LEN];
  uint8_t signature[PQC_MAX_SIG_LEN];
  uint32_t block_crc;
  uint8_t _padding[PQC_SIG_BLOCK_SIZE - 4 - PQC_IMAGE_DIGEST_LEN - 8 -
                   PQC_MAX_PK_LEN - PQC_MAX_SIG_LEN - 4];
};

typedef struct pqc_sig_block pqc_sig_block_t;

ESP_STATIC_ASSERT(sizeof(pqc_sig_block_t) == PQC_SIG_BLOCK_SIZE,
                  "PQC signature block must be exactly 8192 bytes");

typedef struct {
  pqc_sig_block_t block;
} pqc_signature_sector_t;

ESP_STATIC_ASSERT(sizeof(pqc_signature_sector_t) == PQC_SIG_BLOCK_SIZE,
                  "PQC signature sector must be exactly 8192 bytes");

static inline int pqc_get_algorithm_sizes(uint8_t alg_id, uint32_t *pk_len,
                                            uint32_t *sig_len) {
  switch (alg_id) {
  case PQC_ALG_ML_DSA_44:
    *pk_len = PQC_MLDSA44_PK_LEN;
    *sig_len = PQC_MLDSA44_SIG_LEN;
    return 0;
  case PQC_ALG_ML_DSA_65:
    *pk_len = PQC_MLDSA65_PK_LEN;
    *sig_len = PQC_MLDSA65_SIG_LEN;
    return 0;
  case PQC_ALG_ML_DSA_87:
    *pk_len = PQC_MLDSA87_PK_LEN;
    *sig_len = PQC_MLDSA87_SIG_LEN;
    return 0;
  default:
    return -1;
  }
}

#ifdef __cplusplus
}
#endif

#endif /* PQC_SIG_BLOCK_H */
