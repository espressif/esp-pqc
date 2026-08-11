/* SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 * SPDX-License-Identifier: Apache-2.0
 *
 * Bootloader ML-DSA-65 verification: TLSF-backed liboqs, optional temp-region
 * pool+stack, digest = SHA-256(image + ECDSA sector) before the PQC block.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_rom_crc.h"
#include "esp_rom_sys.h"

#include "pqc_bootloader_verify.h"
#include "pqc_public_key.h"
#include "pqc_sig_block.h"
#include "pqc_stack.h"

#include "tlsf.h"
#include <oqs/oqs.h>

/* C3/C5/C6: cycle count via rv_utils (PCCR); other RISC-V: rdcycle. */
#if defined(CONFIG_IDF_TARGET_ESP32C3) ||                                      \
    defined(CONFIG_IDF_TARGET_ESP32C5) || defined(CONFIG_IDF_TARGET_ESP32C6)
#include "riscv/rv_utils.h"
#define PQC_RDCYCLE() rv_utils_get_cycle_count()
#else
#define PQC_RDCYCLE()                                                          \
  ({                                                                           \
    uint32_t _c;                                                               \
    __asm__ volatile("rdcycle %0" : "=r"(_c));                                 \
    _c;                                                                        \
  })
#endif

/* Match esp_image_format.h without including it here. */
#ifndef ESP_ERR_IMAGE_INVALID
#define ESP_ERR_IMAGE_INVALID 0x2002
#endif

/* Hash flash first, then mmap PQC block (single mmap slot). */
const void *bootloader_mmap(uint32_t src_addr, uint32_t size);
void bootloader_munmap(const void *mapping);

typedef void *bootloader_sha256_handle_t;
bootloader_sha256_handle_t bootloader_sha256_start(void);
void bootloader_sha256_data(bootloader_sha256_handle_t handle, const void *data,
                            size_t data_len);
void bootloader_sha256_finish(bootloader_sha256_handle_t handle,
                              uint8_t *digest);

static const char *TAG = "PQC";

#define ALIGN_UP(num, align) (((num) + ((align) - 1)) & ~((align) - 1))
#define FLASH_SECTOR_SIZE 0x1000u

#if defined(CONFIG_PQC_MEM_TLSF)
/* Pool + stack at high end of app SRAM/DRAM (see ld/<target>/memory.ld.in). */
#define TLSF_POOL_SIZE (CONFIG_PQC_TLSF_POOL_SIZE_KB * 1024u)
#define PQC_STACK_SIZE (CONFIG_PQC_CALL_STACK_SIZE_KB * 1024u)
#define PQC_TEMP_REGION_SIZE (TLSF_POOL_SIZE + PQC_STACK_SIZE)
#if defined(CONFIG_IDF_TARGET_ESP32C5)
#define PQC_SRAM_BOUNDARY 0x40848ba0u
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
#define PQC_SRAM_BOUNDARY 0x40868910u
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
#define PQC_SRAM_BOUNDARY 0x3FCC8F10u
#elif defined(CONFIG_IDF_TARGET_ESP32S31)
#define PQC_SRAM_BOUNDARY 0x2f0672b0u
#else
#error                                                                         \
    "PQC_SRAM_BOUNDARY not defined for this target — add an entry here and in ld/<target>/memory.ld.in"
#endif
#define PQC_TEMP_REGION_START (PQC_SRAM_BOUNDARY - PQC_TEMP_REGION_SIZE)
#define PQC_STACK_START (PQC_TEMP_REGION_START + TLSF_POOL_SIZE)
#define PQC_STACK_END (PQC_STACK_START + PQC_STACK_SIZE)
#else
#define TLSF_POOL_SIZE (8u * 1024u)
#endif

#define PQC_STACK_FILL_PATTERN 0x5A5AA5A5u
#define PQC_PROFILE_CPU_MHZ 80u
#define PQC_HASH_CHUNK_SIZE (64u * 1024u)

#if !defined(CONFIG_PQC_MEM_TLSF)
static uint8_t s_tlsf_pool[TLSF_POOL_SIZE] __attribute__((aligned(4)));
#endif
static tlsf_t s_tlsf_heap = NULL;

static esp_err_t tlsf_ensure_init(void) {
  if (s_tlsf_heap != NULL) {
    return ESP_OK;
  }
#if defined(CONFIG_PQC_MEM_TLSF)
  void *pool = (void *)PQC_TEMP_REGION_START;
#else
  void *pool = s_tlsf_pool;
#endif
  s_tlsf_heap = tlsf_create_with_pool(pool, TLSF_POOL_SIZE, TLSF_POOL_SIZE);
  if (s_tlsf_heap == NULL) {
    ESP_EARLY_LOGE(TAG, "TLSF pool init failed");
    return ESP_ERR_NO_MEM;
  }
#ifdef CONFIG_PQC_DEBUG_VERBOSE
  ESP_EARLY_LOGI(TAG, "TLSF pool initialised (%u bytes) at %p", TLSF_POOL_SIZE,
                 pool);
#endif
  return ESP_OK;
}

void *oqs_platform_malloc(size_t size) {
  void *p = tlsf_malloc(s_tlsf_heap, size);
#ifdef CONFIG_PQC_DEBUG_VERBOSE
  ESP_EARLY_LOGI(TAG, "oqs_malloc(%u) = %p", (unsigned)size, p);
#endif
  return p;
}

void *oqs_platform_calloc(size_t n, size_t size) {
  void *p = tlsf_malloc(s_tlsf_heap, n * size);
#ifdef CONFIG_PQC_DEBUG_VERBOSE
  ESP_EARLY_LOGI(TAG, "oqs_calloc(%u, %u) = %p", (unsigned)n, (unsigned)size,
                 p);
#endif
  if (p) {
    memset(p, 0, n * size);
  }
  return p;
}

void oqs_platform_free(void *ptr) {
#ifdef CONFIG_PQC_DEBUG_VERBOSE
  if (ptr) {
    ESP_EARLY_LOGI(TAG, "oqs_free(%p)", ptr);
  }
#endif
  if (ptr) {
    tlsf_free(s_tlsf_heap, ptr);
  }
}

#if defined(CONFIG_PQC_MEM_TLSF)
void *pqc_tlsf_alloc(size_t size) {
  if (s_tlsf_heap == NULL && tlsf_ensure_init() != ESP_OK) {
    return NULL;
  }
  void *p = tlsf_malloc(s_tlsf_heap, size);
#ifdef CONFIG_PQC_DEBUG_VERBOSE
  ESP_EARLY_LOGI(TAG, "tlsf_alloc(%u) = %p", (unsigned)size, p);
#endif
  if (p) {
    memset(p, 0, size);
  } else {
    ESP_EARLY_LOGE(TAG, "TLSF ALLOC FAILED for %u bytes!", (unsigned)size);
  }
  return p;
}

void pqc_tlsf_free(void *ptr, size_t size) {
  (void)size;
#ifdef CONFIG_PQC_DEBUG_VERBOSE
  if (ptr) {
    ESP_EARLY_LOGI(TAG, "tlsf_free(%p, %u)", ptr, (unsigned)size);
  }
#endif
  if (ptr) {
    tlsf_free(s_tlsf_heap, ptr);
  }
}
#endif /* CONFIG_PQC_MEM_TLSF */

#if defined(CONFIG_PQC_MEM_TLSF)
#define s_pqc_stack_start ((uint8_t *)PQC_STACK_START)
#define s_pqc_stack_end ((uint8_t *)PQC_STACK_END)
uint8_t *const pqc_stack_top = (uint8_t *)PQC_STACK_END;
#else
extern uint8_t _pqc_stack_start[];
extern uint8_t _pqc_stack_end[];
#define s_pqc_stack_start _pqc_stack_start
#define s_pqc_stack_end _pqc_stack_end
#endif

static OQS_SIG *s_sig_obj = NULL;
static uint8_t s_digest[PQC_IMAGE_DIGEST_LEN];
static const pqc_sig_block_t *s_block = NULL;

static size_t pqc_stack_used_bytes(void) {
  /* Unused stack still holds PQC_STACK_FILL_PATTERN; stack grows down from end. */
  const uint32_t *p = (const uint32_t *)s_pqc_stack_start;
  const uint32_t *limit = (const uint32_t *)s_pqc_stack_end;

  while (p < limit && *p == PQC_STACK_FILL_PATTERN) {
    p++;
  }
  size_t unused =
      (size_t)((const uint8_t *)p - (const uint8_t *)s_pqc_stack_start);
  size_t total = (size_t)((const uint8_t *)s_pqc_stack_end -
                          (const uint8_t *)s_pqc_stack_start);
  return total - unused;
}

#if defined(CONFIG_PQC_MEM_TLSF)
static void pqc_zero_temp_region(void) {
  memset((void *)PQC_TEMP_REGION_START, 0, PQC_TEMP_REGION_SIZE);
}
#endif

static esp_err_t sha256_flash_region(uint32_t flash_addr, uint32_t len,
                                     uint8_t *digest) {
  bootloader_sha256_handle_t sha = bootloader_sha256_start();
  if (sha == NULL) {
    ESP_EARLY_LOGE(TAG, "Failed to start SHA-256 context");
    return ESP_ERR_NO_MEM;
  }

  uint32_t offset = 0;
  while (offset < len) {
    uint32_t chunk = len - offset;
    if (chunk > PQC_HASH_CHUNK_SIZE) {
      chunk = PQC_HASH_CHUNK_SIZE;
    }
    chunk = ALIGN_UP(chunk, 4);
    if (chunk > len - offset) {
      chunk = len - offset;
    }

    const void *mapping = bootloader_mmap(flash_addr + offset, chunk);
    if (mapping == NULL) {
      ESP_EARLY_LOGE(TAG, "mmap failed at 0x%lX+%lu",
                     (unsigned long)(flash_addr + offset),
                     (unsigned long)chunk);
      bootloader_sha256_finish(sha, NULL);
      return ESP_ERR_IMAGE_INVALID;
    }

    bootloader_sha256_data(sha, mapping, chunk);
    bootloader_munmap(mapping);
    offset += chunk;
  }

  bootloader_sha256_finish(sha, digest);
  return ESP_OK;
}

static esp_err_t validate_pqc_block(const pqc_sig_block_t *block) {
  if (block->magic_byte != PQC_SIGNATURE_MAGIC) {
    ESP_EARLY_LOGE(TAG, "Bad magic: 0x%02X (expected 0x%02X)",
                   block->magic_byte, PQC_SIGNATURE_MAGIC);
    return ESP_ERR_IMAGE_INVALID;
  }
  if (block->version != PQC_SIGNATURE_VERSION) {
    ESP_EARLY_LOGE(TAG, "Bad version: 0x%02X (expected 0x%02X)", block->version,
                   PQC_SIGNATURE_VERSION);
    return ESP_ERR_IMAGE_INVALID;
  }

  uint32_t expected_pk_len, expected_sig_len;
  if (pqc_get_algorithm_sizes(block->algorithm_id, &expected_pk_len,
                              &expected_sig_len) != 0) {
    ESP_EARLY_LOGE(TAG, "Unknown algorithm ID: 0x%02X", block->algorithm_id);
    return ESP_ERR_IMAGE_INVALID;
  }
  if (block->public_key_len != expected_pk_len) {
    ESP_EARLY_LOGE(TAG, "PK length mismatch: %lu (expected %lu)",
                   (unsigned long)block->public_key_len,
                   (unsigned long)expected_pk_len);
    return ESP_ERR_IMAGE_INVALID;
  }
  if (block->signature_len > expected_sig_len) {
    ESP_EARLY_LOGE(TAG, "Signature too long: %lu (max %lu)",
                   (unsigned long)block->signature_len,
                   (unsigned long)expected_sig_len);
    return ESP_ERR_IMAGE_INVALID;
  }

  uint32_t computed_crc =
      esp_rom_crc32_le(0, (const uint8_t *)block, PQC_CRC_COVER_LEN);
  if (computed_crc != block->block_crc) {
    ESP_EARLY_LOGE(TAG, "CRC mismatch: computed=0x%08lX stored=0x%08lX",
                   (unsigned long)computed_crc,
                   (unsigned long)block->block_crc);
    return ESP_ERR_IMAGE_INVALID;
  }

  return ESP_OK;
}

static int pqc_verify_on_stack(void) {
  if (s_sig_obj == NULL || s_sig_obj->verify == NULL) {
    ESP_EARLY_LOGE(TAG, "OQS_SIG object not initialised");
    return (int)OQS_ERROR;
  }

  if (memcmp(s_block->image_digest, s_digest, PQC_IMAGE_DIGEST_LEN) != 0) {
    ESP_EARLY_LOGE(TAG, "Image digest mismatch (PQC block vs recomputed)");
    return (int)OQS_ERROR;
  }

  if (s_block->public_key_len != PQC_PUBLIC_KEY_LEN ||
      memcmp(s_block->public_key, pqc_public_key, PQC_PUBLIC_KEY_LEN) != 0) {
    ESP_EARLY_LOGE(TAG, "PQC block public key does not match compiled-in key");
    return (int)OQS_ERROR;
  }

  int ret = (int)s_sig_obj->verify(s_digest, PQC_IMAGE_DIGEST_LEN,
                                   s_block->signature, s_block->signature_len,
                                   pqc_public_key);
  return ret;
}

esp_err_t pqc_bootloader_verify(uint32_t pqc_block_flash_addr,
                                uint32_t image_start_addr) {
  esp_err_t err;

  if (tlsf_ensure_init() != ESP_OK) {
    return ESP_ERR_IMAGE_INVALID;
  }
#ifdef CONFIG_PQC_DEBUG_VERBOSE
#if defined(CONFIG_PQC_MEM_TLSF)
  ESP_EARLY_LOGI(TAG, "TLSF heap init OK, pool=0x%08X heap=%p",
                 (unsigned)PQC_TEMP_REGION_START, s_tlsf_heap);
#else
  ESP_EARLY_LOGI(TAG, "TLSF heap init OK, pool=%p heap=%p", s_tlsf_pool,
                 s_tlsf_heap);
#endif
#endif

  if (s_sig_obj == NULL) {
    s_sig_obj = OQS_SIG_ml_dsa_65_new();
    if (s_sig_obj == NULL) {
      ESP_EARLY_LOGE(TAG, "Failed to allocate OQS_SIG object");
      return ESP_ERR_IMAGE_INVALID;
    }

    uintptr_t sig_addr = (uintptr_t)s_sig_obj;
#if defined(CONFIG_PQC_MEM_TLSF)
    uintptr_t pool_start = (uintptr_t)PQC_TEMP_REGION_START;
#else
    uintptr_t pool_start = (uintptr_t)s_tlsf_pool;
#endif
    uintptr_t pool_end = pool_start + TLSF_POOL_SIZE;
    if (sig_addr < pool_start || sig_addr >= pool_end) {
      ESP_EARLY_LOGE(TAG, "TLSF alloc FAILED: OQS_SIG outside pool — "
                          "oqs_platform_malloc override not active!");
      return ESP_ERR_IMAGE_INVALID;
    }
  }

  uint32_t hash_len = pqc_block_flash_addr - image_start_addr;
#ifdef CONFIG_PQC_DEBUG_VERBOSE
  ESP_EARLY_LOGI(
      TAG, "digest hashing flash [0x%lX, 0x%lX) (%lu bytes = image+ECDSA)",
      (unsigned long)image_start_addr, (unsigned long)pqc_block_flash_addr,
      (unsigned long)hash_len);
#endif

  uint32_t sha_c0, sha_c1;
  sha_c0 = PQC_RDCYCLE();
  err = sha256_flash_region(image_start_addr, hash_len, s_digest);
  sha_c1 = PQC_RDCYCLE();
  {
    uint32_t sha_cycles = sha_c1 - sha_c0;
    uint32_t sha_us = sha_cycles / PQC_PROFILE_CPU_MHZ;
    esp_rom_printf(
        "PQC: SHA-256 hash: %lu cycles, %lu us, %lu ms (CPU %u MHz)\n",
        (unsigned long)sha_cycles, (unsigned long)sha_us,
        (unsigned long)(sha_us / 1000u), (unsigned)PQC_PROFILE_CPU_MHZ);
  }
  if (err != ESP_OK) {
    ESP_EARLY_LOGE(TAG, "Failed to hash flash region for PQC digest");
    return ESP_ERR_IMAGE_INVALID;
  }

#ifdef CONFIG_PQC_DEBUG_VERBOSE
  ESP_EARLY_LOGI(TAG, "PQC digest (image+ECDSA): %02x%02x%02x%02x...",
                 s_digest[0], s_digest[1], s_digest[2], s_digest[3]);
#endif

  const pqc_sig_block_t *block = (const pqc_sig_block_t *)bootloader_mmap(
      pqc_block_flash_addr, PQC_SIG_BLOCK_SIZE);
  if (block == NULL) {
    ESP_EARLY_LOGE(TAG, "Failed to mmap PQC block at 0x%lX",
                   (unsigned long)pqc_block_flash_addr);
    return ESP_ERR_IMAGE_INVALID;
  }

  err = validate_pqc_block(block);
  if (err != ESP_OK) {
    ESP_EARLY_LOGE(TAG, "PQC block header validation failed");
    bootloader_munmap(block);
    return ESP_ERR_IMAGE_INVALID;
  }
#ifdef CONFIG_PQC_DEBUG_VERBOSE
  ESP_EARLY_LOGI(TAG, "PQC block OK: alg=%d pk_len=%lu sig_len=%lu",
                 block->algorithm_id, (unsigned long)block->public_key_len,
                 (unsigned long)block->signature_len);
#endif

  s_block = block;

  const size_t stack_bytes = (size_t)(s_pqc_stack_end - s_pqc_stack_start);
#ifdef CONFIG_PQC_DEBUG_VERBOSE
  ESP_EARLY_LOGI(TAG, "PQC stack region: %p - %p (%u bytes)", s_pqc_stack_start,
                 s_pqc_stack_end, (unsigned)stack_bytes);
#endif
  uint32_t *fill = (uint32_t *)s_pqc_stack_start;
  for (size_t i = 0; i < stack_bytes / sizeof(uint32_t); i++) {
    fill[i] = PQC_STACK_FILL_PATTERN;
  }
#ifdef CONFIG_PQC_DEBUG_VERBOSE
  ESP_EARLY_LOGI(TAG, "stack fill done, switching stack...");
#endif

  uint32_t t0, t1;
  t0 = PQC_RDCYCLE();
  int ret = run_with_pqc_stack(pqc_verify_on_stack);
  t1 = PQC_RDCYCLE();
  {
    uint32_t cycles = t1 - t0;
    uint32_t us = cycles / PQC_PROFILE_CPU_MHZ;
    esp_rom_printf(
        "PQC: ML-DSA-65 verify: %lu cycles, %lu us, %lu ms (CPU %u MHz)\n",
        (unsigned long)cycles, (unsigned long)us, (unsigned long)(us / 1000u),
        (unsigned)PQC_PROFILE_CPU_MHZ);
  }

  size_t stack_used = pqc_stack_used_bytes();
  (void)stack_used;

  bootloader_munmap(block);
  s_block = NULL;

#if defined(CONFIG_PQC_MEM_TLSF)
  tlsf_destroy(s_tlsf_heap);
  s_tlsf_heap = NULL;
  s_sig_obj = NULL;
  pqc_zero_temp_region();
#endif

  if (ret != (int)OQS_SUCCESS) {
    ESP_EARLY_LOGE(TAG, "ML-DSA-65 verify FAILED (ret=%d)", ret);
    return ESP_ERR_IMAGE_INVALID;
  }

  esp_rom_printf("PQC verification successful!! \n");

  return ESP_OK;
}
