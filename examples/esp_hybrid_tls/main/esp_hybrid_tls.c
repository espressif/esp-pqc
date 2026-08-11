/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "esp_littlefs.h"

#include "mbedtls/error.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"

/* Trust anchor for the selected profile, embedded by main/CMakeLists.txt (always named test_ca.crt). */
extern const uint8_t ca_crt_start[] asm("_binary_test_ca_crt_start");
extern const uint8_t ca_crt_end[] asm("_binary_test_ca_crt_end");

/*
 * Server address:
 *   Build with: idf.py build -DTLS_TEST_SERVER_IP=<LAN IP of the TLS server>
 */
/* One port per profile so the run_server.sh modes can run side by side; a system nginx often squats on 8443. */
#if defined(CONFIG_EXAMPLE_TLS_PROFILE_CLASSICAL)
#define WEB_PORT "8443"
#define TLS_PROFILE_NAME "classical"
#define TLS_KEM_NAME "X25519 (classical ECDHE)"
#define TLS_SIG_NAME "ECDSA-P256 (sig 0x0403, ecdsa_secp256r1_sha256)"
#define TLS_SERVER_MODE "ecdsa"
/* Log tag follows the profile so a serial capture says which crypto ran. */
#define TLS_LOG_TAG "classical_tls"
#elif defined(CONFIG_EXAMPLE_TLS_PROFILE_HYBRID_KEM)
#define WEB_PORT "8445"
#define TLS_PROFILE_NAME "hybrid KEM"
#define TLS_KEM_NAME "X25519MLKEM768 (0x11EC)"
#define TLS_SIG_NAME "ECDSA-P256 (sig 0x0403, ecdsa_secp256r1_sha256)"
#define TLS_SERVER_MODE "hybrid-kem"
#define TLS_LOG_TAG "hybrid_kem_tls"
#elif defined(CONFIG_EXAMPLE_TLS_PROFILE_FULL_PQC)
#define WEB_PORT "8444"
#define TLS_PROFILE_NAME "full PQC"
#define TLS_KEM_NAME "X25519MLKEM768 (0x11EC)"
#define TLS_SIG_NAME "ML-DSA-65 (sig 0x0905, id-ml-dsa-65, RFC 9881)"
#define TLS_SERVER_MODE "mldsa65"
#define TLS_LOG_TAG "full_pqc_tls"
#else
#error "No CONFIG_EXAMPLE_TLS_PROFILE_* selected; run idf.py menuconfig"
#endif

#ifdef LOCALHOST_TESTING
#define WEB_SERVER WEB_SERVER_STR
#else
#define WEB_SERVER "localhost"
#endif

#define TLS_SERVER_CERT_NAME "esp-pqc-tls-server"

#define DOWNLOAD_PATH "/tls_testfile.bin"
#define DOWNLOAD_DEST "/lfs/testfile.bin"
#if CONFIG_EXAMPLE_HTTP_DOWNLOAD
/* Empty string disables the comparison and only logs the digest. */
#define EXPECTED_SHA256 CONFIG_EXAMPLE_DOWNLOAD_EXPECTED_SHA256
#endif
#define READ_BUF_SIZE 4096
#define HTTP_HDR_BUF_SIZE 4096
/** Chunks for reading HTTP response headers (avoid 1-byte ssl_read + debug
 * flood). */
#define HTTP_HDR_READ_CHUNK 512

static const char *TAG = TLS_LOG_TAG;

static void pqc_log_stack_hwm(const char *where) {
  UBaseType_t w = uxTaskGetStackHighWaterMark(NULL);
  const unsigned unit_b = (unsigned)sizeof(StackType_t);
  const unsigned min_free_b = (unsigned)w * unit_b;
  ESP_LOGI(TAG,
           "StackHighWaterMark [%s]: HWM=%u (stack slot size=%u B) => ~%u B "
           "min free",
           where, (unsigned)w, unit_b, min_free_b);
}

/**
 * Heap watermarks: `free` is the current free heap; `min_free` is the
 * boot-wide minimum (the transient handshake peak = free_before_handshake -
 * min_free_after_handshake when the minimum occurred during the handshake).
 */
static void pqc_log_heap(const char *where) {
  ESP_LOGI(TAG, "Heap [%s]: free=%u B, min_free_since_boot=%u B", where,
           (unsigned)esp_get_free_heap_size(),
           (unsigned)esp_get_minimum_free_heap_size());
}

static const char *REQUEST = "GET " DOWNLOAD_PATH " HTTP/1.0\r\n"
                             "Host: " WEB_SERVER ":" WEB_PORT "\r\n"
                             "User-Agent: ESP32-C5/PQC-TLS1.3\r\n"
                             "\r\n";

static void log_tls_failure_context(mbedtls_ssl_context *ssl, char *buf,
                                    size_t buf_len) {
  const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(ssl);
  uint32_t verify_flags = mbedtls_ssl_get_verify_result(ssl);

  ESP_LOGW(TAG, "Handshake failure context:");
#ifdef CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
  {
    int cid = mbedtls_ssl_get_ciphersuite_id_from_ssl(ssl);
    const char *csnm = mbedtls_ssl_get_ciphersuite(ssl);
    ESP_LOGW(TAG, "  Ciphersuite (may be unset mid-handshake): id=0x%x name=%s",
             (unsigned)cid, csnm != NULL ? csnm : "(none)");
  }
#endif
  ESP_LOGW(TAG, "  TLS version hint: %s", mbedtls_ssl_get_version(ssl));
  ESP_LOGW(TAG, "  Verify flags: 0x%08" PRIx32, verify_flags);

  if (verify_flags != 0) {
    bzero(buf, buf_len);
    mbedtls_x509_crt_verify_info(buf, buf_len, "    ! ", verify_flags);
    ESP_LOGW(TAG, "  Verify details:\n%s", buf);
  }

  if (peer == NULL) {
    ESP_LOGW(TAG, "  Peer certificate: not available");
    return;
  }

  bzero(buf, buf_len);
  mbedtls_x509_dn_gets(buf, buf_len, &peer->subject);
  ESP_LOGW(TAG, "  Peer subject: %s", buf);

  bzero(buf, buf_len);
  mbedtls_x509_dn_gets(buf, buf_len, &peer->issuer);
  ESP_LOGW(TAG, "  Peer issuer : %s", buf);
}

static void https_get_task(void *pvParameters) {
  (void)pvParameters;
  char buf[512];
  int ret;
  uint32_t flags;
  bool ssl_setup_done = false;

  pqc_log_stack_hwm("https_get_task entry");
  pqc_log_heap("https_get_task entry");

  mbedtls_ssl_context ssl;
  mbedtls_x509_crt cacert;
  mbedtls_ssl_config conf;
  mbedtls_net_context server_fd;

  mbedtls_ssl_init(&ssl);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_ssl_config_init(&conf);

#ifdef CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
  ESP_LOGI(TAG, "Initializing PSA Crypto...");
  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "psa_crypto_init failed: 0x%x", (unsigned int)status);
    abort();
  }
  ESP_LOGI(TAG, "PSA Crypto initialized.");
#endif

#if CONFIG_EXAMPLE_USE_TEST_CERTS
  ESP_LOGW(TAG, "TEST CERTS: skipping server hostname/IP verification");
  if ((ret = mbedtls_ssl_set_hostname(&ssl, NULL)) != 0) {
    ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
    abort();
  }
#else
  ESP_LOGI(TAG, "Verifying server cert identity: %s", TLS_SERVER_CERT_NAME);
  if ((ret = mbedtls_ssl_set_hostname(&ssl, TLS_SERVER_CERT_NAME)) != 0) {
    ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
    abort();
  }
#endif

  /* TLS client defaults */
  ESP_LOGI(TAG, "Setting up TLS configuration...");
  if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
    goto exit;
  }

  /* Without MLDSA65 the X.509 parser rejects an ML-DSA CA here, before any socket opens. */
  ret = mbedtls_x509_crt_parse(&cacert, ca_crt_start,
                               ca_crt_end - ca_crt_start);
  if (ret < 0) {
    ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x", -ret);
    goto exit;
  }
  ESP_LOGI(TAG, "CA cert loaded (%u bytes)",
           (unsigned)(ca_crt_end - ca_crt_start));

  /* Full X.509 chain + hostname verification (see mbedtls_ssl_set_hostname). */
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);

  /* Force TLS 1.3; the hybrid KEM groups exist only there. */
  mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);
  mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);

  ESP_LOGI(TAG, "TLS config: version=TLS1.3, authmode=VERIFY_REQUIRED");
  ESP_LOGI(TAG, "TLS profile:      %s (server: run_server.sh %s)",
           TLS_PROFILE_NAME, TLS_SERVER_MODE);
  ESP_LOGI(TAG, "Key exchange:     %s", TLS_KEM_NAME);
  ESP_LOGI(TAG, "Auth scheme:      %s", TLS_SIG_NAME);

#ifdef CONFIG_MBEDTLS_DEBUG
  mbedtls_esp_enable_debug_log(&conf, CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif

  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x", -ret);
    goto exit;
  }
  ssl_setup_done = true;

  mbedtls_net_init(&server_fd);

  /* Connect to the OpenSSL test server */
#if defined(CONFIG_EXAMPLE_TLS_PROFILE_FULL_PQC)
  ESP_LOGI(TAG,
           "CV_DEBUG target=%s:%s (match ESP tls13_cv/mldsa65_oqs with server "
           "-msgfile)",
           WEB_SERVER, WEB_PORT);
#endif
  ESP_LOGI(TAG, "Connecting to https://%s:%s ...", WEB_SERVER, WEB_PORT);
  if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER, WEB_PORT,
                                 MBEDTLS_NET_PROTO_TCP)) != 0) {
    ESP_LOGE(TAG, "mbedtls_net_connect returned -0x%x", -ret);
    goto exit;
  }
  ESP_LOGI(TAG, "TCP connection established.");
  pqc_log_stack_hwm("after TCP connect, before TLS handshake");
  pqc_log_heap("after TCP connect, before TLS handshake");

  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv,
                      NULL);

  /* ClientHello puts the profile's group first in supported_groups and sends its key_share. */
  ESP_LOGI(TAG, "Performing TLS 1.3 handshake...");
  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      continue;
    }
    if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
      /* TLS 1.3 NewSessionTicket post-handshake — not an error */
      continue;
    }
    ESP_LOGE(TAG, "TLS handshake failed: -0x%x", -ret);
    pqc_log_stack_hwm("TLS handshake error path");
    log_tls_failure_context(&ssl, buf, sizeof(buf));
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(TAG, "  Reason: %s", buf);
    goto exit;
  }

  pqc_log_stack_hwm("after TLS handshake (success)");
  pqc_log_heap("after TLS handshake (success)");
  ESP_LOGI(TAG, "*** TLS 1.3 handshake SUCCESS ***");
  ESP_LOGI(TAG, "  Cipher suite : %s", mbedtls_ssl_get_ciphersuite(&ssl));
  ESP_LOGI(TAG, "  TLS version  : %s", mbedtls_ssl_get_version(&ssl));
  ESP_LOGI(TAG, "  Profile      : %s (%s / %s)", TLS_PROFILE_NAME, TLS_KEM_NAME,
           TLS_SIG_NAME);
  {
    /* Leaf key size shows the real cert type: 256 = ECDSA-P256, 15616 = ML-DSA-65. */
    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&ssl);
    if (peer != NULL) {
      ESP_LOGI(TAG, "  Peer key     : %u bits",
               (unsigned)mbedtls_pk_get_bitlen(
                   &((mbedtls_x509_crt *)peer)->pk));
    }
  }

  if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
    ESP_LOGW(TAG, "Peer certificate verify flags (unexpected after success):");
    bzero(buf, sizeof(buf));
    mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
    ESP_LOGW(TAG, "%s", buf);
  } else {
    ESP_LOGI(TAG, "X.509 verify flags: none (chain + hostname OK)");
  }

  /* Send HTTP GET */
  ESP_LOGI(TAG, "Sending HTTP GET request...");
  size_t written_bytes = 0;
  do {
    ret =
        mbedtls_ssl_write(&ssl, (const unsigned char *)REQUEST + written_bytes,
                          strlen(REQUEST) - written_bytes);
    if (ret >= 0) {
      ESP_LOGI(TAG, "  %d bytes written", ret);
      written_bytes += ret;
    } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE &&
               ret != MBEDTLS_ERR_SSL_WANT_READ) {
      ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
      goto exit;
    }
  } while (written_bytes < strlen(REQUEST));

  /* Read HTTP response — application data proves record encryption works */
  ESP_LOGI(TAG,
           "Reading HTTP response (encrypted with AES-GCM/ChaCha-Poly)...");

  uint8_t *dl_buf = malloc(READ_BUF_SIZE);
  assert(dl_buf);
  char *hdr_buf = calloc(1, HTTP_HDR_BUF_SIZE);
  assert(hdr_buf);
  size_t hdr_len = 0;
  int content_length = -1;

  while (hdr_len < HTTP_HDR_BUF_SIZE - 1) {
    size_t space = HTTP_HDR_BUF_SIZE - 1 - hdr_len;
    size_t to_read = space < HTTP_HDR_READ_CHUNK ? space : HTTP_HDR_READ_CHUNK;
    ret = mbedtls_ssl_read(&ssl, (unsigned char *)hdr_buf + hdr_len, to_read);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
      continue;
    if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
      continue;
    if (ret <= 0)
      break;
    hdr_len += (size_t)ret;
    hdr_buf[hdr_len] = '\0';
    if (strstr(hdr_buf, "\r\n\r\n") != NULL)
      break;
    if (strstr(hdr_buf, "\n\n") != NULL)
      break;
  }
  if (hdr_len < HTTP_HDR_BUF_SIZE)
    hdr_buf[hdr_len] = '\0';

  bool headers_found = (hdr_len < HTTP_HDR_BUF_SIZE - 1);
  ESP_LOGI(TAG, "HTTP headers: %u bytes, terminator %s", (unsigned)hdr_len,
           headers_found ? "found" : "NOT FOUND (raw mode)");

  /* Parse Content-Length only if headers were found */
  if (headers_found) {
    char *cl = strcasestr(hdr_buf, "Content-Length:");
    if (cl)
      content_length = atoi(cl + 15);
  }
  ESP_LOGI(TAG, "Content-Length: %d", content_length);

#if CONFIG_EXAMPLE_HTTP_DOWNLOAD
  remove(DOWNLOAD_DEST);
  FILE *f = fopen(DOWNLOAD_DEST, "wb");
  assert(f);
#endif
  size_t body_bytes = 0;

  /* If no HTTP headers found, hdr_buf IS body data — write it first */
  if (!headers_found) {
#if CONFIG_EXAMPLE_HTTP_DOWNLOAD
    fwrite(hdr_buf, 1, hdr_len, f);
#endif
    body_bytes = hdr_len;
  }

  while (content_length < 0 || body_bytes < (size_t)content_length) {
    ret = mbedtls_ssl_read(&ssl, dl_buf, READ_BUF_SIZE);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
      continue;
    if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
      continue;
    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0)
      break;
    if (ret < 0) {
      ESP_LOGE(TAG, "ssl_read: -0x%x", -ret);
      break;
    }
#if CONFIG_EXAMPLE_HTTP_DOWNLOAD
    fwrite(dl_buf, 1, ret, f);
#endif
    body_bytes += ret;
  }

#if CONFIG_EXAMPLE_HTTP_DOWNLOAD
  fclose(f);
#endif
  free(hdr_buf);
  free(dl_buf);

  /* Normalize peer close notify — it is expected after body completes */
  if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
    ret = 0;

#if !CONFIG_EXAMPLE_HTTP_DOWNLOAD
  /* Validate-only: a -www status page differs per connection, so it is not stored or hashed. */
  ESP_LOGI(TAG, "Response body: %u bytes read and discarded (validate-only)",
           (unsigned)body_bytes);
  if (body_bytes == 0) {
    ESP_LOGE(TAG, "No application data received!");
  }
#else
  /* Verify */
  ESP_LOGI(TAG, "Download: %u / %d bytes → %s", (unsigned)body_bytes,
           content_length, DOWNLOAD_DEST);
  if (body_bytes > 0 &&
      (content_length < 0 || (int)body_bytes == content_length))
    ESP_LOGI(TAG, "File size OK (%u bytes)", (unsigned)body_bytes);
  else
    ESP_LOGE(TAG, "Size mismatch!");

  /* SHA-256 checksum of downloaded file — compare with: sha256sum testfile.bin
   */
  FILE *vf = fopen(DOWNLOAD_DEST, "rb");
  if (vf) {
    psa_hash_operation_t hash_op = PSA_HASH_OPERATION_INIT;
    psa_status_t ps = psa_crypto_init();
    if (ps != PSA_SUCCESS) {
      ESP_LOGE(TAG, "psa_crypto_init failed: %d", (int)ps);
      fclose(vf);
      goto exit;
    }
    ps = psa_hash_setup(&hash_op, PSA_ALG_SHA_256);
    if (ps != PSA_SUCCESS) {
      ESP_LOGE(TAG, "psa_hash_setup(SHA-256) failed: %d", (int)ps);
      fclose(vf);
      goto exit;
    }
    uint8_t chunk[256];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), vf)) > 0) {
      ps = psa_hash_update(&hash_op, chunk, n);
      if (ps != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_hash_update failed: %d", (int)ps);
        psa_hash_abort(&hash_op);
        fclose(vf);
        goto exit;
      }
    }
    fclose(vf);
    uint8_t digest[32];
    size_t digest_len = 0;
    ps = psa_hash_finish(&hash_op, digest, sizeof(digest), &digest_len);
    if (ps != PSA_SUCCESS || digest_len != sizeof(digest)) {
      ESP_LOGE(TAG, "psa_hash_finish failed: %d (len=%u)", (int)ps,
               (unsigned)digest_len);
      psa_hash_abort(&hash_op);
      goto exit;
    }
    char hex[65];
    for (int i = 0; i < 32; i++)
      snprintf(hex + i * 2, 3, "%02x", digest[i]);
    ESP_LOGI(TAG, "SHA-256(%s) = %s", DOWNLOAD_DEST, hex);
    if (strlen(EXPECTED_SHA256) == 64) {
      if (strcasecmp(hex, EXPECTED_SHA256) == 0) {
        ESP_LOGI(TAG, "SHA-256 matches the expected digest.");
      } else {
        ESP_LOGE(TAG, "SHA-256 MISMATCH, expected %s", EXPECTED_SHA256);
        ESP_LOGE(TAG, "  A `-www` server returns a per-connection status page, "
                      "not the file: use run_server.sh <mode> download");
      }
    }
  } else {
    ESP_LOGE(TAG, "Could not open %s for checksum", DOWNLOAD_DEST);
  }
#endif /* CONFIG_EXAMPLE_HTTP_DOWNLOAD */

  mbedtls_ssl_close_notify(&ssl);
  ESP_LOGI(TAG, "TLS session closed cleanly.");

exit:
  if (ssl_setup_done) {
    mbedtls_ssl_session_reset(&ssl);
  }
  mbedtls_net_free(&server_fd);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_x509_crt_free(&cacert);

  if (ret != 0) {
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(TAG, "Final error: -0x%x — %s", -ret, buf);
  }

  putchar('\n');
  pqc_log_stack_hwm("https_get_task end");
  pqc_log_heap("https_get_task end (session freed)");
  ESP_LOGI(TAG, "Task complete.");
  vTaskDelete(NULL); /* a FreeRTOS task function must never return */
}

void app_main(void) {
  ESP_LOGI(TAG, "ESP32-C5 TLS 1.3 client starting, profile: %s",
           TLS_PROFILE_NAME);
  ESP_LOGI(TAG, "  KEM : %s", TLS_KEM_NAME);
  ESP_LOGI(TAG, "  Auth: %s", TLS_SIG_NAME);

#if CONFIG_EXAMPLE_HTTP_DOWNLOAD
  ESP_LOGI(TAG, "Initializing LittleFS");

  esp_vfs_littlefs_conf_t conf = {
      .base_path = "/lfs",
      .partition_label = "storage",
      .format_if_mount_failed = true,
      .dont_mount = false,
  };

  ESP_ERROR_CHECK(esp_vfs_littlefs_register(&conf));
  size_t total = 0, used = 0;
  esp_littlefs_info("storage", &total, &used);
  ESP_LOGI(TAG, "LittleFS: total=%u used=%u", (unsigned)total, (unsigned)used);
#else
  ESP_LOGI(TAG, "Validate-only run (CONFIG_EXAMPLE_HTTP_DOWNLOAD=n): LittleFS not mounted");
#endif

  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());

  /* Connect to Wi-Fi — credentials set in menuconfig */
  esp_err_t err = example_connect();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Wi-Fi connect failed: %s", esp_err_to_name(err));
    ESP_LOGE(TAG, "  Check SSID/password in: idf.py menuconfig → "
                         "Example Connection Configuration");
    return;
  }

  xTaskCreate(https_get_task, TLS_LOG_TAG, 16 * 1024, NULL, 5, NULL);
}
