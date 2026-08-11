#!/bin/bash
# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# OpenSSL TLS 1.3 test servers for ESP32 hybrid-PQC interop (native OpenSSL
# 3.6+, no external providers needed — pure ML-DSA-65).
#
# Usage:  ./run_server.sh <mode> [download]
#
# Each mode pairs with one EXAMPLE_TLS_PROFILE_* choice in menuconfig, and pins
# -groups so a device offering the wrong group gets a handshake_failure instead
# of silently downgrading to a group you did not mean to measure.
#
#   ./run_server.sh test        — bundled test cert on port 8444 (pair with
#                                 CONFIG_EXAMPLE_USE_TEST_CERTS=y; any IP)
#   ./run_server.sh mldsa65     — full PQC, X25519MLKEM768 + ML-DSA-65, port 8444
#   ./run_server.sh hybrid-kem  — X25519MLKEM768 + ECDSA-P256, port 8445
#   ./run_server.sh ecdsa       — classical X25519 + ECDSA-P256, port 8443
#
# Add "download" as a second argument to any of those modes to serve real files
# from files/ instead of the generated status page:
#
#   ./run_server.sh ecdsa download
#   ./run_server.sh hybrid-kem download
#   ./run_server.sh mldsa65 download      (same as the legacy "download" mode)
#
# Without it the server runs `s_server -www`, which ignores the requested path
# and answers every GET with an HTML page describing that connection. That page
# is fine for validating a handshake, but its length and contents differ per
# connection, so a SHA-256 of what the device stores will never match
# files/tls_testfile.bin. Pair "download" with CONFIG_EXAMPLE_HTTP_DOWNLOAD=y.
#
# Optional: capture TLS message trace for one ESP run (match Device tls13_cv lines):
#   CV_MSGFILE=/tmp/esp_tls.msg ./run_server.sh mldsa65
# Optional: add OpenSSL's -msg -trace record dump:
#   TRACE=1 ./run_server.sh mldsa65 download

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/../certs"
FILES_DIR="${SCRIPT_DIR}/../files"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

MODE="${1:-mldsa65}"
SERVE="${2:-www}"

case "$MODE" in

  test)
    # Bundled test certificate (certs/test/), generic identity. Pair with
    # CONFIG_EXAMPLE_USE_TEST_CERTS=y: the device validates the chain against the
    # bundled test CA but skips the hostname/IP check, so this works at any IP.
    CERT_SUBDIR="test"
    PORT=8444
    TLS_GROUPS="X25519MLKEM768"
    ;;

  mldsa65)
    # Pure ML-DSA-65, no external provider needed, native OpenSSL 3.6+
    CERT_SUBDIR="mldsa65"
    PORT=8444
    TLS_GROUPS="X25519MLKEM768"
    ;;

  hybrid-kem)
    # PQC key exchange with a classical ECDSA certificate: the profile large
    # deployments ship today, while the public PKI has not migrated to ML-DSA.
    CERT_SUBDIR="ecdsa"
    PORT=8445
    TLS_GROUPS="X25519MLKEM768"
    ;;

  ecdsa)
    # Classical baseline. -groups is pinned to classical curves on purpose:
    # OpenSSL's default list includes X25519MLKEM768, so without this the
    # "baseline" happily negotiates a hybrid handshake and the footprint and
    # timing numbers you collect are not classical at all.
    CERT_SUBDIR="ecdsa"
    PORT=8443
    TLS_GROUPS="X25519:P-256"
    ;;

  download)
    # Kept as an alias for the full PQC file server: same as "mldsa65 download".
    CERT_SUBDIR="mldsa65"
    PORT=8444
    TLS_GROUPS="X25519MLKEM768"
    SERVE="download"
    ;;

  *)
    echo "Usage: $0 [test|mldsa65|hybrid-kem|ecdsa] [download]"
    exit 1
    ;;
esac

case "$SERVE" in
  www)
    # -www answers every GET with a generated status page, not a file.
    SERVE_ARGS=(-www)
    ;;
  download)
    # -HTTP serves real files, relative to the working directory.
    TESTFILE="${FILES_DIR}/tls_testfile.bin"
    if [ ! -f "$TESTFILE" ]; then
      echo "[server] ERROR: $TESTFILE not found."
      echo "[server] Generate it once with:"
      echo "  python3 -c \"import sys; sys.stdout.buffer.write(bytes(i % 256 for i in range(102400)))\" > files/tls_testfile.bin"
      exit 1
    fi
    echo "[server] Serving ${FILES_DIR} via openssl s_server -HTTP on port ${PORT}"
    echo "[server] Expected SHA-256 of tls_testfile.bin:"
    (cd "${FILES_DIR}" && (sha256sum tls_testfile.bin 2>/dev/null || shasum -a 256 tls_testfile.bin)) || true
    cd "${FILES_DIR}"
    SERVE_ARGS=(-HTTP)
    ;;
  *)
    echo "Usage: $0 [test|mldsa65|hybrid-kem|ecdsa] [download]"
    exit 1
    ;;
esac

# exec so this script's PID is the server: killing it releases the port, with no
# wrapper process left holding a live child.
exec ${OPENSSL_BIN} s_server \
  -cert "${CERT_DIR}/${CERT_SUBDIR}/test_server.crt" \
  -key  "${CERT_DIR}/${CERT_SUBDIR}/test_server.key" \
  -CAfile "${CERT_DIR}/${CERT_SUBDIR}/test_ca.crt" \
  -port "${PORT}" \
  -tls1_3 \
  "${SERVE_ARGS[@]}" \
  -groups "${TLS_GROUPS}" \
  ${TRACE:+-msg -trace} \
  ${CV_MSGFILE:+-msgfile "$CV_MSGFILE"}
