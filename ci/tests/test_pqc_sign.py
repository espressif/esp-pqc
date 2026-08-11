# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
"""
Unit tests for examples/pqc_boot_verify/scripts/pqc_sign.py — the ML-DSA-65
Secure Boot V2 signing tool.

These cover the parts that do not need espsecure or a real RSA/ECDSA PEM key:
  * PQC signature-block build/parse round trip and its CRC integrity check
  * image-content / signature-sector slicing helpers
  * C header generation
  * keygen, selftest and a full sign-block verify round trip (via pqcrypto)

Run:
    cd tools && python -m unittest discover -s tests -p "test_*.py" -v
"""
import importlib.util
import os
import struct
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PQC_SIGN_PATH = os.path.join(
    REPO_ROOT, "examples", "pqc_boot_verify", "scripts", "pqc_sign.py"
)


def _load_pqc_sign():
    spec = importlib.util.spec_from_file_location("pqc_sign", PQC_SIGN_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ps = _load_pqc_sign()


class Args:
    """Minimal argparse.Namespace stand-in for the cmd_* functions."""
    def __init__(self, **kw):
        self.__dict__.update(kw)


class TestSignatureBlock(unittest.TestCase):
    def setUp(self):
        self.image_hash = bytes(range(32))
        self.pk = bytes([0xAB]) * ps.ML_DSA_65_PK_LEN
        self.sig = bytes([0xCD]) * 3200  # <= PQC_MAX_SIG_LEN

    def test_build_block_is_8kb(self):
        block = ps.build_pqc_signature_block(self.image_hash, self.sig, self.pk)
        self.assertEqual(len(block), ps.PQC_SIG_BLOCK_SIZE)
        self.assertEqual(block[0], ps.PQC_MAGIC)
        self.assertEqual(block[1], ps.PQC_VERSION)
        self.assertEqual(block[2], ps.PQC_ALG_ML_DSA_65)

    def test_build_parse_roundtrip(self):
        block = ps.build_pqc_signature_block(self.image_hash, self.sig, self.pk)
        h, pk, sig, alg = ps.parse_pqc_signature_block(block)
        self.assertEqual(h, self.image_hash)
        self.assertEqual(pk, self.pk)
        self.assertEqual(sig, self.sig)
        self.assertEqual(alg, ps.PQC_ALG_ML_DSA_65)

    def test_crc_detects_tampering(self):
        block = bytearray(ps.build_pqc_signature_block(self.image_hash, self.sig, self.pk))
        # Flip a byte inside the CRC-covered region (the image digest).
        block[10] ^= 0xFF
        with self.assertRaises(ValueError):
            ps.parse_pqc_signature_block(bytes(block))

    def test_bad_magic_rejected(self):
        block = bytearray(ps.build_pqc_signature_block(self.image_hash, self.sig, self.pk))
        block[0] = 0xE7  # ECDSA magic, not PQC
        with self.assertRaises(ValueError):
            ps.parse_pqc_signature_block(bytes(block))

    def test_oversize_inputs_asserted(self):
        with self.assertRaises(AssertionError):
            ps.build_pqc_signature_block(self.image_hash,
                                         bytes(ps.PQC_MAX_SIG_LEN + 1), self.pk)


class TestImageHelpers(unittest.TestCase):
    def test_pad_to_sector(self):
        self.assertEqual(len(ps.pad_to_sector(b"x" * 10)), ps.SECTOR_SIZE)
        exact = b"y" * ps.SECTOR_SIZE
        self.assertEqual(ps.pad_to_sector(exact), exact)  # already aligned

    def test_extract_content_and_sector(self):
        content = b"A" * (ps.SECTOR_SIZE * 2)
        sig_sector = b"B" * ps.SECTOR_SIZE
        signed = content + sig_sector
        self.assertEqual(ps.extract_image_content(signed), content)
        self.assertEqual(ps.extract_sig_sector(signed), sig_sector)

    def test_strip_pqc_sector(self):
        content = b"C" * (ps.SECTOR_SIZE * 2)
        pqc = ps.build_pqc_signature_block(bytes(32), b"s" * 100,
                                           bytes(ps.ML_DSA_65_PK_LEN))
        self.assertEqual(ps.strip_pqc_sector(content + pqc), content)
        # No PQC sector present -> unchanged.
        self.assertEqual(ps.strip_pqc_sector(content), content)

    def test_count_sig_blocks_none(self):
        self.assertEqual(ps.count_sig_blocks(b"\x00" * ps.SECTOR_SIZE), 0)


class TestHeaderGeneration(unittest.TestCase):
    def test_header_has_key_and_length(self):
        with tempfile.TemporaryDirectory() as d:
            pk_path = os.path.join(d, "pk.bin")
            hdr_path = os.path.join(d, "pqc_public_key.h")
            with open(pk_path, "wb") as f:
                f.write(bytes(ps.ML_DSA_65_PK_LEN))
            rc = ps.cmd_header(Args(pk=pk_path, output=hdr_path))
            self.assertEqual(rc, 0)
            text = open(hdr_path).read()
            self.assertIn(f"#define PQC_PUBLIC_KEY_LEN {ps.ML_DSA_65_PK_LEN}", text)
            self.assertIn("static const uint8_t pqc_public_key", text)

    def test_header_rejects_wrong_size_key(self):
        with tempfile.TemporaryDirectory() as d:
            pk_path = os.path.join(d, "pk.bin")
            with open(pk_path, "wb") as f:
                f.write(bytes(16))  # wrong size
            rc = ps.cmd_header(Args(pk=pk_path, output=os.path.join(d, "h.h")))
            self.assertEqual(rc, 1)


class TestPqcryptoRoundTrips(unittest.TestCase):
    """Paths that use the pqcrypto ML-DSA-65 backend."""

    def test_selftest(self):
        self.assertEqual(ps.cmd_selftest(Args()), 0)

    def test_keygen_writes_correct_sizes(self):
        with tempfile.TemporaryDirectory() as d:
            rc = ps.cmd_keygen(Args(keys_dir=d, force=False))
            self.assertEqual(rc, 0)
            pk = open(os.path.join(d, "pqc_ml_dsa_65_public.bin"), "rb").read()
            sk = open(os.path.join(d, "pqc_ml_dsa_65_secret.bin"), "rb").read()
            self.assertEqual(len(pk), ps.ML_DSA_65_PK_LEN)
            self.assertEqual(len(sk), ps.ML_DSA_65_SK_LEN)

    def test_verify_accepts_valid_block_and_rejects_tamper(self):
        pk, sk = ps.ml_dsa_65_keygen()

        # Fake signed image: [content | 4KB sig_sector], PQC signs SHA-256 of it.
        content = b"\xa5" * (ps.SECTOR_SIZE * 2)
        sig_sector = b"\x5a" * ps.SECTOR_SIZE
        signed = content + sig_sector
        digest = ps.sha256_digest(signed)
        pqc_sig = ps.ml_dsa_65_sign(sk, digest)
        pqc_block = ps.build_pqc_signature_block(digest, pqc_sig, pk)
        final = signed + pqc_block

        with tempfile.TemporaryDirectory() as d:
            bin_path = os.path.join(d, "app.signed.bin")
            pk_path = os.path.join(d, "pk.bin")
            with open(bin_path, "wb") as f:
                f.write(final)
            with open(pk_path, "wb") as f:
                f.write(pk)

            self.assertEqual(ps.cmd_verify(Args(binary=bin_path, pk=pk_path)), 0)

            # Corrupt one byte of the image content -> hash mismatch -> fail.
            bad = bytearray(final)
            bad[0] ^= 0xFF
            with open(bin_path, "wb") as f:
                f.write(bytes(bad))
            self.assertEqual(ps.cmd_verify(Args(binary=bin_path, pk=pk_path)), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
