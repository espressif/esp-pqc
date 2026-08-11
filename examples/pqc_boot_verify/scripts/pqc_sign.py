#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
"""
pqc_sign.py - PQC (ML-DSA-65) signing pipeline for ESP32 Secure Boot V2.

Appends an 8KB PQC signature block after the standard 4KB RSA/ECDSA V2 signature sector.
The block format matches pqc_sig_block_t defined in pqc_sig_block.h.

PQC signs SHA-256(image_content + sig_sector), i.e. the entire image INCLUDING
the RSA/ECDSA V2 signature block.  This binds the classical signature into PQC coverage.
Supports both RSA-PSS 3072-bit and ECDSA V2 signing keys (auto-detected from the
key file). All shipped pqc_boot_verify targets (C3/C5/C6) use RSA-3072.

Uses the pqcrypto Python library (github.com/backbone-hq/pqcrypto) for ML-DSA-65
operations — no external C binary required.

Usage:
    pqc_sign.py keygen [--keys-dir DIR]
    pqc_sign.py sign <binary> --signing-key <pem> --pqc-key <sk_bin> --pqc-pk <pk_bin> [--output <out>]
    pqc_sign.py header --pk <pk_bin> [--output <header.h>]
    pqc_sign.py verify <binary> --pk <pk_bin>
    pqc_sign.py selftest
"""

import argparse
import hashlib
import os
import struct
import sys
import tempfile
import zlib

from pqcrypto.sign import ml_dsa_65 as _ml_dsa_65

ml_dsa_65_keygen = getattr(_ml_dsa_65, "keygen", None) or _ml_dsa_65.generate_keypair
ml_dsa_65_sign = _ml_dsa_65.sign


def ml_dsa_65_verify(public_key, message, signature):
    """True if the signature is valid, False otherwise. Never raises."""
    try:
        result = _ml_dsa_65.verify(public_key, message, signature)
    except Exception:
        return False
    return True if result is None else bool(result)


SECTOR_SIZE = 4096  # Flash sector size

PQC_MAGIC            = 0xE8     # Magic byte (distinguishes from ECDSA V2's 0xE7)
PQC_VERSION          = 0x01     # Block format version
PQC_ALG_ML_DSA_44    = 0x01     # pqc_algorithm_id_t values
PQC_ALG_ML_DSA_65    = 0x02
PQC_ALG_ML_DSA_87    = 0x03
PQC_SIG_BLOCK_SIZE   = 8192    # 8KB = 2 flash sectors
PQC_IMAGE_DIGEST_LEN = 32      # SHA-256
PQC_MAX_PK_LEN       = 2592    # ML-DSA-87 max (struct uses fixed max-size arrays)
PQC_MAX_SIG_LEN      = 4627    # ML-DSA-87 max

# ML-DSA-65 specific sizes
ML_DSA_65_PK_LEN  = 1952
ML_DSA_65_SK_LEN  = 4032
ML_DSA_65_SIG_LEN = 3309

# Offset of block_crc within the struct (everything before it is CRC-covered)
PQC_CRC_COVER_LEN = 4 + PQC_IMAGE_DIGEST_LEN + 8 + PQC_MAX_PK_LEN + PQC_MAX_SIG_LEN  # 7263

# ECDSA signature block constants (from espsecure)
ECDSA_SIG_BLOCK_SIZE = 1216
ECDSA_SIG_BLOCK_MAGIC = 0xE7
ECDSA_SIG_BLOCK_MAX_COUNT = 3

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def build_pqc_signature_block(image_hash: bytes, signature: bytes,
                              public_key: bytes,
                              algorithm_id: int = PQC_ALG_ML_DSA_65,
                              flags: int = 0x00) -> bytes:
    """Build an 8KB PQC signature block matching pqc_sig_block_t.

    Byte layout:
      0       1   magic_byte       (0xE8)
      1       1   version          (0x01)
      2       1   algorithm_id
      3       1   flags
      4-35   32   image_digest     (SHA-256 of image + ECDSA sector)
      36-39   4   public_key_len   (uint32 LE)
      40-43   4   signature_len    (uint32 LE)
      44-2635 2592 public_key      (zero-padded to PQC_MAX_PK_LEN)
      2636-7262 4627 signature     (zero-padded to PQC_MAX_SIG_LEN)
      7263-7266 4  block_crc       (CRC-32-LE of bytes [0..7263))
      7267-8191 925 _padding       (zeros)
    """
    assert len(image_hash) == PQC_IMAGE_DIGEST_LEN
    assert len(public_key) <= PQC_MAX_PK_LEN
    assert len(signature) <= PQC_MAX_SIG_LEN

    # Header (4 bytes)
    block = struct.pack("<BBBB", PQC_MAGIC, PQC_VERSION, algorithm_id, flags)

    # Image digest (32 bytes)
    block += image_hash

    # Actual lengths (8 bytes)
    block += struct.pack("<II", len(public_key), len(signature))

    # Public key zero-padded to max
    block += public_key + b"\x00" * (PQC_MAX_PK_LEN - len(public_key))

    # Signature zero-padded to max
    block += signature + b"\x00" * (PQC_MAX_SIG_LEN - len(signature))

    # CRC-32-LE over everything so far (should be PQC_CRC_COVER_LEN = 7263 bytes)
    assert len(block) == PQC_CRC_COVER_LEN, \
        f"CRC cover length mismatch: {len(block)} != {PQC_CRC_COVER_LEN}"
    crc = zlib.crc32(block) & 0xFFFFFFFF
    block += struct.pack("<I", crc)

    # Zero-pad to 8KB
    block += b"\x00" * (PQC_SIG_BLOCK_SIZE - len(block))

    assert len(block) == PQC_SIG_BLOCK_SIZE, \
        f"PQC block size mismatch: {len(block)} != {PQC_SIG_BLOCK_SIZE}"
    return block


def parse_pqc_signature_block(block_data: bytes):
    """Parse and validate an 8KB PQC signature block.

    Returns (image_hash, public_key, signature, algorithm_id) or raises.
    """
    if len(block_data) < PQC_SIG_BLOCK_SIZE:
        raise ValueError(f"PQC block too small: {len(block_data)} < {PQC_SIG_BLOCK_SIZE}")

    magic, version, alg_id, flags = struct.unpack_from("<BBBB", block_data, 0)

    if magic != PQC_MAGIC:
        raise ValueError(f"Bad PQC magic: 0x{magic:02X} (expected 0x{PQC_MAGIC:02X})")
    if version != PQC_VERSION:
        raise ValueError(f"Bad PQC version: 0x{version:02X}")
    if alg_id not in (PQC_ALG_ML_DSA_44, PQC_ALG_ML_DSA_65, PQC_ALG_ML_DSA_87):
        raise ValueError(f"Unknown algorithm: 0x{alg_id:02X}")

    image_hash = block_data[4:4 + PQC_IMAGE_DIGEST_LEN]
    pk_len, sig_len = struct.unpack_from("<II", block_data, 36)

    if pk_len > PQC_MAX_PK_LEN:
        raise ValueError(f"Public key length {pk_len} exceeds max {PQC_MAX_PK_LEN}")
    if sig_len > PQC_MAX_SIG_LEN:
        raise ValueError(f"Signature length {sig_len} exceeds max {PQC_MAX_SIG_LEN}")

    public_key = block_data[44:44 + pk_len]
    signature = block_data[44 + PQC_MAX_PK_LEN:44 + PQC_MAX_PK_LEN + sig_len]

    # Validate CRC at fixed offset PQC_CRC_COVER_LEN
    stored_crc = struct.unpack_from("<I", block_data, PQC_CRC_COVER_LEN)[0]
    computed_crc = zlib.crc32(block_data[:PQC_CRC_COVER_LEN]) & 0xFFFFFFFF
    if stored_crc != computed_crc:
        raise ValueError(f"CRC mismatch: stored=0x{stored_crc:08X} computed=0x{computed_crc:08X}")

    return image_hash, public_key, signature, alg_id



def pad_to_sector(data: bytes) -> bytes:
    """Pad data with 0xFF to next SECTOR_SIZE boundary."""
    remainder = len(data) % SECTOR_SIZE
    if remainder == 0:
        return data
    return data + b"\xff" * (SECTOR_SIZE - remainder)


def count_sig_blocks(data: bytes) -> int:
    """Count valid RSA/ECDSA V2 signature blocks at the end of the image.

    Both RSA and ECDSA V2 use ets_secure_boot_sig_block_t with magic byte 0xE7.
    """
    if len(data) < SECTOR_SIZE:
        return 0
    # The last sector should be the signature sector
    sig_sector_start = len(data) - SECTOR_SIZE
    count = 0
    for i in range(ECDSA_SIG_BLOCK_MAX_COUNT):
        offset = sig_sector_start + i * ECDSA_SIG_BLOCK_SIZE
        if offset + ECDSA_SIG_BLOCK_SIZE > len(data):
            break
        if data[offset] == ECDSA_SIG_BLOCK_MAGIC:
            # Verify CRC
            stored_crc = struct.unpack_from("<I", data, offset + ECDSA_SIG_BLOCK_SIZE - 20)[0]
            computed_crc = zlib.crc32(data[offset:offset + ECDSA_SIG_BLOCK_SIZE - 20]) & 0xFFFFFFFF
            if stored_crc == computed_crc:
                count += 1
    return count


def extract_image_content(data: bytes) -> bytes:
    """Extract image content (everything before the RSA/ECDSA V2 signature sector)."""
    if len(data) < SECTOR_SIZE:
        raise ValueError("File too small to contain a signature sector")
    return data[:-SECTOR_SIZE]


def extract_sig_sector(data: bytes) -> bytes:
    """Extract the 4KB RSA/ECDSA V2 signature sector (last sector before PQC block)."""
    if len(data) < SECTOR_SIZE:
        raise ValueError("File too small to contain a signature sector")
    return data[-SECTOR_SIZE:]


def strip_pqc_sector(data: bytes) -> bytes:
    """Strip trailing 8KB PQC sector if present."""
    if len(data) < PQC_SIG_BLOCK_SIZE + SECTOR_SIZE:
        return data
    # Check if the magic byte at the start of the last 8KB is PQC
    if data[-PQC_SIG_BLOCK_SIZE] == PQC_MAGIC:
        return data[:-PQC_SIG_BLOCK_SIZE]
    return data



def cmd_keygen(args):
    """Generate ML-DSA-65 keypair."""
    keys_dir = args.keys_dir
    os.makedirs(keys_dir, exist_ok=True)

    pk_path = os.path.join(keys_dir, "pqc_ml_dsa_65_public.bin")
    sk_path = os.path.join(keys_dir, "pqc_ml_dsa_65_secret.bin")

    if os.path.exists(pk_path) and not args.force:
        print(f"Keys already exist at {keys_dir}. Use --force to overwrite.")
        return 1

    pk, sk = ml_dsa_65_keygen()
    with open(pk_path, "wb") as f:
        f.write(pk)
    with open(sk_path, "wb") as f:
        f.write(sk)

    print(f"Generated ML-DSA-65 keypair (via pqcrypto):")
    print(f"  Public key:  {pk_path} ({len(pk)} bytes)")
    print(f"  Secret key:  {sk_path} ({len(sk)} bytes)")
    return 0


def cmd_sign(args):
    """Sign a binary with RSA/ECDSA V2 + PQC (ML-DSA-65).

    Flow:
      1. Read input binary, strip any existing PQC sector
      2. If not already signed, sign with espsecure (RSA-PSS or ECDSA V2, auto-detected from key)
      3. Compute SHA-256 of (image_content + sig_sector) — the full signed image
      4. Sign that hash with ML-DSA-65 using ml_dsa_tool
      5. Build 8KB PQC signature block containing hash + signature + public key
      6. Append PQC block after RSA/ECDSA V2 sector
      7. Write final output: [image_content | sig_sector(4KB) | PQC_block(8KB)]
    """
    binary_path = args.binary
    ecdsa_key = args.signing_key
    pqc_sk = args.pqc_key
    pqc_pk_path = args.pqc_pk
    output_path = args.output or binary_path

    # Read PQC public key
    with open(pqc_pk_path, "rb") as f:
        pqc_pk = f.read()
    if len(pqc_pk) != ML_DSA_65_PK_LEN:
        print(f"Error: PQC public key size {len(pqc_pk)} != expected {ML_DSA_65_PK_LEN}")
        return 1

    # Read input binary
    with open(binary_path, "rb") as f:
        raw_data = f.read()

    print(f"Input: {binary_path} ({len(raw_data)} bytes)")

    # Strip any existing PQC sector
    raw_data = strip_pqc_sector(raw_data)

    # Check if already RSA/ECDSA V2-signed (has signature sector)
    has_sig = count_sig_blocks(raw_data) > 0

    if has_sig:
        print("RSA/ECDSA V2 signature block already present, using existing.")
        signed_data = raw_data
    else:
        # Step 1: Pad to sector boundary
        padded = pad_to_sector(raw_data)
        if len(padded) != len(raw_data):
            print(f"Padded image from {len(raw_data)} to {len(padded)} bytes (sector alignment)")

        # Step 2: Sign with RSA-PSS or ECDSA V2 using espsecure (auto-detects key type)
        print(f"Signing with key: {ecdsa_key}")
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp_in:
            tmp_in.write(padded)
            tmp_in_path = tmp_in.name

        tmp_out_path = tmp_in_path + ".signed"
        try:
            import espsecure
            with open(tmp_in_path, "rb") as datafile:
                espsecure.sign_secure_boot_v2(
                    keyfile=[open(ecdsa_key, "rb")],
                    output=tmp_out_path,
                    append_signatures=False,
                    hsm=False,
                    hsm_config=None,
                    pub_key=[],
                    signature=[],
                    datafile=datafile,
                )
            with open(tmp_out_path, "rb") as f:
                signed_data = f.read()
            print(f"RSA/ECDSA V2 signed: {len(signed_data)} bytes")
        finally:
            os.unlink(tmp_in_path)
            if os.path.exists(tmp_out_path):
                os.unlink(tmp_out_path)

    # signed_data = image_content + sig_sector(4KB)
    image_content = extract_image_content(signed_data)
    sig_sector = extract_sig_sector(signed_data)

    # Step 3: Compute SHA-256 of entire image INCLUDING RSA/ECDSA V2 sector
    # PQC covers: image_content + sig_sector (binds classical signature into PQC coverage)
    pqc_message = signed_data  # = image_content + sig_sector
    image_hash = sha256_digest(pqc_message)
    print(f"PQC digest (image+sig_sector): {image_hash.hex()}")
    print(f"  Image content: {len(image_content)} bytes")
    print(f"  Sig sector:    {len(sig_sector)} bytes")
    print(f"  Total hashed:  {len(pqc_message)} bytes")

    # Step 4: Sign the hash with ML-DSA-65 using pqcrypto
    with open(pqc_sk, "rb") as f:
        sk_bytes = f.read()
    if len(sk_bytes) != ML_DSA_65_SK_LEN:
        print(f"Error: PQC secret key size {len(sk_bytes)} != expected {ML_DSA_65_SK_LEN}")
        return 1

    pqc_signature = ml_dsa_65_sign(sk_bytes, image_hash)
    print(f"ML-DSA-65 signing: OK (pqcrypto)")
    print(f"PQC signature size: {len(pqc_signature)} bytes")

    # Step 5: Build 8KB PQC signature block
    pqc_sector = build_pqc_signature_block(image_hash, pqc_signature, pqc_pk)

    # Step 6: Append PQC sector after RSA/ECDSA V2 sector
    final_data = signed_data + pqc_sector
    print(f"Final image: {len(final_data)} bytes "
          f"(image={len(image_content)}, sig_sector={SECTOR_SIZE}, pqc_sector={PQC_SIG_BLOCK_SIZE})")

    # Step 7: Write output
    with open(output_path, "wb") as f:
        f.write(final_data)
    print(f"Output written to: {output_path}")
    return 0


def cmd_header(args):
    """Generate C header with PQC public key."""
    pk_path = args.pk
    output_path = args.output

    with open(pk_path, "rb") as f:
        pk_data = f.read()

    if len(pk_data) != ML_DSA_65_PK_LEN:
        print(f"Error: public key size {len(pk_data)} != expected {ML_DSA_65_PK_LEN}")
        return 1

    # Format as C array
    lines = []
    lines.append("/* Auto-generated by pqc_sign.py - DO NOT EDIT */")
    lines.append(f"#ifndef PQC_PUBLIC_KEY_H")
    lines.append(f"#define PQC_PUBLIC_KEY_H")
    lines.append("")
    lines.append("#include <stdint.h>")
    lines.append("#include <stddef.h>")
    lines.append("")
    lines.append(f"#define PQC_PUBLIC_KEY_LEN {ML_DSA_65_PK_LEN}")
    lines.append("")
    lines.append(f"static const uint8_t pqc_public_key[PQC_PUBLIC_KEY_LEN] = {{")

    for i in range(0, len(pk_data), 16):
        chunk = pk_data[i:i + 16]
        hex_vals = ", ".join(f"0x{b:02X}" for b in chunk)
        comma = "," if i + 16 < len(pk_data) else ""
        lines.append(f"    {hex_vals}{comma}")

    lines.append("};")
    lines.append("")
    lines.append("#endif /* PQC_PUBLIC_KEY_H */")
    lines.append("")

    header_content = "\n".join(lines)

    with open(output_path, "w") as f:
        f.write(header_content)

    print(f"Generated public key header: {output_path}")
    print(f"  Key size: {ML_DSA_65_PK_LEN} bytes")
    return 0


def cmd_verify(args):
    """Verify PQC signature block of a signed binary."""
    binary_path = args.binary
    pk_path = args.pk

    with open(binary_path, "rb") as f:
        data = f.read()

    # Last 8KB should be PQC block
    if len(data) < PQC_SIG_BLOCK_SIZE + SECTOR_SIZE:
        print("Error: file too small to contain RSA/ECDSA V2 + PQC sectors")
        return 1

    pqc_block = data[-PQC_SIG_BLOCK_SIZE:]
    try:
        stored_hash, public_key, signature, alg_id = parse_pqc_signature_block(pqc_block)
    except ValueError as e:
        print(f"Error: {e}")
        return 1

    alg_names = {PQC_ALG_ML_DSA_44: "ML-DSA-44", PQC_ALG_ML_DSA_65: "ML-DSA-65",
                 PQC_ALG_ML_DSA_87: "ML-DSA-87"}
    print(f"PQC block found: alg={alg_names.get(alg_id, '?')}, pk_len={len(public_key)}, sig_len={len(signature)}")
    print(f"Stored hash: {stored_hash.hex()}")

    # PQC digest covers image_content + sig_sector (everything before PQC block)
    signed_data = data[:-PQC_SIG_BLOCK_SIZE]  # strip 8KB PQC sector
    computed_hash = sha256_digest(signed_data)
    print(f"Computed hash (image+sig_sector): {computed_hash.hex()}")
    print(f"  Hashed region: {len(signed_data)} bytes")

    if stored_hash != computed_hash:
        print("FAIL: image hash mismatch")
        return 1
    print("Image hash: MATCH")

    # Verify ML-DSA-65 signature using pqcrypto
    with open(pk_path, "rb") as f:
        pk_bytes = f.read()
    if len(pk_bytes) != ML_DSA_65_PK_LEN:
        print(f"Error: public key size {len(pk_bytes)} != expected {ML_DSA_65_PK_LEN}")
        return 1

    try:
        ok = ml_dsa_65_verify(pk_bytes, stored_hash, signature)
        if ok:
            print("ML-DSA-65 verification: PASS (pqcrypto)")
            return 0
        else:
            print("ML-DSA-65 verification: FAILED")
            return 1
    except Exception as e:
        print(f"ML-DSA-65 verification: FAILED ({e})")
        return 1


def cmd_selftest(_args):
    """Run a quick round-trip keygen/sign/verify sanity check."""
    print("ML-DSA-65 self-test (pqcrypto)...")

    pk, sk = ml_dsa_65_keygen()
    print(f"  keygen:  pk={len(pk)}B  sk={len(sk)}B  [expected {ML_DSA_65_PK_LEN}/{ML_DSA_65_SK_LEN}]")
    assert len(pk) == ML_DSA_65_PK_LEN and len(sk) == ML_DSA_65_SK_LEN, "keygen size mismatch"

    test_msg = b"ESP32 PQC self-test message"
    sig = ml_dsa_65_sign(sk, test_msg)
    print(f"  sign:    sig={len(sig)}B  [expected {ML_DSA_65_SIG_LEN}]")
    assert len(sig) == ML_DSA_65_SIG_LEN, "signature size mismatch"

    ok = ml_dsa_65_verify(pk, test_msg, sig)
    assert ok, "verify returned False"
    print("  verify:  PASS")

    # Tamper test — verify must reject a corrupted signature
    tampered = bytearray(sig)
    tampered[0] ^= 0xFF
    tamper_rejected = False
    try:
        result = ml_dsa_65_verify(pk, test_msg, bytes(tampered))
        if not result:
            tamper_rejected = True
    except Exception:
        tamper_rejected = True
    if not tamper_rejected:
        print("  tamper:  FAIL (accepted corrupted signature!)")
        return 1
    print("  tamper:  PASS (correctly rejected)")

    # Test with a 32-byte hash (same as signing pipeline)
    import hashlib
    test_hash = hashlib.sha256(b"dummy image data").digest()
    sig2 = ml_dsa_65_sign(sk, test_hash)
    ok2 = ml_dsa_65_verify(pk, test_hash, sig2)
    assert ok2, "hash-message verify failed"
    print("  hash-msg verify: PASS")

    print("Self-test PASSED")
    return 0



def main():
    parser = argparse.ArgumentParser(
        description="PQC (ML-DSA-65) signing pipeline for ESP32 Secure Boot V2"
    )
    sub = parser.add_subparsers(dest="command")

    # keygen
    p_keygen = sub.add_parser("keygen", help="Generate ML-DSA-65 keypair")
    p_keygen.add_argument("--keys-dir", default=os.path.join(SCRIPT_DIR, "..", "keys"),
                          help="Directory to store keys (default: ../keys)")
    p_keygen.add_argument("--force", action="store_true",
                          help="Overwrite existing keys")

    # sign
    p_sign = sub.add_parser("sign", help="Sign binary with RSA/ECDSA V2 + PQC")
    p_sign.add_argument("binary", help="Input binary to sign")
    p_sign.add_argument("--signing-key", required=True,
                        help="RSA or ECDSA private key (.pem) — auto-detected from key type")
    p_sign.add_argument("--pqc-key", required=True,
                        help="ML-DSA-65 secret key (.bin)")
    p_sign.add_argument("--pqc-pk", required=True,
                        help="ML-DSA-65 public key (.bin) — embedded in PQC signature block")
    p_sign.add_argument("--output", "-o",
                        help="Output path (default: overwrite input)")

    # header
    p_header = sub.add_parser("header", help="Generate C header with PQC public key")
    p_header.add_argument("--pk", required=True,
                          help="ML-DSA-65 public key (.bin)")
    p_header.add_argument("--output", "-o", required=True,
                          help="Output header file path")

    # verify
    p_verify = sub.add_parser("verify", help="Verify PQC signature of a signed binary")
    p_verify.add_argument("binary", help="Signed binary to verify")
    p_verify.add_argument("--pk", required=True,
                          help="ML-DSA-65 public key (.bin)")

    # selftest
    sub.add_parser("selftest", help="Quick ML-DSA-65 keygen/sign/verify round-trip test")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    commands = {
        "keygen": cmd_keygen,
        "sign": cmd_sign,
        "header": cmd_header,
        "verify": cmd_verify,
        "selftest": cmd_selftest,
    }
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
