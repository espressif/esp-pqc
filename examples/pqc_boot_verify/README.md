| Supported Targets | ESP32-C3 | ESP32-C5 | ESP32-C6 |
| ----------------- | -------- | -------- | -------- |

# PQC Boot Verify Example

(See the README.md file in the upper level 'examples' directory for more information about examples.)

This example adds an ML-DSA-65 signature check to the second stage bootloader, in front of the standard ESP-IDF Secure Boot V2 check. On every boot the bootloader verifies the post-quantum signature of the application image first, then runs the classical Secure Boot V2 verification. Both have to pass before the application starts.

The post-quantum verification comes from the `esp-pqc` component, built for the bootloader. The signing side is [scripts/pqc_sign.py](scripts/pqc_sign.py), which generates the key pair, produces the header that the bootloader compiles in, and appends the signature block to the application binary during the build. The classical key and signature stay with the normal ESP-IDF Secure Boot V2 flow.

Use this example to evaluate what an additional boot-time signature check costs on your own board, to prototype a signing flow where your build server holds both keys, or as a reference for how a second verification step is hooked into the bootloader and the image layout.

> [!IMPORTANT]
> This example is for experimentation on a development board. It is not a production trust model or signing workflow. Signing keys are not part of the repository: generate your own, keep them confidential, and never reuse a key between a demonstration and a product.

## How to Use Example

### Hardware Required

* A development board with an ESP32-C3, ESP32-C5 or ESP32-C6
* A USB cable for power supply and programming

### Software Required

* ESP-IDF v6.0 or later, set up and sourced with `. $IDF_PATH/export.sh`
* The Python `pqcrypto` library, installed with `pip install -r ci/requirements.txt`

### Set Chip Target

Go to the example project directory and set the chip target:

```
idf.py set-target <target>
```

For example, to set esp32c5 as the chip target, run:

```
idf.py set-target esp32c5
```

### 1. Generate the Keys

Generate the post-quantum key pair:

```bash
python scripts/pqc_sign.py keygen --keys-dir keys/
# keys/pqc_ml_dsa_65_public.bin
# keys/pqc_ml_dsa_65_secret.bin
```

For the classical key, generate an RSA-3072 key with `espsecure.py` as described in the ESP-IDF Secure Boot V2 documentation.

### 2. Generate the Public Key Header

The bootloader compares the key in the signature block against a key compiled into it, so turn the public key into a header first:

```bash
python scripts/pqc_sign.py header \
    --pk keys/pqc_ml_dsa_65_public.bin \
    --output bootloader_components/bootloader_support/include/pqc_public_key.h
```

Repeat this step whenever you generate a new key pair.

### 3. Configure the Project

```
idf.py menuconfig
```

The options are under **Component config > PQC Secure Boot**:

| Option | Default | Description |
|--------|---------|-------------|
| `PQC_SECURE_BOOT_ENABLED` | y | Master enable for the post-quantum verification step. |
| `PQC_MEMORY_STRATEGY` | TLSF | Where the verification buffers live. See [Memory Strategies](#memory-strategies). |
| `PQC_TLSF_POOL_SIZE_KB` | 48 | Pool size for the TLSF strategy. |
| `PQC_CALL_STACK_SIZE_KB` | 8 | Call-frame stack size for the TLSF strategy. |
| `PQC_MLD_REDUCE_RAM` | y | Trade some speed for lower RAM use. |
| `PQC_DEBUG_VERBOSE` | n | Print detailed verification logs during boot. |

Secure Boot V2 has to be enabled as well, under **Security features**: select Secure Boot V2 and set the path to the signing key from step 1. The bundled `sdkconfig.defaults` already enables Secure Boot V2 and flash encryption in development mode.

### 4. Build and Flash

```
idf.py build
```

The build does the signing for you: it builds the bootloader with the verification code, builds the application, then runs `pqc_sign.py sign` to append both signature blocks to the application binary. There is no manual signing step.

Flash encryption is enabled by default, so flash with:

```
idf.py -p PORT encrypted-flash monitor
```

To disable flash encryption for development, turn off **Security features > Enable flash encryption in bootloader**, run `idf.py fullclean` because security options change the build, then use the normal `idf.py -p PORT flash monitor`.

(To exit the serial monitor, type ``Ctrl-]``.)

## Example Output

If you see console output similar to the following, both checks passed and the application was allowed to start. The cycle counts and timings depend on the chip and the bootloader clock:

```
Verifying image signature...
PQC: SHA-256 hash: 2465694 cycles, 30821 us, 30 ms (CPU 80 MHz)
PQC: ML-DSA-65 verify: 3533980 cycles, 44174 us, 44 ms (CPU 80 MHz)
PQC verification successful!!
I (229) secure_boot_v2: Verifying with RSA-PSS...
I (242) secure_boot_v2: Signature verified successfully!
RSA verify: 1095604 cycles, 13695 us, 13 ms
Secure boot total (PQC+RSA): 7328597 cycles, 91607 us, 91 ms
```

If either check fails, the bootloader stops before loading the application and reports which step failed.

## How It Works

The signature block is appended after the classical signature sector, so the flash layout of a signed application is:

```
[Application image] [0xFF padding]
[4 KB Secure Boot V2 signature sector]
[8 KB PQC signature block]
```

On boot, the bootloader:

1. Locates the application image and the signature block that follows the classical signature sector.
2. Validates the block header and its CRC-32.
3. Hashes the image together with the classical signature sector with SHA-256, in chunks.
4. Compares that digest against the digest stored in the block.
5. Verifies the ML-DSA-65 signature over the digest, on a separate stack.
6. Checks the public key in the block against the key compiled into the bootloader.
7. Continues into the standard Secure Boot V2 verification, and starts the application only if that passes too.

Because the digest covers the classical signature sector as well as the image, the classical signature cannot be replaced without invalidating the post-quantum one.

### Memory Strategies

Verification needs more RAM than the bootloader normally has available, so `PQC_MEMORY_STRATEGY` offers two ways to provide it:

* **TLSF heap** (default): borrows a pool from the top of the application SRAM region during verification, zeroes it afterwards, and leaves it to the application as heap. This lowers the application's static link budget by about 22 KB.
* **Stack**: reserves a dedicated stack in the bootloader's own data segment. Simpler, and it borrows nothing from the application, but it lowers the application's static link budget by about 110 KB.

Both are link-time budgets rather than a loss of usable RAM: an application that allocates at run time is unaffected, while one that exceeds the static window fails to link. With `PQC_SECURE_BOOT_ENABLED` off, the layout matches stock ESP-IDF.

## Signing Tool Reference

[scripts/pqc_sign.py](scripts/pqc_sign.py) supports the following commands:

```bash
pqc_sign.py keygen [--keys-dir DIR] [--force]   # generate an ML-DSA-65 key pair
pqc_sign.py header --pk <public.bin> --output <header.h>
pqc_sign.py verify <binary> --pk <public.bin>   # check a signed binary on the host
pqc_sign.py selftest                            # keygen, sign and verify round trip
```

The build calls the `sign` command itself, so you normally use `keygen` and `header` only.

## Troubleshooting

* **Build fails with a missing `pqc_public_key.h`.** Run step 2 before building. The public key has to be compiled into the bootloader.

* **Verification fails on boot.** The key compiled into the bootloader does not match the key used for signing. Run `pqc_sign.py header` again with the current public key and rebuild.

* **The bootloader runs out of memory.** Increase `PQC_TLSF_POOL_SIZE_KB`, or keep `PQC_MLD_REDUCE_RAM` enabled to trade speed for RAM.

* **The application fails to link after enabling the feature.** The static data of the application no longer fits under the lowered ceiling. Switch to the TLSF strategy if you are using the stack strategy, or move large static buffers to run-time allocation.

* **Program upload failure.** The hardware connection may not be correct: run `idf.py -p PORT monitor` and reboot your board to see whether there is any output. The download baud rate may also be too high: lower it in the `menuconfig` menu and try again.

For any technical queries, please open an [issue](https://github.com/espressif/post_quantum_cryptography/issues) on GitHub. We will get back to you soon.
