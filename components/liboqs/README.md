# liboqs

This directory holds an Espressif fork of [liboqs](https://github.com/open-quantum-safe/liboqs), adapted to run on ESP32 series chips. It is not an ESP-IDF component on its own. The component your project depends on is [`esp-pqc`](../../) at the repository root, which builds this fork and also brings in the [`mbedtls`](../mbedtls/) override for TLS. See the [top-level README](../../README.md) for the repository overview.

This README is the reference for what the fork provides and for every `CONFIG_LIBOQS_*` option.

## What the Fork Provides

* The standard liboqs API. Firmware calls `OQS_KEM_*` for key exchange and `OQS_SIG_*` for signatures, so code written against upstream liboqs works unchanged.
* Algorithm families selectable from menuconfig instead of by editing CMake: ML-KEM and ML-DSA are on by default, and SLH-DSA, FALCON, MAYO, CROSS, SNOVA, UOV, BIKE, FrodoKEM, NTRU Prime, Classic McEliece, HQC and Kyber (Round 3) can be enabled.
* ML-DSA-65 and ML-KEM-768 tuned for these chips, through a compact 32-bit Keccak layer in `ports/fips202_kyber.c` that is always on for those two, and through heap-backed temporaries by default. Both stay standard, so keys, ciphertexts and signatures interoperate with any other implementation. The other algorithms are available but not tuned, and cost more flash and stack.
* The SoC hardware RNG wired in as the liboqs random source, optionally registered before `app_main()`.

Sizes of keys, ciphertexts and signatures are not fixed by this fork. Query them at run time with `OQS_KEM_length_*` or `OQS_SIG_length_*` after `OQS_KEM_new()` or `OQS_SIG_new()`, or see the [liboqs documentation](https://github.com/open-quantum-safe/liboqs) for the variant you enable.

Typical usage:

```c
#include <oqs/oqs.h>

void example(void)
{
    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");
    /* OQS_KEM_keypair, OQS_KEM_encaps, OQS_KEM_decaps, ... */
    OQS_KEM_free(kem);

    OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");
    /* OQS_SIG_keypair, OQS_SIG_sign, OQS_SIG_verify, ... */
    OQS_SIG_free(sig);
}
```

For working code, see the [kem_basic](../../examples/kem_basic/) and [signature_basic](../../examples/signature_basic/) examples.

## How the Fork Is Built

The build rules and every `CONFIG_LIBOQS_*` option live at the repository root, in [`CMakeLists.txt`](../../CMakeLists.txt) and [`Kconfig`](../../Kconfig). The `esp-pqc` component builds the liboqs submodule in place and compiles the ESP glue in `ports/`. Every other change to liboqs is a real commit on the fork branch, and the behavior of a build is selected through the Kconfig options below.

## Kconfig Options

Everything is under **Component config > Post-Quantum Cryptography (esp-pqc) > liboqs** in `idf.py menuconfig`. The mbedTLS side sits next to it under **mbedTLS**.

> Run `idf.py fullclean` after changing any `CONFIG_LIBOQS_*` option, because CMake caches those values.

### Algorithm Selection

`CONFIG_LIBOQS_ENABLE_KEM_ML_KEM` (default y) and `CONFIG_LIBOQS_ENABLE_SIG_ML_DSA` (default y), plus one option per additional family. Enable only what you use, because each family adds flash and some add significant stack.

### Advanced Options

| Option | Default | Purpose |
|--------|---------|---------|
| `CONFIG_LIBOQS_AUTO_INIT_RNG` | y | Register the hardware RNG (`esp_fill_random`) as the liboqs random source before `app_main()`. With it off, call `esp_liboqs_rng_init()` yourself. |
| `CONFIG_LIBOQS_MLD_HEAP_TEMPORARIES` | y | Put ML-DSA-65 per-call temporaries on the heap instead of the caller's stack. They are zeroized before being freed, and an allocation failure returns an error. With it off, the same data goes on the stack and a task needs 80 to 100 KB. |
| `CONFIG_LIBOQS_MLK_HEAP_TEMPORARIES` | y | The same for ML-KEM-768 temporaries. ML-KEM-512 and ML-KEM-1024 are unaffected. |
| `CONFIG_LIBOQS_MLD_VERIFY_ONLY` | n | Build only ML-DSA-65 verification, so key generation and signing return `OQS_ERROR`. Used by the bootloader in [pqc_boot_verify](../../examples/pqc_boot_verify/). |
| `CONFIG_LIBOQS_MLD_EXTERNAL_ALLOC` | n | Let the consumer provide the allocator for ML-DSA-65 large temporaries instead of using malloc and free, as the bootloader does with its own pool. |
| `CONFIG_LIBOQS_MINIMAL_COMMON` | n | Leave the common SHA3, SHA2 and fips202 layer out to save flash. Safe when you use only ML-DSA and ML-KEM, which use the Keccak layer from `ports/` instead. Do not enable it alongside FALCON, SLH-DSA or other algorithms that need the common hash layer. |
| `CONFIG_LIBOQS_DEBUG_INSTRUMENTATION` | n | Compile in per-phase timers and Keccak counters. Adds overhead, for analysis only. |
| `CONFIG_LIBOQS_VERBOSE_LOGGING` | n | Detailed operation logging, at the cost of code size. |

> **Entropy source.** The application has to enable a real entropy source before generating keys, otherwise the RNG output is not truly random. See [Random Number Generation](https://docs.espressif.com/projects/esp-idf/en/latest/api-reference/system/random.html) in the ESP-IDF Programming Guide.

### Memory Configuration

`CONFIG_LIBOQS_TASK_STACK_SIZE` and `CONFIG_LIBOQS_HEAP_SIZE_WARNING_KB` are informational hints, and `LIBOQS_MEMORY_PROFILE` documents suggested algorithm sets per SRAM budget. What actually gets built is decided by the algorithm options above.

### Hybrid TLS

`CONFIG_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_GROUP_X25519MLKEM768` and `CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65` wire the liboqs include path and the feature macros onto the mbedTLS targets at configure time. They need the [`mbedtls`](../mbedtls/) override, that is `CONFIG_MBEDTLS_USE_BUNDLED_PQC=y`. See the [esp_hybrid_tls](../../examples/esp_hybrid_tls/) example for the full setup.

## ESP-IDF Compatibility

Requires ESP-IDF v6.0 or later. Supported targets are listed in the [top-level README](../../README.md).

* **Xtensa** (ESP32, ESP32-S2, ESP32-S3): CMake sets `OQS_PERMIT_UNSUPPORTED_ARCHITECTURE` so upstream liboqs accepts the CPU, and the reference C code is used throughout.
* **RISC-V** (ESP32-C2, ESP32-C3, ESP32-C5, ESP32-C6, ESP32-H2, ESP32-P4 and similar): `CMAKE_SYSTEM_PROCESSOR` is set to `riscv32`, so `MLK_SYS_RISCV32` and `MLD_SYS_RISCV32` come from the toolchain. liboqs has no assembly backend for RV32, so these targets also build the reference C code.

## Security Notes

* Use `OQS_MEM_secure_free()` for secret keys and other sensitive buffers where applicable.
* The algorithms run in software. Side-channel resistance depends on the upstream implementations and on how you use them, so do a risk assessment before using them in production.
* The keys and certificates under `examples/` are for testing only. Generate your own, and never publish private keys.

## License

Apache-2.0, see [LICENSE](../../LICENSE). The `liboqs/` submodule bundles [liboqs](https://github.com/open-quantum-safe/liboqs) and third-party algorithm sources under their own licenses.

## Contributing

Issues and pull requests are welcome. When changing algorithm or port behavior, run the relevant examples on at least one Xtensa and one RISC-V target if you can.
