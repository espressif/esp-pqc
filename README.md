| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C5 | ESP32-C6 | ESP32-C61 | ESP32-H2 | ESP32-P4 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- | -------- | --------- | -------- | -------- | -------- | -------- |

# esp-pqc

`esp-pqc` adds post-quantum algorithms to ESP-IDF as a single component. Depend on it and your application can call the `OQS_KEM_*` and `OQS_SIG_*` APIs for key exchange and signatures, and negotiate TLS 1.3 with a hybrid key exchange and a post-quantum certificate. No files under `$IDF_PATH` are modified.

It wraps [liboqs](https://github.com/open-quantum-safe/liboqs) for the algorithms and ships an [mbedTLS](https://github.com/Mbed-TLS/mbedtls) override that adds the TLS 1.3 support. Both come with the component, so one dependency is enough.

> **Status:** `esp-pqc` is a preview project, distributed as source from GitHub. The APIs and the Kconfig option names can still change between releases, and `pqc_boot_verify` is experimental. Use a release tag if you want a fixed base, or track `main` for the newest work.

## What You Get

| Part | Path | Role |
|------|------|------|
| `esp-pqc` | [repository root](CMakeLists.txt) | The component you depend on. It builds liboqs and pulls in the `mbedtls` override for you. |
| liboqs | [`components/liboqs/`](components/liboqs/) | The algorithm library, providing the `OQS_KEM_*` and `OQS_SIG_*` APIs. See its [README](components/liboqs/README.md) for the algorithm list and every Kconfig option. |
| mbedtls | [`components/mbedtls/`](components/mbedtls/) | Overrides the built-in ESP-IDF `mbedtls` with a build that supports hybrid TLS 1.3, selected by `CONFIG_MBEDTLS_USE_BUNDLED_PQC` (default y). |

The algorithms run in software on the CPU, because typical ESP32 silicon has no accelerator for them. Randomness comes from the SoC hardware RNG (`esp_fill_random`).

## How to Use

### Hardware Required

* An ESP development board based on one of the supported targets listed above
* A USB cable for power and programming

See [Development Boards](https://www.espressif.com/en/products/devkits) for more information.

### Software Required

* ESP-IDF v6.0 or later

Get the sources with git, including the submodules:

```bash
git clone --recursive https://github.com/espressif/esp-pqc.git
```

If you cloned without `--recursive`, or you switched branches, run:

```bash
git submodule update --init --recursive
```

### Add esp-pqc to Your Project

Start from one of the [examples](#examples), or add the dependency to your own project in `main/idf_component.yml`:

```yaml
dependencies:
  esp-pqc:
    # Path to your esp-pqc clone, the directory that holds CMakeLists.txt and
    # idf_component.yml. The in-repo examples use `path: ../../..`.
    path: /path/to/esp-pqc
```

Then require it in the component that calls the APIs:

```cmake
idf_component_register(
    SRCS "app_main.c"
    INCLUDE_DIRS "."
    REQUIRES esp-pqc
)
```

Include the headers with `#include <oqs/oqs.h>`.

### Set the Target

```bash
idf.py set-target <chip_name>
```

### Configure the Project

```bash
idf.py menuconfig
```

Every option lives under **Component config > Post-Quantum Cryptography (esp-pqc)**, in two groups:

* **liboqs**: which algorithms are built, and how they use memory (`CONFIG_LIBOQS_*`).
* **mbedTLS**: which mbedTLS tree the override builds, and the hybrid TLS 1.3 options (`CONFIG_MBEDTLS_*`).

The stock ESP-IDF mbedTLS options stay where they always were, under **Component config > mbedTLS**.

Run `idf.py fullclean` after changing any `CONFIG_LIBOQS_*` or `CONFIG_MBEDTLS_*` option, because CMake caches those values.

### Build and Flash

```bash
idf.py build flash monitor
```

To exit the serial monitor, type `Ctrl-]`.

See the [Getting Started Guide](https://docs.espressif.com/projects/esp-idf/en/latest/get-started/index.html) for full steps to configure and use ESP-IDF.

## Examples

Each project under [`examples/`](examples/) is a standard ESP-IDF project. Build and run one with `idf.py set-target <chip> && idf.py build flash monitor`.

| Example | What it does |
|---------|--------------|
| [kem_basic](examples/kem_basic/) | Runs a key encapsulation on the device and reports time, cycles, heap and stack. Start here for a device that has to agree on a session key with a peer. |
| [signature_basic](examples/signature_basic/) | Signs and verifies on the device, next to RSA and ECDSA from the same run. Start here for verifying an update, a configuration blob or a command. |
| [esp_hybrid_tls](examples/esp_hybrid_tls/) | A TLS 1.3 client over Wi-Fi that talks to an OpenSSL server, in three selectable crypto profiles. Start here for an HTTPS client, an OTA download or a telemetry uplink. |
| [pqc_boot_verify](examples/pqc_boot_verify/) | Experimental. The bootloader adds a signature check in front of Secure Boot V2 on ESP32-C3, ESP32-C5 and ESP32-C6. Ships no keys, so you generate your own. |

On-device Unity regression tests live in [`test_apps/liboqs_test/`](test_apps/liboqs_test/).

## Security Notes

* The algorithms run in software. Side-channel resistance depends on the upstream liboqs and mbedTLS implementations and on how you use them, so do a risk assessment before using them in production.
* The keys and certificates under `examples/` are for testing only. Generate your own, and never publish private keys.

## Troubleshooting

* If a build picks up stale settings after a Kconfig change, run `idf.py fullclean` and build again.
* If a submodule directory is empty, run `git submodule update --init --recursive`.

For any technical queries, please open an issue on GitHub. We will get back to you soon.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details. The bundled liboqs, mbedTLS and third-party algorithm sources are under their respective licenses inside the submodule trees.
