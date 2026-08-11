| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C5 | ESP32-C6 | ESP32-C61 | ESP32-H2 | ESP32-P4 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- | -------- | --------- | -------- | -------- | -------- | -------- |

# Signature Basic Example

(See the README.md file in the upper level 'examples' directory for more information about examples.)

This example shows how to sign and verify data on the device with the `esp-pqc` component. It creates two FreeRTOS tasks that run one after the other:

* `sig_test` signs and verifies a message with ML-DSA-65, 20 iterations per phase, and reports time, CPU cycles, heap use and task stack use.
* `rsa_ecdsa_classical` runs the same kind of operations with RSA and ECDSA through the mbedTLS PSA API, so both sets of numbers come from one run on one board.

The example calls the liboqs signature API that `esp-pqc` provides: `OQS_SIG_new()`, `OQS_SIG_keypair()`, `OQS_SIG_sign()`, `OQS_SIG_verify()` and `OQS_SIG_free()`. The algorithm is available because `CONFIG_LIBOQS_ENABLED` and `CONFIG_LIBOQS_ENABLE_SIG_ML_DSA` are set in [sdkconfig.defaults](./sdkconfig.defaults).

Use this example as the starting point for anything where a device has to check who produced a piece of data: verifying an OTA image or a configuration blob before applying it, signing telemetry or a device attestation, or validating a command from a cloud backend. The side-by-side classical numbers help you decide where a signature check fits in that flow, since verification cost is what a device pays on every update.

## How to Use Example

### Hardware Required

* A development board with any supported ESP32 series chip (for example ESP32-S3-DevKitC or ESP32-P4-Function-EV-Board)
* A USB cable for power supply and programming

### Software Required

* ESP-IDF v6.0 or later

### Set Chip Target

Go to the example project directory and set the chip target:

```
idf.py set-target <target>
```

For example, to set esp32s3 as the chip target, run:

```
idf.py set-target esp32s3
```

### Configure the Project

This example does not need configuration. The required Kconfig options differing from the ESP-IDF defaults are pre-set for this particular example in [sdkconfig.defaults](./sdkconfig.defaults), including the performance optimization level and the larger app partition that the signature code needs.

Macros at the top of [main/signature_basic.c](main/signature_basic.c) control what the example runs and reports:

| Macro | Default | Description |
|-------|---------|-------------|
| `KEYGEN` | 1 | Benchmark key generation. |
| `SIGN` | 1 | Benchmark signing. |
| `VERIFY` | 1 | Benchmark verification. |
| `USE_COMMON_TEST_KEYS` | 1 | Use the fixed key pair and message in [main/sig_fixed_vectors.c](main/sig_fixed_vectors.c) so runs are reproducible across builds. Set to 0 to generate fresh keys at run time. |
| `ENABLE_HEAP_MONITORING` | 1 | Log heap use around the tasks and each operation. |
| `ENABLE_STACK_MONITORING` | 1 | Log FreeRTOS stack high-water marks. |

To conveniently check or modify Kconfig options for this example in a project configuration menu, run:

```
idf.py menuconfig
```

### Run Another Algorithm

The example runs ML-DSA-65. To run a different signature algorithm:

1. Enable the algorithm family under `Component config > Post-Quantum Cryptography (esp-pqc) > liboqs`.
2. In `signature_test_task()` in [main/signature_basic.c](main/signature_basic.c), call `test_signature("<algorithm>")`. Commented calls at the bottom of the file show the pattern. The name must match the liboqs name, listed as the `OQS_SIG_alg_*` macros in `liboqs/src/sig/sig.h`.
3. Set `USE_COMMON_TEST_KEYS` to 0, because the fixed vectors only cover ML-DSA-65. The task then runs key generation, signing and verification with freshly generated keys.
4. Increase `SIG_TEST_TASK_STACK_BYTES` if the algorithm needs more stack than ML-DSA-65.

Key encapsulation algorithms use a different API, so benchmark those with the [kem_basic](../kem_basic/) example instead.

### Skip the Classical Comparison

To build a smaller image without the RSA and ECDSA task, remove `test_rsa.c` and `test_mbedtls_ecdsa.c` from [main/CMakeLists.txt](main/CMakeLists.txt) and drop the `xTaskCreate(classical_rsa_ecdsa_task, ...)` call in `app_main()`.

### Build and Flash

Execute the following command to build the project, flash it to your development board, and run the monitor tool to view the serial output:

```
idf.py -p PORT flash monitor
```

(To exit the serial monitor, type ``Ctrl-]``.)

## Example Output

If you see console output similar to the following, the example is running correctly. The values depend on the chip, the clock and the optimization level:

```
I (325) sig_example: Testing signature: ML-DSA-65
[HEAP] signature_test_task: Start - Used: 24372 B, Free: 328476 B, Total: 352848 B, Largest: 303104 B, Min Free: 328476 B
I (...) analysis: === SIGN Performance Statistics (20 iterations) ===
+------------------+---------------+------------------+
| Metric           | Time (ms)     | Cycles           |
+------------------+---------------+------------------+
| Average          |        128.60 |         30953351 |
| Maximum          |           519 |        124630802 |
| Minimum          |            32 |          7680661 |
+------------------+---------------+------------------+
I (...) analysis: === VERIFY Performance Statistics (20 iterations) ===
+------------------+---------------+------------------+
| Metric           | Time (ms)     | Cycles           |
+------------------+---------------+------------------+
| Average          |         22.00 |          5335539 |
| Maximum          |            22 |          5364050 |
| Minimum          |            22 |          5333458 |
+------------------+---------------+------------------+
[STACK] signature_test_task: End - Total: 8192 B, Used: 3296 B, Free: 4896 B
```

The classical task prints its RSA and ECDSA results in the same format after the ML-DSA task finishes.

Two things to keep in mind when reading the numbers. Signing time varies a lot between iterations, so compare the minimum or raise the iteration count instead of relying on one average. Verification time is stable, which makes it the useful figure when you compare chips or builds, and cycle counts are the right axis to compare across chips because clock speeds differ.

## Troubleshooting

* **Build fails with "liboqs not found".** Initialize the submodules of this repository:

  ```bash
  cd ../..
  git submodule update --init --recursive
  ```

* **The device reports "OQS_randombytes_system is not available".** Keep `CONFIG_LIBOQS_AUTO_INIT_RNG=y` in the configuration, or call `esp_liboqs_rng_init()` yourself before the first liboqs call.

* **Out of memory.** Reduce what the rest of the application allocates, or run the task on a chip with more RAM. Change `SIG_TEST_TASK_STACK_BYTES` only if the serial `[STACK]` lines show the task running out of stack.

* **Program upload failure.** The hardware connection may not be correct: run `idf.py -p PORT monitor` and reboot your board to see whether there is any output. The download baud rate may also be too high: lower it in the `menuconfig` menu and try again.

For any technical queries, please open an [issue](https://github.com/espressif/post_quantum_cryptography/issues) on GitHub. We will get back to you soon.
