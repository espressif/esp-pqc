| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C5 | ESP32-C6 | ESP32-C61 | ESP32-H2 | ESP32-P4 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- | -------- | --------- | -------- | -------- | -------- | -------- |

# KEM Basic Example

(See the README.md file in the upper level 'examples' directory for more information about examples.)

This example shows how to use a key encapsulation mechanism (KEM) from the `esp-pqc` component in an application. It creates one FreeRTOS task that generates an ML-KEM-768 key pair, then runs encapsulation and decapsulation 20 times and reports the time, CPU cycles, heap use and task stack use for each phase.

The example calls the liboqs KEM API that `esp-pqc` provides: `OQS_KEM_new()`, `OQS_KEM_keypair()`, `OQS_KEM_encaps()`, `OQS_KEM_decaps()` and `OQS_KEM_free()`. The algorithm is available because `CONFIG_LIBOQS_ENABLED` and `CONFIG_LIBOQS_ENABLE_KEM_ML_KEM` are set in [sdkconfig.defaults](./sdkconfig.defaults).

Use this example as the starting point for firmware that has to agree on a session key with a peer, such as a provisioning flow, a custom secure channel over Wi-Fi or BLE, or a gateway link where you control both ends. Because every phase reports timing and memory, you can also use it to check what a key exchange costs on your target before you build a protocol around it.

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

This example does not need configuration. The required Kconfig options differing from the ESP-IDF defaults are pre-set for this particular example in [sdkconfig.defaults](./sdkconfig.defaults).

The defaults build for size (`CONFIG_COMPILER_OPTIMIZATION_SIZE=y`). If you want to compare timings between builds or targets, build for performance instead:

```
Component config > Compiler options > Optimization Level > Optimize for performance (-O2)
```

Two macros at the top of [main/kem_basic.c](main/kem_basic.c) control what the example reports:

| Macro | Default | Description |
|-------|---------|-------------|
| `ENABLE_HEAP_MONITORING` | 1 | Log heap use around the task and each operation. |
| `ENABLE_STACK_MONITORING` | 1 | Log FreeRTOS stack high-water marks. |

To conveniently check or modify Kconfig options for this example in a project configuration menu, run:

```
idf.py menuconfig
```

### Run Another Algorithm

The example runs ML-KEM-768. To run a different KEM:

1. Enable the algorithm family under `Component config > Post-Quantum Cryptography (esp-pqc) > liboqs`.
2. In `kem_test_task()` in [main/kem_basic.c](main/kem_basic.c), call `test_kem("<algorithm>")`. Commented calls at the bottom of the file show the pattern. The name must match the liboqs name, listed as the `OQS_KEM_alg_*` macros in `liboqs/src/kem/kem.h`.
3. Increase `KEM_TEST_TASK_STACK_BYTES` if the algorithm needs more stack than ML-KEM-768.

Each run generates its own key pair, so no test vectors are needed. Signature algorithms use a different API, so benchmark those with the [signature_basic](../signature_basic/) example instead.

### Build and Flash

Execute the following command to build the project, flash it to your development board, and run the monitor tool to view the serial output:

```
idf.py -p PORT flash monitor
```

(To exit the serial monitor, type ``Ctrl-]``.)

## Example Output

If you see console output similar to the following, the example is running correctly. The values depend on the chip, the clock and the optimization level:

```
I (325) kem_example: Testing KEM: ML-KEM-768 (20 iterations)
I (335) kem_example: Running 20 iterations...
[HEAP] kem_test_task: Start - Used: 53248 B, Free: 195680 B, Total: 248928 B, Largest: 131072 B, Min Free: 180224 B
I (...) kem_example: ✓ All 20 iterations completed successfully!
I (...) kem_example: Performance Statistics Summary (20 iterations, encaps+decaps only):
+------------------+----------+----------+----------+------------+------------+------------+
| Operation        | Avg (us) | Min (us) | Max (us) | Avg Cycles | Min Cycles | Max Cycles |
+------------------+----------+----------+----------+------------+------------+------------+
| Encapsulation    |     4832 |     4820 |     4933 |    1159164 |    1156288 |    1183920 |
| Decapsulation    |     5849 |     5841 |     5898 |    1403622 |    1401840 |    1415520 |
+------------------+----------+----------+----------+------------+------------+------------+
[STACK] kem_test_task: End - Total: 12288 B, Used: 4336 B, Free: 7952 B
```

Compare cycle counts rather than microseconds when you move between chips, because the two run at different clock speeds.

## Troubleshooting

* **Build fails with "liboqs not found".** Initialize the submodules of this repository:

  ```bash
  cd ../..
  git submodule update --init --recursive
  ```

* **The device reports "OQS_randombytes_system is not available".** Keep `CONFIG_LIBOQS_AUTO_INIT_RNG=y` in the configuration, or call `esp_liboqs_rng_init()` yourself before the first liboqs call.

* **Out of memory.** Reduce what the rest of the application allocates, or run the KEM task on a chip with more RAM. Change `KEM_TEST_TASK_STACK_BYTES` only if the serial `[STACK]` lines show the task running out of stack.

* **Program upload failure.** The hardware connection may not be correct: run `idf.py -p PORT monitor` and reboot your board to see whether there is any output. The download baud rate may also be too high: lower it in the `menuconfig` menu and try again.

For any technical queries, please open an [issue](https://github.com/espressif/post_quantum_cryptography/issues) on GitHub. We will get back to you soon.
