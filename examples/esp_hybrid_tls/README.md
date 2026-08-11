| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C5 | ESP32-C6 | ESP32-C61 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- | -------- | --------- | -------- | -------- |

# Hybrid PQC TLS 1.3 Client Example

(See the README.md file in the upper level 'examples' directory for more information about examples.)

This example connects over Wi-Fi to a TLS server on your network, completes a TLS 1.3 handshake, verifies the server certificate, and sends an HTTPS `GET`. It can either read the response and discard it, or store the downloaded file and check its SHA-256.

The TLS code is plain mbedTLS: `mbedtls_ssl_config_defaults()`, `mbedtls_x509_crt_parse()`, `mbedtls_ssl_handshake()`, `mbedtls_ssl_read()` and `mbedtls_ssl_write()`. Nothing in [main/esp_hybrid_tls.c](main/esp_hybrid_tls.c) selects an algorithm at run time. The `esp-pqc` component, pulled in through [main/idf_component.yml](main/idf_component.yml), supplies the post-quantum key exchange and certificate support that mbedTLS negotiates, and no files under `$IDF_PATH` are modified.

Use this example as the starting point for a device that talks to your own server or cloud endpoint over TLS 1.3: an HTTPS client, an OTA download, or a telemetry uplink. It builds in three profiles, so you can also run the same firmware against the same server with and without post-quantum algorithms and compare handshake time and memory use on your own board before committing to one.

## How to Use Example

### Hardware Required

* A development board with any supported ESP32 series chip with Wi-Fi
* At least 4 MB of flash, which the bundled [partitions.csv](partitions.csv) expects
* A USB cable for power supply and programming

### Software Required

* ESP-IDF v6.0 or later
* A PC on the same network as the board, running OpenSSL 3.6 or later. The [scripts/run_server.sh](scripts/run_server.sh) helper starts the matching test server.
* The submodules of this repository, populated with `git submodule update --init --recursive`

### Set Chip Target

Go to the example project directory and set the chip target:

```
idf.py set-target <target>
```

For example, to set esp32c5 as the chip target, run:

```
idf.py set-target esp32c5
```

### Configure the Project

The TLS options are pre-set for this example in [sdkconfig.defaults](./sdkconfig.defaults). Open the project configuration menu to set the rest:

```
idf.py menuconfig
```

* **Example Connection Configuration**: set the Wi-Fi SSID and password.
* **Hybrid PQC TLS Example**: pick the TLS crypto profile and, optionally, the file download check.

| Option | Default | Description |
|--------|---------|-------------|
| `EXAMPLE_TLS_PROFILE` | Full PQC | Which profile to build. Selects the trust anchor that gets embedded and the port the client connects to. |
| `EXAMPLE_HTTP_DOWNLOAD` | n | Store the response body in LittleFS and compare its SHA-256 against `EXAMPLE_DOWNLOAD_EXPECTED_SHA256`. Off means the response is read and discarded. |
| `EXAMPLE_USE_TEST_CERTS` | n | Skip the server identity check and use the bundled test certificate. Test only, see below. |

Each profile pairs with one server mode, and each mode listens on its own port, so you can leave all three servers running side by side:

| Profile | Key exchange | Certificate | Port | Server |
| --- | --- | --- | --- | --- |
| Classical | X25519 | ECDSA-P256 | 8443 | `./scripts/run_server.sh ecdsa` |
| Hybrid KEM | X25519MLKEM768 | ECDSA-P256 | 8445 | `./scripts/run_server.sh hybrid-kem` |
| Full PQC (default) | X25519MLKEM768 | ML-DSA-65 | 8444 | `./scripts/run_server.sh mldsa65` |

The algorithms themselves are Kconfig options of the `esp-pqc` component under `Component config > Post-Quantum Cryptography (esp-pqc)`, not of this example, so the build cross-checks them against the profile you picked and fails with the exact options to change if they disagree:

| Profile | Required options |
| --- | --- |
| Classical | `CONFIG_LIBOQS_ENABLED=n` |
| Hybrid KEM | `CONFIG_LIBOQS_ENABLED=y`, `CONFIG_LIBOQS_ENABLE_KEM_ML_KEM=y`, `CONFIG_LIBOQS_ENABLE_SIG_ML_DSA=n` |
| Full PQC | `CONFIG_LIBOQS_ENABLED=y`, `CONFIG_LIBOQS_ENABLE_KEM_ML_KEM=y`, `CONFIG_LIBOQS_ENABLE_SIG_ML_DSA=y` |

### Set the Server Address

On the device, `localhost` is the device itself, so pass the address of the PC that runs the server at build time:

```
idf.py build -DTLS_TEST_SERVER_IP=192.168.x.x
```

The client checks the server certificate against a fixed identity, `esp-pqc-tls-server`, and not against that IP address. The bundled certificates in [certs/](certs/) are issued to that name, so they keep working when the server moves to another address and you do not need to regenerate anything.

To use your own CA instead, generate a key pair and certificates for the same name with OpenSSL, replace the files in `certs/<profile>/`, and rebuild. Reflash only when the CA itself changes, because that is the file the firmware embeds.

If you would rather skip the identity check during a quick test, enable `EXAMPLE_USE_TEST_CERTS` and run `./scripts/run_server.sh test`. The chain is still validated against the bundled test CA, but any host presenting a certificate from that CA is accepted, so leave this option off outside of testing.

### Build and Flash

Execute the following command to build the project, flash it to your development board, and run the monitor tool to view the serial output:

```
idf.py -p PORT flash monitor
```

(To exit the serial monitor, type ``Ctrl-]``.)

### Start the Server

Run the mode that matches the profile you built, for example:

```
./scripts/run_server.sh mldsa65
```

Add `download` to any mode to serve real files from `files/` instead of a generated status page, which is what `EXAMPLE_HTTP_DOWNLOAD=y` expects:

```
./scripts/run_server.sh mldsa65 download
```

The file to serve is `files/tls_testfile.bin`, which is not part of the repository. Create it once with:

```bash
python3 -c "import sys; sys.stdout.buffer.write(bytes(i % 256 for i in range(102400)))" > files/tls_testfile.bin
```

## Example Output

If you see console output similar to the following, the example is running correctly. This capture is the full PQC profile with the file download enabled, so the log tag is `full_pqc_tls`. The other profiles log as `classical_tls` and `hybrid_kem_tls`:

```
I (436) full_pqc_tls: ESP32-C5 TLS 1.3 client starting, profile: full PQC
I (446) full_pqc_tls:   KEM : X25519MLKEM768 (0x11EC)
I (446) full_pqc_tls:   Auth: ML-DSA-65 (sig 0x0905, id-ml-dsa-65, RFC 9881)
I (14526) full_pqc_tls: Verifying server cert identity: esp-pqc-tls-server
I (14546) full_pqc_tls: CA cert loaded (7571 bytes)
I (14546) full_pqc_tls: TLS profile:      full PQC (server: run_server.sh mldsa65)
I (14576) full_pqc_tls: Connecting to https://10.95.110.13:8444 ...
I (14886) full_pqc_tls: TCP connection established.
I (14906) full_pqc_tls: Performing TLS 1.3 handshake...
I (15216) full_pqc_tls: *** TLS 1.3 handshake SUCCESS ***
I (15226) full_pqc_tls:   Cipher suite : TLS1-3-AES-256-GCM-SHA384
I (15236) full_pqc_tls:   TLS version  : TLSv1.3
I (15246) full_pqc_tls:   Peer key     : 15616 bits
I (15256) full_pqc_tls: X.509 verify flags: none (chain + hostname OK)
I (15256) full_pqc_tls: Sending HTTP GET request...
I (16886) full_pqc_tls: Download: 102400 / -1 bytes → /lfs/testfile.bin
I (16916) full_pqc_tls: SHA-256(/lfs/testfile.bin) = 27783e87963a4efb6829b531c9ba57b44f45797f6770bd637fbf0d807cbdbae0
I (16916) full_pqc_tls: SHA-256 matches the expected digest.
I (16926) full_pqc_tls: TLS session closed cleanly.
```

The run also logs stack high-water marks and heap watermarks around the handshake, so you can compare profiles on your own board.

## Troubleshooting

* **The handshake fails right after ClientHello, with alert 40.** The firmware profile and the server mode disagree. Every server mode pins its key exchange group, so a mismatch is refused rather than quietly downgraded. Check the `TLS profile:` line the firmware logs at startup and start the server mode it names.

* **Certificate verification fails.** Build with `-DTLS_TEST_SERVER_IP` set to the address of the PC running the server. If you replaced the certificates, keep the `esp-pqc-tls-server` identity, and rebuild and reflash when the CA changes.

* **The server presents a `CN=localhost` self-signed certificate.** Something else is already bound to the port, so `openssl s_server` failed to bind. A system nginx often holds 8443. Check with `lsof -nP -iTCP:8443 -sTCP:LISTEN` and stop that service, or use another profile's port.

* **The SHA-256 does not match.** The server is running without the `download` argument. Without it the server ignores the requested path and returns a generated status page that differs on every connection. Restart it as `./scripts/run_server.sh <mode> download`.

* **Wi-Fi connect failure.** Set the SSID and password under **Example Connection Configuration** in `menuconfig`.

* **Build or CMake errors.** Run `idf.py fullclean` and build again after changing any `CONFIG_MBEDTLS_*` or `CONFIG_LIBOQS_*` option, because CMake caches those values. If a component is reported missing, check that the submodules are populated.

* **Program upload failure.** The hardware connection may not be correct: run `idf.py -p PORT monitor` and reboot your board to see whether there is any output. The download baud rate may also be too high: lower it in the `menuconfig` menu and try again.

## Security Note

The [certs/](certs/) directory holds test keys and certificates only. Generate your own for anything beyond local testing, and never publish private keys.

## Technical Support and Feedback

Please use the following feedback channels:

* For technical queries, go to the [esp32.com](https://esp32.com/) forum
* For ESP-IDF issues, create a [GitHub issue](https://github.com/espressif/esp-idf/issues)
* For this component and example, open an [issue](https://github.com/espressif/post_quantum_cryptography/issues) on GitHub

We will get back to you as soon as possible.
