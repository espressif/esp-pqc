# liboqs Unity test suite

Quick, on-device regression tests for the `liboqs` component — structured
like ESP-IDF's `components/mbedtls/test_apps` (Unity `TEST_CASE`s + a pytest
runner). Run them after changing the component, its Kconfig toggles, or the
liboqs submodule to confirm nothing is broken.

## What is covered

| File | Tag | Cases |
|------|-----|-------|
| `test_liboqs_kem.c` | `[liboqs][kem]` | ML-KEM-768 encaps/decaps round-trip + shared-secret agreement; 20× heap-stability loop; tampered ciphertext (implicit rejection → different secret); wrong secret key |
| `test_liboqs_sig.c` | `[liboqs][sig]` | ML-DSA-65 sign/verify round-trip; 20× heap-stability loop; tampered signature / tampered message / wrong public key all fail verify |
| `test_liboqs_rng.c` | `[liboqs][rng]` | `esp_liboqs_randombytes` fills + draws differ; `OQS_randombytes` is wired to the HW source |
| `test_liboqs_mem.c` | `[liboqs][mem]` | ML-KEM/ML-DSA transient heap scratch is fully freed (no leak); ML-DSA-65 sign+verify completes in a 12 KB task with heap-backed temporaries |

Every test runs under a per-test heap guard (`setUp`/`tearDown` in `app_main.c`)
that fails on heap corruption and warns on leaks — so the heap-backed
temporaries (`CONFIG_LIBOQS_MLD/MLK_HEAP_TEMPORARIES`) are checked on every case.

## Configurations

- **`default`** — heap-backed ML-DSA-65 / ML-KEM-768 temporaries on (the shipped
  default). Small task stacks.
- **`stack_only`** (`sdkconfig.ci.stack_only`) — `CONFIG_LIBOQS_MLD/MLK_HEAP_TEMPORARIES=n`,
  i.e. upstream stack-only liboqs. Confirms results stay correct without the
  override allocators; Unity stack is raised to ~110 KB because ML-DSA-65 then
  keeps ~56 KB on the stack.

## Running

Interactive (pick cases from the Unity menu):

```bash
idf.py --preview set-target esp32s31     # or esp32, esp32c3, esp32p4, ...
idf.py --preview build flash monitor
```

Automated (runs all cases, both configs):

```bash
pytest --target esp32s31 --preview
```

`esp32s31` needs `--preview` (bring-up target) and the latest esptool. On
non-preview targets drop `--preview`.
