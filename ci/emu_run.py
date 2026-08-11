#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
"""
Run a built ESP-IDF app inside esp-emulator (esp-emu) and assert on its serial output.

esp-emu is a standalone emulator (not a pytest-embedded service), so this script is the glue: it merges an ESP-IDF build dir into one flash binary, boots it in esp-emu, streams the emulated UART to stdout, and:

  * PASSES as soon as every --expect regex has been seen, or
  * FAILS if any --fail regex is seen (panic / abort / boot loop), or
  * FAILS if --timeout seconds elapse before all --expect regexes are seen.

Typical use (see .gitlab-ci.yml):

  python ci/emu_run.py \
      --build-dir examples/kem_basic/build_esp32c3_default \
      --chip esp32c3 \
      --expect "iterations completed successfully" \
      --timeout 180
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from queue import Empty, Queue

# Lines that mean the firmware crashed / rebooted — never a healthy run.
DEFAULT_FAIL_PATTERNS = [
    r"Guru Meditation Error",
    r"abort\(\) was called",
    r"assert failed",
    r"rst:0x[0-9a-fA-F]+ \(.*(PANIC|WDT|BROWNOUT)",
    r"CORRUPT HEAP",
    r"Stack canary watchpoint triggered",
]


def _run(cmd, **kw):
    print("[emu_run] $ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, **kw)


def _esptool_major() -> int:
    try:
        import esptool  # noqa: WPS433 (local import on purpose)
        return int(str(esptool.__version__).split(".")[0])
    except Exception:
        return 4


def merge_binary(build_dir: str, chip: str, out_path: str) -> str:
    """Produce a single merged flash image from an ESP-IDF build dir.

    Reads flasher_args.json (in every modern IDF build) to stay independent of build-dir layout; esptool flags differ between v4 (merge_bin/--flash_mode) and v5 (merge-bin/--flash-mode), so we pick them from the installed major version.
    """
    fa_path = os.path.join(build_dir, "flasher_args.json")
    if not os.path.isfile(fa_path):
        sys.exit(f"[emu_run] ERROR: {fa_path} not found — was the app built?")

    with open(fa_path) as f:
        fa = json.load(f)

    settings = fa.get("flash_settings", {})
    flash_files = fa.get("flash_files", {})
    if not flash_files:
        sys.exit(f"[emu_run] ERROR: no flash_files in {fa_path}")

    if _esptool_major() >= 5:
        sub, fm, ff, fs = "merge-bin", "--flash-mode", "--flash-freq", "--flash-size"
    else:
        sub, fm, ff, fs = "merge_bin", "--flash_mode", "--flash_freq", "--flash_size"

    cmd = [
        sys.executable, "-m", "esptool", "--chip", chip, sub,
        "-o", out_path,
        fm, settings.get("flash_mode", "dio"),
        ff, settings.get("flash_freq", "keep"),
        fs, settings.get("flash_size", "keep"),
    ]
    for offset, fname in sorted(flash_files.items(), key=lambda kv: int(kv[0], 0)):
        cmd += [offset, fname]

    res = _run(cmd, cwd=build_dir)
    if res.returncode != 0:
        sys.exit(f"[emu_run] ERROR: esptool merge failed (rc={res.returncode})")
    return os.path.join(build_dir, out_path)


def _reader(proc, q: Queue):
    for raw in iter(proc.stdout.readline, b""):
        q.put(raw.decode("utf-8", errors="replace"))
    proc.stdout.close()


def run_emulator(merged_bin: str, chip: str, expects, fails, timeout: int,
                 extra_args) -> int:
    esp_emu = shutil.which("esp-emu")
    if not esp_emu:
        sys.exit(
            "[emu_run] ERROR: 'esp-emu' not on PATH — install it with "
            "'curl -fsSL https://raw.githubusercontent.com/espressif/esp-emulator/main/install.sh | sh' "
            "and make sure ~/.local/bin is on PATH"
        )

    expect_res = [re.compile(p) for p in expects]
    fail_res = [re.compile(p) for p in (fails + DEFAULT_FAIL_PATTERNS)]
    seen = [False] * len(expect_res)

    cmd = [esp_emu, "--chip", chip, "--firmware", merged_bin] + list(extra_args)
    print(f"[emu_run] launching: {' '.join(cmd)}", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, bufsize=1)

    q: Queue = Queue()
    threading.Thread(target=_reader, args=(proc, q), daemon=True).start()

    deadline = time.monotonic() + timeout
    tail = []
    try:
        while time.monotonic() < deadline:
            try:
                line = q.get(timeout=0.5)
            except Empty:
                if proc.poll() is not None and q.empty():
                    print("[emu_run] emulator exited before all expectations met",
                          flush=True)
                    break
                continue
            sys.stdout.write(line)
            sys.stdout.flush()
            tail.append(line)
            tail = tail[-40:]

            for fr in fail_res:
                if fr.search(line):
                    print(f"\n[emu_run] FAIL: matched failure pattern /{fr.pattern}/",
                          flush=True)
                    return 1
            for i, er in enumerate(expect_res):
                if not seen[i] and er.search(line):
                    seen[i] = True
                    print(f"[emu_run] matched expect /{er.pattern}/", flush=True)
            if all(seen):
                print("\n[emu_run] PASS: all expectations met", flush=True)
                return 0

        missing = [er.pattern for er, ok in zip(expect_res, seen) if not ok]
        print(f"\n[emu_run] FAIL: timed out after {timeout}s; "
              f"unmatched expectations: {missing}", flush=True)
        print("[emu_run] --- last output ---\n" + "".join(tail), flush=True)
        return 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def main() -> int:
    ap = argparse.ArgumentParser(description="Run an ESP-IDF app under esp-emu and assert output")
    ap.add_argument("--build-dir", required=True, help="ESP-IDF build directory")
    ap.add_argument("--chip", required=True, choices=["esp32c3", "esp32c6", "esp32p4"])
    ap.add_argument("--expect", action="append", default=[],
                    help="regex that must appear in serial output (repeatable)")
    ap.add_argument("--fail", action="append", default=[],
                    help="extra regex that, if seen, fails the run (repeatable)")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--merged-name", default="emu_merged.bin")
    ap.add_argument("--emu-arg", action="append", default=[],
                    help="extra argument passed through to esp-emu (repeatable)")
    args = ap.parse_args()

    if not args.expect:
        args.expect = [r".+"]  # at least require *some* output

    merged = merge_binary(args.build_dir, args.chip, args.merged_name)
    return run_emulator(merged, args.chip, args.expect, args.fail,
                        args.timeout, args.emu_arg)


if __name__ == "__main__":
    sys.exit(main())
