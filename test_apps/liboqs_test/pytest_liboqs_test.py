# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
#
# pytest runner for the esp-liboqs Unity test app.
#
# The CI configs (sdkconfig.ci.default / sdkconfig.ci.stack_only) set
# CONFIG_LIBOQS_TEST_RUN_ALL_ON_BOOT=y, so the app runs every Unity case on boot
# and prints the summary — no interactive menu. We assert on that summary via
# pytest-embedded's Unity parser (fails on any non-zero Unity failure count).
# This is the hardware / QEMU lane; CI itself runs these builds under esp-emu
# (see emu_liboqs_test in .gitlab-ci.yml), which shares the same auto-run marker.
#
#   pytest --target esp32c3 --preview
#   pytest --target esp32     # Xtensa, reference C paths
import pytest
from pytest_embedded_idf.dut import IdfDut


@pytest.mark.generic
@pytest.mark.parametrize(
    'config',
    ['default', 'stack_only'],
    indirect=True,
)
def test_liboqs(dut: IdfDut) -> None:
    # ML-DSA / ML-KEM keygen+sign+verify can take a few seconds per case.
    dut.expect_unity_test_output(timeout=120)
