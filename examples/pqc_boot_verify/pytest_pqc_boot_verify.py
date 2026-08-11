# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
#
import pytest
from pytest_embedded import Dut


@pytest.mark.secure_boot
@pytest.mark.parametrize(
    'target',
    ['esp32c3'],
    indirect=True,
)
def test_pqc_boot_verify(dut: Dut) -> None:
    dut.expect('PQC verification successful', timeout=120)
    dut.expect('Secure boot and flash encryption enabled', timeout=30)
    dut.expect('PQC verification is also enabled', timeout=30)
