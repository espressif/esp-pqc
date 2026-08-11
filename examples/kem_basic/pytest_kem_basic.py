# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
#
import pytest
from pytest_embedded import Dut


@pytest.mark.generic
def test_kem_basic(dut: Dut) -> None:
    # ML-KEM-768 keygen + encaps + decaps over 20 iterations.
    dut.expect('iterations completed successfully', timeout=300)
    dut.expect('Example complete!', timeout=30)
