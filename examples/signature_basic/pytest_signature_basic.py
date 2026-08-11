# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
#
import pytest
from pytest_embedded import Dut


@pytest.mark.generic
def test_signature_basic(dut: Dut) -> None:
    dut.expect(r'=== VERIFY Performance Statistics', timeout=600)
