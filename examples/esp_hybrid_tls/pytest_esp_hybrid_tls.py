# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0


import pytest
from pytest_embedded import Dut


@pytest.mark.wifi_router
@pytest.mark.parametrize(
    'target',
    ['esp32c5'],
    indirect=True,
)
def test_esp_hybrid_tls(dut: Dut) -> None:
    dut.expect(r'\*\*\* TLS 1.3 handshake SUCCESS \*\*\*', timeout=120)
    dut.expect('X.509 verify flags: none', timeout=30)
    dut.expect('TLS session closed cleanly', timeout=120)
