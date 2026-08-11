/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PQC_STACK_H
#define PQC_STACK_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Run fn() with the PQC stack in SRAM (see .dram0.pqc_stack in bootloader.ld.in).
 * Use this for PQC verification that needs a large stack.
 *
 * @return return value of fn()
 */
int run_with_pqc_stack(int (*fn)(void));

#ifdef __cplusplus
}
#endif

#endif /* PQC_STACK_H */
