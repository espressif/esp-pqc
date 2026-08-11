/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sdkconfig.h"

    .text
    .align  2
    .global run_with_pqc_stack

run_with_pqc_stack:
    addi    sp, sp, -16
    sw      ra, 8(sp)
    sw      s0, 0(sp)
    mv      s0, sp                  
#if defined(CONFIG_PQC_MEM_TLSF)
    la      t0, pqc_stack_top       
    lw      sp, 0(t0)               
#else
    la      sp, _pqc_stack_end      
#endif
    jalr    ra, 0(a0)               
    mv      sp, s0                 
    lw      s0, 0(sp)
    lw      ra, 8(sp)
    addi    sp, sp, 16
    ret
