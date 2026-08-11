/* SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 * SPDX-License-Identifier: Apache-2.0
 * ML-DSA TLSF alloc hooks; -include when CONFIG_PQC_MEM_TLSF=y. */
#ifndef PQC_MLD_ALLOC_H
#define PQC_MLD_ALLOC_H

#include <stddef.h>

void *pqc_tlsf_alloc(size_t size);
void pqc_tlsf_free(void *ptr, size_t size);

#define MLD_CUSTOM_ALLOC(v, T, N) \
    T *v = (T *)pqc_tlsf_alloc(sizeof(T) * (N))

#define MLD_CUSTOM_FREE(v, T, N) \
    pqc_tlsf_free((void *)(v), sizeof(T) * (N))

#endif /* PQC_MLD_ALLOC_H */
