/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
//
// Local declarations for ML-KEM timing profiling functions.
// These functions are implemented in the mlkem-native library
// (esp-liboqs component) and linked in at build time.

#ifndef KEM_TIMING_H
#define KEM_TIMING_H

#ifdef __cplusplus
extern "C" {
#endif

/* Timing profiling structure for ML-KEM operations */
typedef struct {
    /* Keypair generation timings */
    double keypair_total;
    double keypair_indcpa_keypair;
    double keypair_hash_h;
    double keypair_pct;

    /* Encapsulation timings */
    double enc_total;
    double enc_modulus_check;
    double enc_hash_h;
    double enc_hash_g;
    double enc_indcpa_enc;
    double enc_finalize;
    /* IndCPA enc sub-stages (detailed) */
    double enc_indcpa_unpack;
    double enc_indcpa_mat_gen;
    double enc_indcpa_noise;
    double enc_indcpa_ntt_mvmul;
    double enc_indcpa_invntt_pack;

    /* Decapsulation timings */
    double dec_total;
    double dec_hash_check;
    double dec_indcpa_dec;
    double dec_hash_g;
    double dec_reencrypt;
    double dec_memcmp;
    double dec_hash_j;
    double dec_cmov;
    /* IndCPA dec sub-stages (detailed) */
    double dec_indcpa_unpack;
    double dec_indcpa_ntt_mvmul;
    double dec_indcpa_invntt;
    double dec_indcpa_finish;
} mlkem_timing_data_t;

/* Global timing data - defined in the mlkem-native library */
extern mlkem_timing_data_t g_mlkem_timings;

/* Helper functions for timing management */
void mlkem_reset_timings(void);
void mlkem_print_timings_single_line(void);
mlkem_timing_data_t *mlkem_get_timings(void);

#ifdef __cplusplus
}
#endif

#endif /* KEM_TIMING_H */
