/// Author: <kisfg@hotmail.com, 2025-06>
#include "aigis_const.h"
#ifndef __AIGIS_REDUCE_H__
#define __AIGIS_REDUCE_H__


/// 返回 a / 2^o + 0.5
static int16_t m(int16_t a, uint8_t o) {
    return (a + (1u << (o-1))) >> o; 
}

int16_t enc_barr_reduce(int16_t a) {
    int16_t t = m(a, 13) * AIGIS_ENC_MOD_Q;
    /* 注释此处，保证返回值处于 [-3841, 3840]
        while (a < 0) { a += AIGIS_ENC_MOD_Q; }
        while (a >= AIGIS_ENC_MOD_Q) { a += AIGIS_ENC_MOD_Q; }
    */
    return a - t;
}

/// 返回 a 2^{-16} mod 7681.
int16_t enc_mont_reduce(int32_t a) {
    int16_t tmp = (int16_t)(a * AIGIS_ENC_NEG_QINV);
    return (a + (int32_t)tmp * AIGIS_ENC_MOD_Q) >> 16;
}

int16_t enc_nq_q(int16_t a) {
    return a + ((a >> 15) & AIGIS_ENC_MOD_Q); // 只有负数才会产生 0xFFFF
}

int16_t enc_n2q_q(int16_t a) {
    return enc_nq_q(enc_nq_q(a));
}

uint32_t sig_barr_reduce(uint32_t a) {
    return a - (a >> AIGIS_SIG_QBITS) * AIGIS_SIG_MOD_Q;
}

/// (a - aqQinv) / 2^32 ~ a / 2^32 (mod q)
uint32_t sig_mont_reduce(uint64_t a) {
    uint64_t t = (a * AIGIS_SIG_NEG_QINV) & 0xFFFFFFFFu;
    return (a + t * AIGIS_SIG_MOD_Q) >> 32; 
}

#endif // AIGIS_REDUCE_H
