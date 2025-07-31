/// Last modified at 2025年07月14日 星期一 12时19分26秒
/// Author: <kisfg@hotmail.com, 2025-06>
#include "aigis_const.h"
#ifndef __AIGIS_REDUCE_H__
#define __AIGIS_REDUCE_H__

/// 返回 a / 2^o + 0.5
static int16_t m(int16_t a, uint8_t o) {
	return (a + (1u << (o-1))) >> o;
}

int16_t enc_barr_reduce(int16_t a);
int16_t enc_mont_reduce(int32_t a);
int16_t enc_nq_q(int16_t a);
int16_t enc_n2q_q(int16_t a);
uint32_t sig_barr_reduce(uint32_t a);
uint32_t sig_mont_reduce(uint64_t a);
uint32_t sig_try_shrink(uint32_t a);
uint32_t sig_try_shrink2(uint32_t a);
void sig_pow2round(uint32_t *r, uint32_t *r1);
void decompose(uint32_t a, uint32_t *a0, uint32_t *a1);
uint32_t make_hint(const uint32_t a, const uint32_t b);
uint32_t use_hint(const uint32_t a, const uint32_t hint);

#endif // AIGIS_REDUCE_H
