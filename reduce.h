/// Last modified at 2025年07月12日 星期六 22时55分04秒
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
	/* 注释以下两行后，仍保证返回值处于 [-3841, 3840]
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

// (-q, q) -> (0, q)
int16_t enc_nq_q(int16_t a) {
	return a + ((a >> 15) & AIGIS_ENC_MOD_Q); // 只有负数才会产生 0xFFFF
}

// (-2q, q) -> (0, q)
int16_t enc_n2q_q(int16_t a) {
	return enc_nq_q(enc_nq_q(a));
}

/// 返回 a 2^{-22 or -23} mod 7681.
uint32_t sig_barr_reduce(uint32_t a) {
	return a - (a >> AIGIS_SIG_QBITS) * AIGIS_SIG_MOD_Q;
}

/// (a - aqQinv) / 2^32 ~ a / 2^32 (mod q)
uint32_t sig_mont_reduce(uint64_t a) {
	uint64_t t = (a * AIGIS_SIG_NEG_QINV) & 0xFFFFFFFFu;
	return (a + t * AIGIS_SIG_MOD_Q) >> 32;
}

uint32_t sig_try_shrink(uint32_t a) {
	a -= AIGIS_SIG_MOD_Q;
	return a + (((int32_t)a >> 31) & AIGIS_SIG_MOD_Q);
}

uint32_t sig_try_shrink2(uint32_t a) {
	a -= AIGIS_SIG_MOD_Q << 1;
	a += ((int32_t)a >> 31) & (AIGIS_SIG_MOD_Q<<1);
	return sig_try_shrink(a);
}

void sig_pow2round(uint32_t *r, uint32_t *r1) {
	int32_t t = (*r) & ((1 << AIGIS_SIG_D) - 1);
	t -= (1 << (AIGIS_SIG_D - 1)) + 1;
	t += (t >> 31) & (1 << AIGIS_SIG_D);
	t -= (1 << (AIGIS_SIG_D - 1)) - 1;
	*r1 = (*r - t) >> AIGIS_SIG_D;
	*r = AIGIS_SIG_MOD_Q + t;
}

/// 返回值作为 a1
void decompose(uint32_t a, uint32_t *a0, uint32_t *a1) {
	int32_t u = ((a*3)>>AIGIS_SIG_DECOMP_BITS) + 1,
			t = a - u*AIGIS_SIG_ALPHA;
	u -= (t>>31) & 0b1;
	t += (t>>31) & AIGIS_SIG_ALPHA;

	t -= (AIGIS_SIG_ALPHA>>1) | 1;
	t += (t>>31) & AIGIS_SIG_ALPHA;
	t -= (AIGIS_SIG_ALPHA>>1) - 1;

	a = u + ((t>>31)&0b1);
	uint32_t s = (a == 6);
	*a0 = AIGIS_SIG_MOD_Q + t - s;
	*a1 = s ? 0 : a;
}


uint32_t make_hint(const uint32_t a, const uint32_t b) {
	uint32_t r, r1, r2;
	decompose(a, &r, &r1);
	decompose(sig_try_shrink2(a+b), &r, &r2);
	return r1 != r2;
}

uint32_t use_hint(const uint32_t a, const uint32_t hint) {
	uint32_t a0, a1;
	decompose(a, &a0, &a1);
	if (!hint) {
		return a1;
	} else if (a0 > AIGIS_SIG_MOD_Q) {
		return (a1 == (AIGIS_SIG_MOD_Q-1)/AIGIS_SIG_ALPHA - 1) ? 0 : a1+1;
	}
	return (!a1) ? (AIGIS_SIG_MOD_Q-1)/AIGIS_SIG_ALPHA - 1 : a1-1;
}

#endif // AIGIS_REDUCE_H
