

#include "aigis_const.h"
#include "ntt.h"
#include "reduce.h"
#include "samplers/rej_samp.h"
#include "samplers/cbd.h"

#ifndef __AIGIS_POLY_H__
#define __AIGIS_POLY_H__

typedef uint32_t sig_poly[AIGIS_N]; // a_{0}+a_{1}X+...+a_{255}X^255 ~ (a0, a1, ..., a255)

/// enc_poly ~ int16_t*
typedef int16_t  enc_poly[AIGIS_N]; // a_{0}+a_{1}X+...+a_{255}X^255 ~ (a0, a1, ..., a255)

/// enc_pvec ~ int16_t**
typedef enc_poly enc_pvec[AIGIS_ENC_K];

/// enc_matr ~ int16_t***
typedef enc_pvec enc_matr[AIGIS_ENC_K];

typedef sig_poly sig_vecl[AIGIS_SIG_L];
typedef sig_poly sig_veck[AIGIS_SIG_K];

/// K * L 维矩阵
typedef sig_vecl sig_matr_kl[AIGIS_SIG_K];


void enc_gen_matr(
	enc_matr res,
	const uint8_t* coins,
	int trans
) {
	int i = 0, j = 0;
	uint8_t ext_seed[AIGIS_SEED_SIZE+2];
	for (; i < AIGIS_SEED_SIZE; i ++) {
		ext_seed[i] = coins[i];
	}
	for (i = 0; i < AIGIS_ENC_K; i ++) {
		for (j = 0; j < AIGIS_ENC_K; j ++) {
			int x, y;
			trans ? (x = j, y = i) : (x = i, y = j);
			ext_seed[AIGIS_SEED_SIZE+0] = x;
			ext_seed[AIGIS_SEED_SIZE+1] = y;
			enc_xof_and_parse(res[i][j], ext_seed, AIGIS_SEED_SIZE+2);
		}
	}
}
/// eta_scale 只能是 AIGIS_ENC_ETA_E_INP_SIZE
///			   或 AIGIS_ENC_ETA_S_INP_SIZE
int enc_gen_pvec_via_noise(
	enc_pvec res,
	size_t eta_scale,   // x * 64
	const uint8_t *seed,
	uint8_t nonce
) {
	uint8_t ext_seed[AIGIS_SEED_SIZE+1],
			*buf = (uint8_t*)malloc(eta_scale);
	int i = 0, ret = 0;
	for (; i < AIGIS_SEED_SIZE; i ++) {
		ext_seed[i] = seed[i];
	}
	for (i = 0; i < AIGIS_ENC_K; i ++) {
		ext_seed[AIGIS_SEED_SIZE] = nonce++;
		kdf_xof256(buf, eta_scale, ext_seed, AIGIS_SEED_SIZE+1);
		ret |= cbd_eta(eta_scale >> 6, res[i], buf);
	}
	free(buf);
	return ret;
}

void enc_gen_poly_in_eta_e(
	enc_poly res,
	const uint8_t *seed,
	uint8_t nonce
) {
	uint8_t ext_seed[AIGIS_SEED_SIZE+1],
			buf[AIGIS_ENC_ETA_E_INP_SIZE];
	int i = 0;
	for (; i < AIGIS_SEED_SIZE; i ++) {
		ext_seed[i] = seed[i];
	}
	ext_seed[AIGIS_SEED_SIZE] = nonce;
	// 似乎这个就是 PRF 函数
	kdf_xof256(buf, AIGIS_ENC_ETA_E_INP_SIZE, ext_seed, AIGIS_SEED_SIZE+1);
	(void)cbd_eta(AIGIS_ENC_ETA_E, res, buf);
}

/// 多项式环上元素的加减以及频域点乘

void enc_poly_sub(
	enc_poly res,
	const enc_poly a,
	const enc_poly b
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		res[i] = a[i] - b[i];
	}
}

void enc_poly_add(
	enc_poly res,
	const enc_poly a,
	const enc_poly b
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		res[i] = a[i] + b[i];
	}
}

void enc_poly_dot_mul(
	enc_poly res,
	const enc_poly ntt_a,
	const enc_poly ntt_b
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		int32_t tmp = enc_mont_reduce(AIGIS_ENC_POW_2_32_Q * ntt_b[i]);
		res[i] = enc_mont_reduce(tmp * ntt_a[i]);
	}
}


void enc_poly_shrink_q(
	enc_poly res,
	int16_t (*shink_fn)(int16_t a)
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		res[i] = shink_fn(res[i]);
	}
}


/// 加解密相关函数
void enc_poly_from_msg(
	enc_poly res,
	const uint8_t msg[AIGIS_SEED_SIZE]
) {
	uint16_t i, j, mask;

	for (i = 0; i < AIGIS_SEED_SIZE; i++) {
		for (j = 0; j < 8; j++) {
			mask = -((msg[i] >> j) & 1);
			res[8*i+j] = mask & ((AIGIS_ENC_MOD_Q+1)>>1);
		}
	}
}
void enc_poly_to_msg(
	uint8_t msg[AIGIS_SEED_SIZE],
	const enc_poly a
) {
	uint16_t t;
	int i, j;

	for (i = 0; i < AIGIS_SEED_SIZE; i++) {
		msg[i] = 0;
		for (j = 0; j < 8; j++) {
			t = (((a[8*i+j]<<1) + (AIGIS_ENC_MOD_Q>>1))/AIGIS_ENC_MOD_Q) & 1;
			msg[i] |= t << j;
		}
	}
}

// 签名算法所用的多项式
void sig_poly_dot_mul(
	sig_poly res,
	const sig_poly ntt_a,
	const sig_poly ntt_b
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		uint64_t tmp = sig_mont_reduce(AIGIS_SIG_POW_2_64_Q * ntt_b[i]);
		res[i] = sig_mont_reduce(tmp * ntt_a[i]);
	}
}

void sig_poly_add(
	sig_poly res,
	const sig_poly a,
	const sig_poly b
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		res[i] = a[i] + b[i];
	}
}

void sig_poly_sub(
	sig_poly res,
	const sig_poly a,
	const sig_poly b
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		res[i] = AIGIS_SIG_MOD_Q*2 + a[i] - b[i];
	}
}

void sig_poly_neg(sig_poly res) {
	for (int i = 0; i < AIGIS_N; i ++) {
		res[i] = AIGIS_SIG_MOD_Q*2 - res[i];
	}
}

void sig_poly_shrink(
	sig_poly res,
	uint32_t (*shrink_fn)(uint32_t a)
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		res[i] = shrink_fn(res[i]);
	}
}

// lsh := left shift
void sig_poly_lsh(sig_poly res, uint8_t k) {
	for (int i = 0; i < AIGIS_N; i ++) {
		res[i] <<= k;
	}
}

uint8_t sig_poly_check_norm(
	const sig_poly a,
	uint32_t B
) {
	int32_t t;
	const int32_t x = ((AIGIS_SIG_MOD_Q-1)>>1);
	for (int i = 0; i < AIGIS_N; i ++) {
		t = x - a[i];
		t ^= (t >> 31);
		t = x - t;
		if ((uint32_t)t >= B) { return 1; }
	}
	return 0;
}

void sig_veck_sub(
	sig_veck res,
	const sig_veck a,
	const sig_veck b
) {
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_sub(res[i], a[i], b[i]);
	}
}

void sig_veck_pow2round(sig_veck r0, sig_veck r1) {
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		for (int j = 0; j < AIGIS_N; j ++) {
			sig_pow2round(r0[i]+j, r1[i]+j);
		}
	}
}

uint32_t sig_veck_make_hint(
	sig_veck res,
	const sig_veck u,
	const sig_veck h
) {
	uint32_t ret = 0;
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		for (int j = 0; j < AIGIS_N; j ++) {
			res[i][j] = make_hint(u[i][j], h[i][j]);
			ret += res[i][j];
		}
	}
	return ret;
}

void sig_veck_use_hint(
	sig_veck res,
	const sig_veck u,
	const sig_veck h
) {
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		for (int j = 0; j < AIGIS_N; j ++) {
			res[i][j] = use_hint(u[i][j], h[i][j]);
		}
	}
}


void sig_veck_lsh(
	sig_veck res,
	uint8_t k
) {
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_lsh(res[i], k);
	}
}


void sig_veck_add(
	sig_veck res,
	const sig_veck a,
	const sig_veck b
) {
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_add(res[i], a[i], b[i]);
	}

}

#define generic_sig_vec_ntt_gen(attr, vec_name, boundary, fn_name)	\
void attr##_##vec_name##_##fn_name(attr##_##vec_name res) {			\
	for (int i = 0; i < boundary; i ++) {							\
		attr##_##fn_name(res[i]);									\
	}																\
}

generic_sig_vec_ntt_gen(sig, vecl, AIGIS_SIG_L, ntt);
generic_sig_vec_ntt_gen(sig, vecl, AIGIS_SIG_L, inv_ntt);
generic_sig_vec_ntt_gen(sig, veck, AIGIS_SIG_K, ntt);
generic_sig_vec_ntt_gen(sig, veck, AIGIS_SIG_K, inv_ntt);
generic_sig_vec_ntt_gen(enc, pvec, AIGIS_ENC_K, ntt);
generic_sig_vec_ntt_gen(enc, pvec, AIGIS_ENC_K, inv_ntt);

#undef generic_sig_vec_ntt_gen 

void sig_veck_try_shrink(
	sig_veck res,
	uint32_t (*shrink_fn)(uint32_t a)
) {
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_shrink(res[i], shrink_fn);
	}
}


/// 多项式向量的加减及矩阵运算
void enc_pvec_add(
	enc_pvec res,
	const enc_pvec a,
	const enc_pvec b
) {
	for (int i = 0; i < AIGIS_ENC_K; i ++) {
		enc_poly_add(res[i], a[i], b[i]);
	}
}

void enc_pvec_add_poly(
	enc_pvec res,
	const enc_pvec a,
	const enc_poly b
) {
	for (int i = 0; i < AIGIS_ENC_K; i ++) {
		enc_poly_add(res[i], a[i], b);
	}
}


void enc_pvec_mul(
	enc_pvec res,
	enc_pvec ntt_a,
	enc_pvec ntt_b
) {
	for (int i = 0; i < AIGIS_ENC_K; i ++) {
		enc_poly_dot_mul(res[i], ntt_a[i], ntt_b[i]);
		enc_inv_ntt(res[i]);
	}
}

void enc_inner_mul(
	enc_poly res,
	const enc_pvec a,
	const enc_pvec b
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		int32_t tmp = enc_mont_reduce(AIGIS_ENC_POW_2_32_Q * b[0][i]);
		res[i] = enc_mont_reduce(tmp * a[0][i]);
		for (int j = 1; j < AIGIS_ENC_K; j ++) {
			tmp = enc_mont_reduce(AIGIS_ENC_POW_2_32_Q * b[j][i]);
			res[i] += enc_mont_reduce(tmp * a[j][i]);
		}
		res[i] = enc_barr_reduce(res[i]);
	}
}

void enc_ntt_matr_act(
	enc_pvec res,
	const enc_matr ntt_a,
	const enc_pvec ntt_b
) {
	for (int i = 0; i < AIGIS_ENC_K; i ++) {
		enc_inner_mul(res[i], ntt_a[i], ntt_b);
	}
}

void enc_pvec_shrink_q(
	enc_pvec res,
	int16_t (*shrink_fn)(int16_t a)
) {
	for (int i = 0; i < AIGIS_ENC_K; i ++) {
		enc_poly_shrink_q(res[i], shrink_fn);
	}
}



void sig_inner_mul_vecl(
	sig_poly res,
	const sig_vecl a,
	const sig_vecl b
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		uint64_t tmp = sig_mont_reduce(AIGIS_SIG_POW_2_64_Q * a[0][i]);
		res[i] = sig_mont_reduce(tmp * b[0][i]);
		for (int j = 1; j < AIGIS_SIG_L; j ++) {
			tmp = sig_mont_reduce(AIGIS_SIG_POW_2_64_Q * a[j][i]);
			res[i] += sig_mont_reduce(tmp * b[j][i]);
		}
		res[i] = sig_barr_reduce(res[i]);
	}
}

void sig_matr_kl_ntt_act(
	sig_veck res,
	const sig_matr_kl mat,
	const sig_vecl vecl
) {
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		sig_inner_mul_vecl(res[i], mat[i], vecl);
		sig_inv_ntt(res[i]);
	}
}

void sig_poly_decomp(
	sig_poly r0,
	sig_poly r1,
	const sig_poly a
) {
	for (int j = 0; j < AIGIS_N; j ++) {
		decompose(a[j], &r0[j], &r1[j]);
	}
}

void sig_veck_decomp(
	sig_veck r0,
	sig_veck r1,
	const sig_veck a
) {
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_decomp(r0[i], r1[i], a[i]);
	}
}

#endif // AIGIS_POLY_H
