

#include "aigis_const.h"
#include "ntt.h"
#include "reduce.h"
#include "samplers/rej_samp.h"
#include "samplers/cbd.h"
#ifdef __DEBUG
#include <stdio.h>
#endif //DEBUG
#ifndef __AIGIS_POLY_H__
#define __AIGIS_POLY_H__

typedef uint32_t sig_poly[AIGIS_N]; // a_{0}+a_{1}X+...+a_{255}X^255 ~ (a0, a1, ..., a255)

/// typedef int16_t *enc_poly.
typedef int16_t  enc_poly[AIGIS_N]; // a_{0}+a_{1}X+...+a_{255}X^255 ~ (a0, a1, ..., a255)

/// typedef int16_t **enc_pvec.
typedef enc_poly enc_pvec[AIGIS_ENC_K];

/// typedef int16_t ***enc_matr.
typedef enc_pvec enc_matr[AIGIS_ENC_K]; // [AIGIS_ENC_K];

typedef sig_poly sig_vecl[AIGIS_SIG_L];// [AIGIS_SIG_L];
typedef sig_poly sig_veck[AIGIS_SIG_K];// [AIGIS_SIG_K];



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
            aigis_xof_and_parse(res[i][j], ext_seed, AIGIS_SEED_SIZE+2);
        }
    }
}
/// eta_scale 只能是 AIGIS_ENC_ETA_E_INP_SIZE
///               或 AIGIS_ENC_ETA_S_INP_SIZE
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
	buf=NULL;
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


void enc_poly_nq_q(enc_poly res) {
    for (int i = 0; i < AIGIS_N; i ++) {
        res[i] = enc_nq_q(res[i]);
    }
}

void enc_poly_n2q_q(enc_poly res) {
    for (int i = 0; i < AIGIS_N; i ++) {
        res[i] = enc_n2q_q(res[i]);
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
			res[8*i+j] = mask & ((AIGIS_ENC_MOD_Q+1) / 2);
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

// 签名算法
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

void enc_pvec_ntt(enc_pvec res) {
    for (int i = 0; i < AIGIS_ENC_K; i ++) {
        enc_ntt(res[i]);
    }
}

void enc_pvec_inv_ntt(enc_pvec res) {
    for (int i = 0; i < AIGIS_ENC_K; i ++) {
        enc_inv_ntt(res[i]);
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



void enc_pvec_nq_q(enc_pvec res) {
    for (int i = 0; i < AIGIS_ENC_K; i ++) {
        enc_poly_nq_q(res[i]);
    }
}

void enc_pvec_n2q_q(enc_pvec res) {
    for (int i = 0; i < AIGIS_ENC_K; i ++) {
        enc_poly_n2q_q(res[i]);
    }
}

#endif // AIGIS_POLY_H
