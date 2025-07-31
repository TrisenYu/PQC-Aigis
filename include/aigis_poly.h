/// Last modified at 2025年07月31日 星期四 17时45分48秒

#include "ntt.h"
#include "reduce.h"
#include "aigis_const.h"

#include "samplers/rej_samp.h"
#include "samplers/cbd.h"

#ifndef __AIGIS_POLY_H__
#define __AIGIS_POLY_H__

typedef uint32_t sig_poly[AIGIS_N]; // a_{0}+a_{1}X+...+a_{255}X^255 ~ (a0, a1, ..., a255)
typedef int16_t  enc_poly[AIGIS_N]; // a_{0}+a_{1}X+...+a_{255}X^255 ~ (a0, a1, ..., a255)
typedef enc_poly enc_veck[AIGIS_ENC_K];
typedef enc_veck enc_matr[AIGIS_ENC_K];
typedef sig_poly sig_vecl[AIGIS_SIG_L];
typedef sig_poly sig_veck[AIGIS_SIG_K];

/// K * L 维矩阵
typedef sig_vecl sig_matr_kl[AIGIS_SIG_K];

#define ring_addition(type_name, op_name)	\
void type_name##_##op_name(					\
	type_name res,							\
	const type_name a,						\
	const type_name b						\
)

ring_addition(enc_poly, add);
ring_addition(enc_poly, sub);
ring_addition(sig_poly, add);
ring_addition(sig_poly, sub);
#undef ring_addition

/// 多项式点乘
#define poly_dot_mul_gen(ty)									\
void ty##_poly_dot_mul(											\
	ty##_poly res,												\
	const ty##_poly ntt_a,										\
	const ty##_poly ntt_b										\
)

poly_dot_mul_gen(enc);
poly_dot_mul_gen(sig);
#undef poly_dot_mul_gen

/// 生成多项式可用的 ntt 或 inv_ntt 函数
#define ring_vec_ntt_gen(attr, vec_name, fn_name)	\
void attr##_##vec_name##_##fn_name(attr##_##vec_name res)

ring_vec_ntt_gen(sig, vecl, ntt);
ring_vec_ntt_gen(sig, vecl, inv_ntt);
ring_vec_ntt_gen(sig, veck, ntt);
ring_vec_ntt_gen(sig, veck, inv_ntt);
ring_vec_ntt_gen(enc, veck, ntt);
ring_vec_ntt_gen(enc, veck, inv_ntt);
#undef ring_vec_ntt_gen


/// 多项式向量的加减及矩阵运算
#define ring_vec_addition_gen(vec_name, op)	\
void vec_name##_##op(						\
	vec_name res,							\
	const vec_name a, 						\
	const vec_name b						\
)

ring_vec_addition_gen(enc_veck, add);
ring_vec_addition_gen(sig_veck, add);
ring_vec_addition_gen(sig_veck, sub);
#undef ring_vec_addition_gen

void enc_gen_matr(
	enc_matr res,
	const uint8_t* coins,
	int trans
);
void sig_expand_mat(
	sig_matr_kl mat,
	const uint8_t rho[AIGIS_SEED_SIZE]
);
int enc_gen_veck_via_noise(
	enc_veck res,
	size_t eta_scale,   // x * 64
	const uint8_t *seed,
	uint8_t nonce
);
void enc_gen_poly_in_eta_e(
	enc_poly res,
	const uint8_t *seed,
	uint8_t nonce
);
void enc_poly_shrink_q(
	enc_poly res,
	int16_t (*shink_fn)(int16_t a)
);
void sig_poly_shrink(
	sig_poly res,
	uint32_t (*shrink_fn)(uint32_t a)
);
void enc_poly_from_msg(
	enc_poly res,
	const uint8_t msg[AIGIS_SEED_SIZE]
);
void enc_poly_to_msg(
	uint8_t msg[AIGIS_SEED_SIZE],
	const enc_poly a
);
void sig_poly_neg(sig_poly res);
void sig_poly_lsh(sig_poly res, uint8_t k);
uint8_t sig_poly_check_norm(const sig_poly a, uint32_t B);
void sig_veck_pow2round(sig_veck r0, sig_veck r1);
uint32_t sig_veck_make_hint(
	sig_veck res,
	const sig_veck u,
	const sig_veck h
);
void sig_veck_use_hint(
	sig_veck res,
	const sig_veck u,
	const sig_veck h
);
void sig_veck_lsh(sig_veck res, uint8_t k);
void enc_veck_add_poly(
	enc_veck res,
	const enc_veck a,
	const enc_poly b
);
void enc_veck_mul(
	enc_veck res,
	const enc_veck ntt_a,
	const enc_veck ntt_b
);
void enc_inner_mul(
	enc_poly res,
	const enc_veck a,
	const enc_veck b
);
void sig_inner_mul_vecl(
	sig_poly res,
	const sig_vecl a,
	const sig_vecl b
);
void enc_ntt_matr_act(
	enc_veck res,
	const enc_matr ntt_a,
	const enc_veck ntt_b
);
void sig_matr_kl_ntt_act(
	sig_veck res,
	const sig_matr_kl mat,
	const sig_vecl vecl
);
void enc_veck_shrink_q(
	enc_veck res,
	int16_t (*shrink_fn)(int16_t a)
);
void sig_veck_try_shrink(
	sig_veck res,
	uint32_t (*shrink_fn)(uint32_t a)
);
void sig_poly_decomp(
	sig_poly r0,
	sig_poly r1,
	const sig_poly a
);
void sig_veck_decomp(
	sig_veck r0,
	sig_veck r1,
	const sig_veck a
);
void sig_poly_eta_s_uniform(
	uint32_t *res,
	const uint8_t seed[AIGIS_SEED_SIZE],
	uint8_t nonce
);
void sig_poly_eta_e_uniform(
	uint32_t *res,
	const uint8_t seed[AIGIS_SEED_SIZE],
	uint8_t nonce
);
void sig_poly_gamma1_m1_uniform(
	uint32_t *res,
	const uint8_t *seed,
	const uint16_t nonce
);
#endif // AIGIS_POLY_H
