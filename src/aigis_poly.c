/// Last modified at 2025年08月01日 星期五 00时08分42秒
#include "aigis_poly.h"
#include "samplers/rej_samp.c"

void enc_gen_matr(
	enc_matr res,
	const uint8_t* coins,
	int trans
) {
	int i = 0, j = 0, x, y;
	uint8_t ext_seed[AIGIS_SEED_SIZE+2];
	for (; i < AIGIS_SEED_SIZE; i ++) {
		ext_seed[i] = coins[i];
	}
	for (i = 0; i < AIGIS_ENC_K; i ++) {
		for (j = 0; j < AIGIS_ENC_K; j ++) {
			trans ? (x = j, y = i) : (x = i, y = j);
			ext_seed[AIGIS_SEED_SIZE+0] = x;
			ext_seed[AIGIS_SEED_SIZE+1] = y;
			enc_xof_and_parse(res[i][j], ext_seed, AIGIS_SEED_SIZE+2);
		}
	}
}


void sig_expand_mat(
	sig_matr_kl mat,
	const uint8_t rho[AIGIS_SEED_SIZE]
) {
	uint32_t i = 0, j = 0;
	uint8_t inp_buf[AIGIS_SEED_SIZE+2]={0},
			*out_buf = (uint8_t*)calloc(AIGIS_SIG_EXP_MATR_SIZE, 1);

	memcpy(inp_buf, rho, AIGIS_SEED_SIZE);
	for (; i < AIGIS_SIG_K; i ++) {
		for (j = 0; j < AIGIS_SIG_L; j ++) {
			inp_buf[AIGIS_SEED_SIZE] = i + (j<<4);
			sig_rej_mat(mat[i][j], out_buf, inp_buf);
		}
	}
	free(out_buf);
}

/// eta_scale 只能是 AIGIS_ENC_ETA_E_INP_SIZE
///			   或 AIGIS_ENC_ETA_S_INP_SIZE
int enc_gen_veck_via_noise(
	enc_veck res,
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
		// TODO: XOF256
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
	/// TODO: XOF256
	kdf_xof256(buf, AIGIS_ENC_ETA_E_INP_SIZE, ext_seed, AIGIS_SEED_SIZE+1);
	(void)cbd_eta(AIGIS_ENC_ETA_E, res, buf);
}

/// 多项式环上元素的加减以及频域点乘
#define ring_addition(type_name, mod_val, op_name, op)	\
void type_name##_##op_name(								\
	type_name res,										\
	const type_name a,									\
	const type_name b									\
) {														\
	for (int i = 0; i < AIGIS_N; i ++) {				\
		res[i] = mod_val + a[i] op b[i];				\
	}													\
}

ring_addition(enc_poly, 0, add, +);
ring_addition(enc_poly, 0, sub, -);
ring_addition(sig_poly, 0, add, +);
ring_addition(sig_poly, AIGIS_SIG_MOD_Q*2, sub, -);
#undef ring_addition

/// 多项式点乘
#define poly_dot_mul_gen(ty, midval_ty, mont_val)				\
void ty##_poly_dot_mul(											\
	ty##_poly res,												\
	const ty##_poly ntt_a,										\
	const ty##_poly ntt_b										\
) {																\
	for (int i = 0; i < AIGIS_N; i ++) {						\
		midval_ty tmp = ty##_mont_reduce(mont_val * ntt_a[i]);	\
		res[i] = ty##_mont_reduce(tmp * ntt_b[i]);				\
	}															\
}

poly_dot_mul_gen(enc, int32_t, AIGIS_ENC_POW_2_32_Q);
poly_dot_mul_gen(sig, uint64_t, AIGIS_SIG_POW_2_64_Q);
#undef poly_dot_mul_gen


void enc_poly_shrink_q(
	enc_poly res,
	int16_t (*shink_fn)(int16_t a)
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		res[i] = shink_fn(res[i]);
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
			// TODO: 注意到这里用了除法
			t = (((a[8*i+j]<<1)+(AIGIS_ENC_MOD_Q>>1))/AIGIS_ENC_MOD_Q) & 1;
			msg[i] |= t << j;
		}
	}
}

// 签名算法所用的多项式
void sig_poly_neg(sig_poly res) {
	for (int i = 0; i < AIGIS_N; i ++) {
		res[i] = AIGIS_SIG_MOD_Q*2 - res[i];
	}
}


// lsh := left shift
void sig_poly_lsh(sig_poly res, uint8_t k) {
	for (int i = 0; i < AIGIS_N; i ++) {
		res[i] <<= k;
	}
}

uint8_t sig_poly_check_norm(const sig_poly a, uint32_t B) {
	const int32_t x = ((AIGIS_SIG_MOD_Q-1)>>1);
	for (int i = 0; i < AIGIS_N; i ++) {
		int32_t t = x - a[i];
		t ^= (t >> 31);
		t = x - t;
		if ((uint32_t)t >= B) { return 1; }
	}
	return 0;
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


void sig_veck_lsh(sig_veck res, uint8_t k) {
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_lsh(res[i], k);
	}
}


/// 生成多项式可用的 ntt 或 inv_ntt 函数
#define ring_vec_ntt_gen(attr, vec_name, boundary, fn_name)	\
void attr##_##vec_name##_##fn_name(attr##_##vec_name res) {	\
	for (int i = 0; i < boundary; i ++) {				   	\
		attr##_##fn_name(res[i]);						   	\
	}													   	\
}

ring_vec_ntt_gen(sig, vecl, AIGIS_SIG_L, ntt);
ring_vec_ntt_gen(sig, vecl, AIGIS_SIG_L, inv_ntt);
ring_vec_ntt_gen(sig, veck, AIGIS_SIG_K, ntt);
ring_vec_ntt_gen(sig, veck, AIGIS_SIG_K, inv_ntt);
ring_vec_ntt_gen(enc, veck, AIGIS_ENC_K, ntt);
ring_vec_ntt_gen(enc, veck, AIGIS_ENC_K, inv_ntt);
#undef ring_vec_ntt_gen


/// 多项式向量的加减及矩阵运算
#define ring_vec_addition_gen(vec_name, op, boundary, poly_name)	\
void vec_name##_##op(												\
	vec_name res,													\
	const vec_name a, 												\
	const vec_name b												\
) {																	\
	for (int i = 0; i < boundary; i ++) {							\
		poly_name##_##op(res[i], a[i], b[i]);						\
	}																\
}

ring_vec_addition_gen(enc_veck, add, AIGIS_ENC_K, enc_poly);
ring_vec_addition_gen(sig_veck, add, AIGIS_SIG_K, sig_poly);
ring_vec_addition_gen(sig_veck, sub, AIGIS_SIG_K, sig_poly);
#undef ring_vec_addition_gen


void enc_veck_add_poly(
	enc_veck res,
	const enc_veck a,
	const enc_poly b
) {
	for (int i = 0; i < AIGIS_ENC_K; i ++) {
		enc_poly_add(res[i], a[i], b);
	}
}


void enc_veck_mul(
	enc_veck res,
	const enc_veck ntt_a,
	const enc_veck ntt_b
) {
	for (int i = 0; i < AIGIS_ENC_K; i ++) {
		enc_poly_dot_mul(res[i], ntt_a[i], ntt_b[i]);
		enc_inv_ntt(res[i]);
	}
}

void enc_inner_mul(
	enc_poly res,
	const enc_veck a,
	const enc_veck b
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

void enc_ntt_matr_act(
	enc_veck res,
	const enc_matr ntt_a,
	const enc_veck ntt_b
) {
	for (int i = 0; i < AIGIS_ENC_K; i ++) {
		enc_inner_mul(res[i], ntt_a[i], ntt_b);
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

void enc_veck_shrink_q(
	enc_veck res,
	int16_t (*shrink_fn)(int16_t a)
) {
	for (int i = 0; i < AIGIS_ENC_K; i ++) {
		enc_poly_shrink_q(res[i], shrink_fn);
	}
}

void sig_veck_try_shrink(
	sig_veck res,
	uint32_t (*shrink_fn)(uint32_t a)
) {
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_shrink(res[i], shrink_fn);
	}
}



void sig_poly_decomp(
	sig_poly r0,
	sig_poly r1,
	const sig_poly a
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		decompose(a[i], &r0[i], &r1[i]);
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

void sig_poly_eta_s_uniform(
	uint32_t *res,
	const uint8_t seed[AIGIS_SEED_SIZE],
	uint8_t nonce
) {
	uint8_t inp_buf[AIGIS_SEED_SIZE+2] = {0},
			*out_buf = (uint8_t*)calloc(AIGIS_SIG_2_KDF256_RATE, 1);
	for (int i = 0; i < AIGIS_SEED_SIZE; i ++) {
		inp_buf[i] = seed[i];
	}
	inp_buf[AIGIS_SEED_SIZE] = nonce;
	/// TODO: XOF256
	kdf_xof256(
		out_buf, AIGIS_SIG_2_KDF256_RATE,
		inp_buf, AIGIS_SEED_SIZE+1+(!AIGIS_KDF_CONF)
	);
	sig_rej_eta_s(res, out_buf, AIGIS_SIG_2_KDF256_RATE);
	free(out_buf);
}

void sig_poly_eta_e_uniform(
	uint32_t *res,
	const uint8_t seed[AIGIS_SEED_SIZE],
	uint8_t nonce
) {
	uint32_t pos = 0;
	uint8_t inp_buf[AIGIS_SEED_SIZE+2]={0},
			*out_buf = (uint8_t*)calloc(AIGIS_SIG_EXP_ETA_E_SIZE, 1);


	for (int i = 0; i < AIGIS_SEED_SIZE; i ++) {
		inp_buf[i] = seed[i];
	}
	inp_buf[AIGIS_SEED_SIZE] = nonce;

	// TODO: XOF256
	kdf_xof256(
		out_buf, AIGIS_SIG_2_KDF256_RATE,
		inp_buf, AIGIS_SEED_SIZE+1+(!AIGIS_KDF_CONF)
	);

	switch (AIGIS_SIG_ETA_E) {
	default:
	case 3:
		sig_rej_eta_e(
			res, AIGIS_N, out_buf,
			AIGIS_SIG_EXP_ETA_E_SIZE
		);
		break;
	case 5:
		pos = sig_rej_eta_e(
			res, 223, out_buf,
			AIGIS_SIG_EXP_ETA_E_SIZE
		);
		if (pos + 85 > AIGIS_SIG_2_KDF256_RATE) {
			/// TODO: XOF256
			kdf_xof256(
				out_buf+AIGIS_SIG_2_KDF256_RATE,
				AIGIS_SIG_KDF256_RATE,
				inp_buf, AIGIS_SEED_SIZE+1
			);
		}
		sig_rej_eta_e(
			&res[223], 33, &out_buf[pos],
			AIGIS_SIG_EXP_ETA_E_SIZE-pos
		);
	}
	free(out_buf);
}

void sig_poly_gamma1_m1_uniform(
	uint32_t *res,
	const uint8_t *seed,
	const uint16_t nonce
) {
	uint32_t i = 0, cnt = 0, pos = 0,
			 t0, t1;
	uint8_t inp_buf[AIGIS_SEED_SIZE + AIGIS_CRH_SIZE + 2],
			*out_buf = (uint8_t*)calloc(AIGIS_SIG_5_KDF256_RATE, 1);
	for (; i < AIGIS_SEED_SIZE + AIGIS_CRH_SIZE; i ++) {
		inp_buf[i] = seed[i];
	}
	inp_buf[i] = nonce & 0xFF;
	inp_buf[i+1] = nonce >> 8;
	// TODO: XOF256
	kdf_xof256(
		out_buf, AIGIS_SIG_5_KDF256_RATE,
		inp_buf, AIGIS_SEED_SIZE+AIGIS_CRH_SIZE+2
	);

	for (;
		cnt < AIGIS_N && pos < AIGIS_SIG_5_KDF256_RATE;
		pos += 5
	) {
		t0  = out_buf[pos];
		t0 |= (uint32_t)out_buf[pos + 1] << 8;
		t0 |= (uint32_t)out_buf[pos + 2] << 16;

		t1  = out_buf[pos + 2] >> 4;
		t1 |= (uint32_t)out_buf[pos + 3] << 4;
		t1 |= (uint32_t)out_buf[pos + 4] << 12;

		t0 &= 0x3FFFF;
		t1 &= 0x3FFFF;

		if (t0 <= AIGIS_SIG_GAMMA1 << 1 && cnt < AIGIS_N) {
			res[cnt++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_GAMMA1 - 1 - t0;
		}
		if (t1 <= AIGIS_SIG_GAMMA1 << 1 && cnt < AIGIS_N) {
			res[cnt++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_GAMMA1 - 1 - t1;
		}
	}

	free(out_buf);
}
