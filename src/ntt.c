/// Last modified at 2025年07月14日 星期一 12时16分43秒
#include "ntt.h"

void enc_ntt(int16_t a[AIGIS_N]) {
	int64_t level = 7, cnt = 0, step;
	for (; level >= 0; level--) {
		step = 1 << level;
		for (uint64_t st_pos = 0; st_pos < AIGIS_N; st_pos += step << 1) {
			int32_t g = zeta_7681_R[cnt++];
			for (uint64_t i = st_pos; i < st_pos + step; i ++) {
				int16_t tmp = enc_mont_reduce(g * a[i+step]);
				a[i+step] = enc_barr_reduce(a[i] - tmp);
				a[i] = enc_barr_reduce(a[i] + tmp);
			}
		}
	}
}

void enc_inv_ntt(int16_t a[AIGIS_N]) {
	int64_t level = 0, cnt = 0, step;
	for (; level < 8; level ++) {
		step = 1 << level;
		for (uint64_t st_pos = 0; st_pos < AIGIS_N; st_pos += step << 1) {
			int32_t g = zeta_7681_inv_R[cnt++];
			for (uint64_t i = st_pos; i < st_pos + step; i++) {
				int16_t tmp = a[i+step];
				a[i+step] = a[i] - tmp;
				a[i] += tmp;
				a[i+step] = enc_mont_reduce(g * a[i+step]);

				/// a[i] = enc_mont_reduce((int32_t)a[i] * AIGIS_ENC_POW_2_15_Q);
				/*
					2044 = 2 ** 15 mod 7681
					不使用以上采用 2^16/2*g^{-1} 时的写法，
					而想要为少几次乘法的性能优化使用 2^16*g_x^{-1} 和 2^8*g_0^{-1}
					其中 x in {1, 2, 3, 4, 5, 6, 7} 时
					需要按照下面的写法来
				*/
				a[i] =  level ^ 7 ?
						enc_barr_reduce(a[i]) :
						enc_mont_reduce((int32_t)a[i] << 8);
			}
		}
	}
}

void sig_ntt(uint32_t a[AIGIS_N]) {
	uint64_t step = AIGIS_N >> 1, cnt = 0, st_pos;
	for (; step; step >>= 1) {
		for (st_pos = 0; st_pos < AIGIS_N; st_pos += step << 1) {
			uint64_t zeta = sig_zeta_R[cnt++];
			for (uint64_t i = st_pos; i < st_pos + step; i ++) {
				uint32_t tmp = sig_mont_reduce(zeta * a[i+step]);
				a[i+step] = a[i] + (AIGIS_SIG_MOD_Q << 1) - tmp;
				a[i] += tmp;
			}
		}
	}
}

void sig_inv_ntt(uint32_t a[AIGIS_N]) {
	uint64_t step = 1, cnt = 0, st_pos;
	for (; step < AIGIS_N; step <<= 1) {
		for (st_pos = 0; st_pos < AIGIS_N; st_pos += step << 1) {
			uint64_t zeta = sig_zeta_inv_R[cnt++];
			for (uint64_t i = st_pos; i < st_pos + step; i ++) {
				uint32_t tmp = a[i];
				a[i] = sig_barr_reduce(tmp + a[i+step]);
				tmp += (AIGIS_SIG_MOD_Q<<9) - a[i + step];
				a[i+step] = sig_mont_reduce(zeta * tmp);
			}
		}
	}
	// 原先用2^56是因为32+24=56.
	// 上一步做完还一直有2^8，所以总共是2^64 mod q
	// 在下一步的循环内减少2^32，那么在结果上看
	// 最终得到2^32*a[i] (mod q)
	// 可直接用于后续的mont_reduce上
	for (step = 0; step < AIGIS_N >> 1; step ++) {
		// 如法炮制不多阐述
		a[step] = sig_mont_reduce(AIGIS_SIG_POW_2_24_Q * a[step]);
	}
}
