/// Last modified at 2025年07月31日 星期四 16时04分44秒
#include "../aigis_const.h"
/// TODO: KDF
#include "../hash/kdf_aux.h"
#include <stdint.h>

#ifndef __AIGIS_REJ_SAMP_H__
#define __AIGIS_REJ_SAMP_H__


static uint16_t _8to16(uint8_t x) { return (uint16_t)(x); }

/*
	目前只支持enc_mod=7681的情况
	12289有14位，还需要评估对其它模块的影响。比如ntt的单位根、eta采样等。
*/
void sig_rej_mat(
	uint32_t res_poly[AIGIS_N],
	uint8_t out_buf[AIGIS_SIG_EXP_MATR_SIZE],
	const uint8_t *inp_buf
);
static void _sig_mat_qbits_22_mode(
	uint32_t res_poly[AIGIS_N],
	uint8_t *out_buf,
	/// TODO: KDF
	kdf_state *state
);
static void _sig_mat_qbits_21_mode(
	uint32_t *res_poly,
	const uint8_t *out_buf
);
uint32_t sig_rej_eta_e(
	uint32_t *a,
	uint32_t len,
	const uint8_t *buf,
	uint64_t buf_len
);
void sig_rej_eta_s(
	uint32_t *a,
	const uint8_t *buf,
	uint64_t buf_len
);
void enc_xof_and_parse(
	int16_t *coeff,
	const uint8_t* seed,
	uint64_t seed_size
);
static uint16_t enc_rej_sampler(
	int16_t *res,
	uint32_t *res_cnt,
	const uint8_t *buf,
	uint64_t buf_size
);
static uint16_t enc_read_qbits(
	const uint8_t *buf,
	uint64_t st_pos,
	uint8_t ofs
);
#endif // AIGIS_REJ_SAMP_H
