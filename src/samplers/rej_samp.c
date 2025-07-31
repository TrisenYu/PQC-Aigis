/// Last modified at 2025年07月31日 星期四 16时05分06秒
#include "samplers/rej_samp.h"
static uint16_t enc_read_qbits(
	const uint8_t *buf,
	uint64_t st_pos,
	uint8_t ofs
) {
	switch (ofs) {
	case 1: // 7 + {6, 7}
		return (buf[st_pos] >> 1 | (_8to16(buf[st_pos+1]) << 7)) & 0x1FFF;
	case 2: // 6 + {7, 8}
		return (buf[st_pos] >> 2 | (_8to16(buf[st_pos+1]) << 6)) & 0x1FFF;
	case 3: // 5 + 8 + {0, 1}
		return (buf[st_pos] >> 3 | (_8to16(buf[st_pos+1]) << 5) | (_8to16(buf[st_pos+2]) << AIGIS_ENC_QBITS)) & 0x1FFF;
	case 4: // 4 + 8 + {1, 2}
		return (buf[st_pos] >> 4 | (_8to16(buf[st_pos+1]) << 4) | (_8to16(buf[st_pos+2]) << 12)) & 0x1FFF;
	case 5: // 3 + 8 + {2, 3}
		return (buf[st_pos] >> 5 | (_8to16(buf[st_pos+1]) << 3) | (_8to16(buf[st_pos+2]) << 11)) & 0x1FFF;
	case 6: // 2 + 8 + {3, 4}
		return (buf[st_pos] >> 6 | (_8to16(buf[st_pos+1]) << 2) | (_8to16(buf[st_pos+2]) << 10)) & 0x1FFF;
	case 7: // 1 + 8 + {4, 5}
		return (buf[st_pos] >> 7 | (_8to16(buf[st_pos+1]) << 1) | (_8to16(buf[st_pos+2]) << 9)) & 0x1FFF;
	case 0: // 8 + {5, 6}
	default:
		return (buf[st_pos] >> 0 | _8to16(buf[st_pos+1]) << 8) & 0x1FFF;
	}
}

/// 按照标准写明的实现
static uint16_t enc_rej_sampler(
	int16_t *res,
	uint32_t *res_cnt,
	const uint8_t *buf,
	uint64_t buf_size
) {
	uint32_t cnt = *res_cnt, st_pos = 0;
	buf_size <<= 3;
	uint32_t idx = 0, rem = 0;
	while (cnt < AIGIS_N && st_pos < buf_size) {
		uint16_t t = enc_read_qbits(buf, st_pos >> 3, st_pos & 0b111);
		if (t < AIGIS_ENC_MOD_Q) {
			res[cnt++] = t;
		}
		else {
			res[cnt] = res[cnt];
			cnt += 0;
		}
		st_pos += AIGIS_ENC_QBITS;
	}
	*res_cnt = cnt;
	return st_pos;
}

void enc_xof_and_parse(
	int16_t *coeff,
	const uint8_t* seed,
	uint64_t seed_size
) {
	/**
		buf 预期长度为 {512}
		n_blocks 则为 {15}
	 */
	uint8_t buf[AIGIS_ENC_REJ_SIZE+KDF128_RATE];
	uint32_t len = (AIGIS_ENC_REJ_SIZE+KDF128_RATE-1);

	/// TODO: kdf
	kdf_state state;
	kdf_init(&state, seed_size);
	kdf128_absorb(&state, seed, seed_size);
	kdf_squeeze(&state, buf, len);
	// 以上是 xof 部分，下面 parse，不过改完以后还是非常抽象
	uint32_t cur = 0,
			 pos = enc_rej_sampler(coeff, &cur, buf, len);
	len -= pos;
	while (cur < AIGIS_N) {
		pos -= KDF128_RATE;
		len += KDF128_RATE;
		/// TODO: kdf_squeeze
		kdf_squeeze(&state, &buf[pos], KDF128_RATE);
		int step = enc_rej_sampler(coeff, &cur, &buf[pos], len);
		pos += step;
		len -= step;
	}

	/// TODO: KDF
	kdf_destroy(&state);
}

void sig_rej_eta_s(
	uint32_t *a,
	const uint8_t *buf,
	uint64_t buf_len
) {
	uint32_t ctr = 0, pos = 0;
	uint8_t t[8];
	switch(AIGIS_SIG_ETA_S) {
	case 1:
		for (; pos < buf_len && ctr < AIGIS_N; pos++) {
			for (int i = 0; i < 4 && ctr < AIGIS_N; i ++) {
				t[i] = (buf[pos] >> (i<<1)) & 0x3;
				if (t[i] > 2) { continue; }
				a[ctr++] = AIGIS_SIG_MOD_Q + 1 - t[i];
			}
		}
		return;
	default:
		for (; pos < buf_len && ctr < AIGIS_N; pos += 3) {
			t[0] =  buf[pos] & 0x07;
			t[1] = (buf[pos] >> 3) & 0x07;
			t[2] = (buf[pos] >> 6) | ((buf[pos+1] & 0x1) << 2);
			t[3] = (buf[pos+1] >> 1) & 0x07;
			t[4] = (buf[pos+1] >> 4) & 0x07;
			t[5] = (buf[pos+1] >> 7) | ((buf[pos+2] & 0x3) << 1);
			t[6] = (buf[pos+2] >> 2) & 0x07;
			t[7] =  buf[pos+2] >> 5;
			for (int i = 0; i < 8 && ctr < AIGIS_N; i ++) {
				if (t[i] > AIGIS_SIG_ETA_S << 1) { continue; }
				a[ctr++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_ETA_S - t[i];
			}
		}
		// TODO: 剩下的怎么办?
	}
}

#if (AIGIS_SIG_ETA_E == 3)
	#define __SIG_ETA_E_MASK 0x7
	#define __SIG_ETA_E_BITS 5
#else
	#define __SIG_ETA_E_MASK 0xF
	#define __SIG_ETA_E_BITS 4
#endif

uint32_t sig_rej_eta_e(
	uint32_t *a,
	uint32_t len,
	const uint8_t *buf,
	uint64_t buf_len
) {
	uint32_t ctr = 0, pos = 0;
	uint8_t t0, t1;
	for (; pos < buf_len && ctr < len; pos ++) {
		t0 = buf[pos] & __SIG_ETA_E_MASK;
		t1 = buf[pos] >> __SIG_ETA_E_BITS;
		if (t0 <= 2 * AIGIS_SIG_ETA_E) {
			a[ctr++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_ETA_E - t0;
		}
		if (t1 <= 2 * AIGIS_SIG_ETA_E && ctr < len) {
			a[ctr++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_ETA_E - t1;
		}
	}
	return pos;
}

static void _sig_mat_qbits_21_mode(
	uint32_t *res_poly,
	const uint8_t *out_buf
) {
	uint32_t counter = 0, pos = 0;
	while (counter < AIGIS_N) {
		uint32_t val  = out_buf[pos++];
		val |= (uint32_t)out_buf[pos++] << 8;
		val |= (uint32_t)out_buf[pos++] << 16;

		val &= 0x1FFFFF;
		/* Rejection sampling */
		if(val < AIGIS_SIG_MOD_Q) {
			res_poly[counter++] = val;
		}
	}
}


static void _sig_mat_qbits_22_mode(
	uint32_t res_poly[AIGIS_N],
	uint8_t *out_buf,
	/// TODO: KDF
	kdf_state *state
) {
	uint32_t pos = 0, ctr = 0, val;

	// if (!val) { puts("0!"); }
#define __samp_22bits(lena) 							\
	do {												\
		val  = out_buf[pos++];							\
		val |= (uint32_t)out_buf[pos++] << 8;			\
		val |= (uint32_t)out_buf[pos++] << 16;			\
		val &= 0x3FFFFF;								\
		if (val < AIGIS_SIG_MOD_Q && ctr < lena) {		\
			res_poly[ctr++] = val;						\
		}												\
	} while (ctr < lena)

	__samp_22bits(223);
	/* Probability we need more than 6 blocks to generate 225 elements: < 2^{-135}.*/
	/* Probability we need more than 258 bytes to generate the last 31 elements: < 2^{-133}.*/
	/// TODO: Goes in this if condition has a huge probability.
	if (AIGIS_KDF128_PAD_SIZE < 258 + pos) {
		/// TODO: KDF
		if (!!kdf_alter_inp_buf) {
			kdf_alter_inp_buf(
				state, AIGIS_SEED_SIZE+1,
				!AIGIS_KDF_CONF
			);
		}
		kdf_squeeze(
			state, out_buf+AIGIS_KDF128_PAD_SIZE,
			AIGIS_SIG_KDF128_RATE
		);
	}
	__samp_22bits(AIGIS_N);
#undef __samp_22bits
}

void sig_rej_mat(
	uint32_t res_poly[AIGIS_N],
	uint8_t out_buf[AIGIS_SIG_EXP_MATR_SIZE],
	const uint8_t *inp_buf
) {
	/// TODO: KDF
	kdf_state state;
	kdf_init(&state, AIGIS_SEED_SIZE+1+(!AIGIS_KDF_CONF));
	kdf128_absorb(&state, inp_buf, AIGIS_SEED_SIZE+1+(!AIGIS_KDF_CONF));
	kdf128_sig_squeeze_blocks(&state, out_buf, AIGIS_KDF128_PAD_SIZE/AIGIS_SIG_KDF128_RATE);

	switch (AIGIS_SIG_QBITS) {
	case 21:
	default:
		_sig_mat_qbits_21_mode(res_poly, out_buf);
		break;
	case 22:
		_sig_mat_qbits_22_mode(res_poly, out_buf, &state);
		break;
	}
	/// TODO: KDF
	kdf_destroy(&state);
	return;
}
