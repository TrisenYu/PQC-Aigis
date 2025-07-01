#include "../aigis_const.h"
#include "../kdf_aux.h"

#ifndef __AIGIS_REJ_SAMP_H__
#define __AIGIS_REJ_SAMP_H__

static uint16_t _8to16(uint8_t x) { return (uint16_t)(x); }
static uint16_t aigis_read_qbits(
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


static uint16_t aigis_rej_sampler(
	int16_t *res,
	uint32_t *res_cnt,
	const uint8_t *buf,
	uint64_t buf_size
) {
    uint32_t cnt = *res_cnt, st_pos = 0;
	buf_size <<= 3;
	uint32_t idx = 0, rem = 0;
    while (cnt < AIGIS_N && st_pos < buf_size) {
		uint16_t t = aigis_read_qbits(buf, st_pos >> 3, st_pos & 0b111);
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

void aigis_xof_and_parse(
	int16_t *coeff,
    const uint8_t* seed, 
    uint64_t seed_size
) {
	/**
		buf 预期长度为 {512}
		n_blocks 则为 {15}
	 */
    uint8_t buf[AIGIS_ENC_REJ_SIZE+KDF128_RATE];
	uint32_t n_blocks = (AIGIS_ENC_REJ_SIZE+KDF128_RATE-1) / KDF128_RATE;

    aigis_kdf_state state;
	kdf_init(&state, seed_size);
	kdf_absorb(&state, seed, seed_size);
    kdf_squeeze(&state, buf, n_blocks);
    // 以上是 xof 部分，下面 parse，不过改完以后还是非常抽象
	uint32_t cur = 0, len = n_blocks * KDF128_RATE,
			 pos = aigis_rej_sampler(coeff, &cur, buf, len);
	len -= pos;
	while (cur < AIGIS_N) {
		pos -= KDF128_RATE;
		len += KDF128_RATE;
		kdf_squeeze(&state, &buf[pos], 1);
		int step = aigis_rej_sampler(coeff, &cur, &buf[pos], len);
		pos += step;
		len -= step;
	}

	kdf_destroy(&state);
}
#endif // AIGIS_REJ_SAMP_H
