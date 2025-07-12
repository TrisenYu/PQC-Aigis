/// Last modified at 2025年07月12日 星期六 14时39分13秒
#include <stdint.h>
#include <stdio.h>
#include "../../hash/kdf_aux.h"
uint16_t _8cast16(uint8_t x) { return (uint16_t)(x); }
uint16_t aigis_read_qbits(
	const uint8_t *buf, 
	uint64_t st_pos,
	uint8_t ofs
) {
	switch (ofs) {
	case 1: // 7 + {6, 7}
		return (buf[st_pos] >> 1 | (_8cast16(buf[st_pos+1]) << 7)) & 0x1FFF;
	case 2: // 6 + {7, 8}
		return (buf[st_pos] >> 2 | (_8cast16(buf[st_pos+1]) << 6)) & 0x1FFF;
	case 3: // 5 + 8 + {0, 1}
		return (buf[st_pos] >> 3 | (_8cast16(buf[st_pos+1]) << 5) | (_8cast16(buf[st_pos+2]) << 13)) & 0x1FFF;
	case 4: // 4 + 8 + {1, 2}
		return (buf[st_pos] >> 4 | (_8cast16(buf[st_pos+1]) << 4) | (_8cast16(buf[st_pos+2]) << 12)) & 0x1FFF;
	case 5: // 3 + 8 + {2, 3}
		return (buf[st_pos] >> 5 | (_8cast16(buf[st_pos+1]) << 3) | (_8cast16(buf[st_pos+2]) << 11)) & 0x1FFF;
	case 6: // 2 + 8 + {3, 4}
		return (buf[st_pos] >> 6 | (_8cast16(buf[st_pos+1]) << 2) | (_8cast16(buf[st_pos+2]) << 10)) & 0x1FFF;
	case 7: // 1 + 8 + {4, 5}
		return (buf[st_pos] >> 7 | (_8cast16(buf[st_pos+1]) << 1) | (_8cast16(buf[st_pos+2]) << 9)) & 0x1FFF;
	case 0: // 8 + {5, 6}
	default:
		return (buf[st_pos] >> 0 | _8cast16(buf[st_pos+1]) << 8) & 0x1FFF;
	}
}


uint16_t aigis_modified_reject_sampling(
	int16_t *res,
	uint32_t *res_cnt,
	const uint8_t *buf,
	uint64_t buf_size
) {
    uint32_t cnt = *res_cnt, st_pos = 0;
	buf_size <<= 3;
	uint32_t idx = 0, rem = 0;
    while (cnt < 256 && st_pos < buf_size) {
		uint16_t t = aigis_read_qbits(buf, st_pos >> 3, st_pos & 0b111);
		if (t < 7681) { res[cnt++] = t; }
		else { res[cnt] = res[cnt]; cnt += 0; }
		st_pos += 13;
    }
	*res_cnt = cnt;
    return st_pos;
}

/// 原始版本
static int rej_uniform(int16_t *r, int *cur, int n, const uint8_t *buf, int buflen) {
	int ctr, pos;
	int16_t val[8];
	ctr = *cur;
	pos = 0;

	while (ctr + 8 <= n && pos + 13 <= buflen) {
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1fff;
		val[1] = ((buf[pos+1]>>5) | ((uint16_t)buf[pos + 2] << 3) | ((uint16_t)buf[pos + 3] << 11)) & 0x1fff;
		val[2] = ((buf[pos + 3] >> 2) | ((uint16_t)buf[pos + 4] << 6)) & 0x1fff;
		val[3] = ((buf[pos + 4] >> 7) | ((uint16_t)buf[pos + 5] << 1) | ((uint16_t)buf[pos + 6] << 9)) & 0x1fff;
		val[4] = ((buf[pos + 6] >> 4) | ((uint16_t)buf[pos + 7] << 4) | ((uint16_t)buf[pos + 8] << 12)) & 0x1fff;
		val[5] = ((buf[pos + 8] >> 1) | ((uint16_t)buf[pos + 9] << 7)) & 0x1fff;
		val[6] = ((buf[pos + 9] >> 6) | ((uint16_t)buf[pos + 10] << 2) | ((uint16_t)buf[pos + 11] << 10)) & 0x1fff;
		val[7] = ((buf[pos + 11] >> 3)| ((uint16_t)buf[pos + 12] << 5));

		if (val[0] < 7681)
			r[ctr++] = val[0];
		if (val[1] < 7681)
			r[ctr++] = val[1];
		if (val[2] < 7681)
			r[ctr++] = val[2];
		if (val[3] < 7681)
			r[ctr++] = val[3];
		if (val[4] < 7681)
			r[ctr++] = val[4];
		if (val[5] < 7681)
			r[ctr++] = val[5];
		if (val[6] < 7681)
			r[ctr++] = val[6];
		if (val[7] < 7681)
			r[ctr++] = val[7];
		pos += 13;
	}
	if (ctr + 8 <= n)//the random bits are enough, request more bits
	{
		*cur = ctr;
		return pos;
	}
	while (ctr < n && pos + 2 <= buflen)
	{
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1fff;
		if (val[0] < 7681)
			r[ctr++] = val[0];
		if (ctr >= n || pos + 3 >= buflen)
		{
			pos += 2;
			break;
		}

		val[1] = ((buf[pos + 1] >> 5) | ((uint16_t)buf[pos + 2] << 3) | ((uint16_t)buf[pos + 3] << 11)) & 0x1fff;
		if (val[1] < 7681)
			r[ctr++] = val[1];
		if (ctr >= n || pos + 4 >= buflen)
		{
			pos += 4;
			break;
		}
		val[2] = ((buf[pos + 3] >> 2) | ((uint16_t)buf[pos + 4] << 6)) & 0x1fff;
		if (val[2] < 7681)
			r[ctr++] = val[2];

		if (ctr >= n || pos + 6 >= buflen)
		{
			pos += 5;
			break;
		}
		val[3] = ((buf[pos + 4] >> 7) | ((uint16_t)buf[pos + 5] << 1) | ((uint16_t)buf[pos + 6] << 9)) & 0x1fff;
		if (val[3] < 7681)
			r[ctr++] = val[3];

		if (ctr >= n || pos + 8 >= buflen)
		{
			pos += 7;
			break;
		}
		val[4] = ((buf[pos + 6] >> 4) | ((uint16_t)buf[pos + 7] << 4) | ((uint16_t)buf[pos + 8] << 12)) & 0x1fff;
		if (val[4] < 7681)
			r[ctr++] = val[4];

		if (ctr >= n || pos + 9 >= buflen)
		{
			pos += 9;
			break;
		}
		val[5] = ((buf[pos + 8] >> 1) | ((uint16_t)buf[pos + 9] << 7)) & 0x1fff;
		if (val[5] < 7681)
			r[ctr++] = val[5];

		if (ctr >= n || pos + 11 >= buflen)
		{
			pos += 10;
			break;
		}
		val[6] = ((buf[pos + 9] >> 6) | ((uint16_t)buf[pos + 10] << 2) | ((uint16_t)buf[pos + 11] << 10)) & 0x1fff;
		if (val[6] < 7681)
			r[ctr++] = val[6];

		if (ctr >= n || pos + 12 >= buflen)
		{
			pos += 12;
			break;
		}
		val[7] = ((buf[pos + 11] >> 3) | ((uint16_t)buf[pos + 12] << 5));
		if (val[7] < 7681)
			r[ctr++] = val[7];
		pos += 13;
	}
	*cur = ctr;
	return pos;
}
void poly_uniform_seed(
    int16_t r[256], 
    const uint8_t *seed, 
    int seed_size
) {
	int32_t cur = 0, pos, step;
	uint8_t buf[480+KDF128_RATE];
	uint32_t len = (480+KDF128_RATE-1);

	aigis_kdf_state state;
	kdf_init(&state, seed_size);
	kdf128_absorb(&state, seed, seed_size);
    kdf_squeeze(&state, buf, len);
	
	pos = rej_uniform(r, &cur, 256, buf, len);
	len -= pos;
	while (cur < 256) {
		pos -= KDF128_RATE;
		len += KDF128_RATE;
		kdf_squeeze(&state, &buf[pos], KDF128_RATE);
		step = rej_uniform(r, &cur, 256, &buf[pos], len);
		pos += step;
		len -= step;
	}
	kdf_destroy(&state);
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
	uint8_t buf[480+KDF128_RATE];
	uint32_t len = 480+KDF128_RATE-1;

    aigis_kdf_state state;
	kdf_init(&state, seed_size);
	kdf128_absorb(&state, seed, seed_size);
    kdf_squeeze(&state, buf, len);
    // 以上是 xof 部分，下面 parse，不过改完以后还是非常抽象
    uint32_t cur = 0,
			 pos = aigis_modified_reject_sampling(coeff, &cur, buf, len);
	len -= pos;
	while (cur < 256) {
		pos -= KDF128_RATE;
		len += KDF128_RATE;
		kdf_squeeze(&state, &buf[pos], KDF128_RATE);
		int step = aigis_modified_reject_sampling(coeff, &cur, &buf[pos], len);
		pos += step;
		len -= step;
	}
	kdf_destroy(&state);

}
int16_t a[256] = { 0
    //   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15,  16, 
    //  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32, 
    //  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48, 
    //  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64, 
    //  65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,  80, 
    //  81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,  96, 
    //  97,  98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 
    // 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 
    // 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 
    // 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 
    // 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 
    // 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 
    // 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 
    // 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 
    // 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 
    // 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256
}, c[256] = {0};
uint8_t b[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
};

int main() {
    poly_uniform_seed(a, b, 256);
    // for (int i = 0; i < 256; i ++) {
    //     printf("%d, ", b[i]);
    //     if (!((i + 1) & 15)) { puts(""); }
    // }
    aigis_xof_and_parse(c, b, 256);
    for (int i = 0; i < 256; i ++) {
        if (a[i] ^ c[i]) {
            printf("diff at: %3d, a[%3d]=%04x, c[%3d]=%04x\n", i, i, a[i], i, c[i]);
        }
    }
    return 0*puts("no diff found.");
}
