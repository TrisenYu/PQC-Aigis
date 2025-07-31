/// Last modified at 2025年07月16日 星期三 10时52分03秒
#include "samplers/rej_samp.h"

static void cbd1(int16_t *res, const uint8_t *ref_buf) {
	uint64_t i = 0, curr;
	const int16_t tb[4] = {0, 0x0001, 0xFFFF, 0};
	for (; i < AIGIS_N / 4; i++) {
        curr = i << 2;
		res[curr + 0] = tb[ref_buf[i] & 0x3];
		res[curr + 1] = tb[(ref_buf[i] >> 2) & 0x3];
		res[curr + 2] = tb[(ref_buf[i] >> 4) & 0x3];
		res[curr + 3] = tb[ref_buf[i] >> 6];
	}
}
static void cbd2(int16_t *res, const uint8_t *ref_buf) {
	uint64_t i = 0, j;
	uint64_t d, t;
	const uint64_t mask55 = 0x5555555555555555;
	int16_t a, b;
	for (; i < AIGIS_N >> 4; i++) {
		d = *(uint64_t*)&ref_buf[i << 3];
		t = d & mask55;
		d = (d >> 1) & mask55;
		t = t + d;
		for (j = 0; j < 16; j++) {
			a = t & 0x3;
			b = (t >> 2) & 0x3;
			res[16 * i + j] = a - b;
			t = t >> 4;
		}
	}
}

static void cbd3(int16_t *res, const uint8_t *ref_buf) {
	unsigned int i = 0, j;
	uint32_t t, d;
	int16_t a, b;

	for(;i < AIGIS_N >> 2; i++) {
		t  = *((uint32_t*)(ref_buf + 3 * i));
		d  = t & 0x00249249;
		d += (t>>1) & 0x00249249;
		d += (t>>2) & 0x00249249;

		for(j=0;j<4;j++) {
            a = (d >> (6*j+0)) & 0x7;
            b = (d >> (6*j+3)) & 0x7;
            res[4*i+j] = a - b;
		}
	}
}
static void cbd4(int16_t r[AIGIS_N], const uint8_t *buf) {
	uint64_t i = 0, j, d, t;
	const uint64_t mask33 = 0x3333333333333333,
                   mask55 = 0x5555555555555555;
	int16_t a, b;
	for (; i < AIGIS_N / 8; i++) {
		d = *(uint64_t*)&buf[8*i];
		t = d & mask55;
		d = (d >> 1) & mask55;
		t = t + d;

		d = t & mask33;
		t = (t >> 2) & mask33;
		t = t + d;
		for (j = 0; j < 8; j++) {
			a = t & 0xf;
			b = (t>>4) & 0xf;
			r[8 * i + j] = a - b;
			t = t >> 8;
		}
	}
}
static void cbd8(int16_t *res, const uint8_t *buf) {
	uint64_t i = 0, j;
	uint64_t d, t;
	uint64_t mask55 = 0x5555555555555555,
             mask33 = 0x3333333333333333,
             mask0f = 0x0f0f0f0f0f0f0f0f;
	int16_t a, b;
	for (; i < AIGIS_N / 4; i++) {
		d = *(uint64_t*)&buf[8 * i];
		t = d & mask55;
		d = (d >> 1) & mask55;
		t = t + d;

		d = t & mask33;
		t = (t >> 2) & mask33;
		t = t + d;

		d = t & mask0f;
		t = (t >> 4) & mask0f;
		t = t + d;

		for (j = 0; j < 4; j++) {
			a = t & 0xff;
			b = (t >> 8) & 0xff;
			res[4 * i + j] = a - b;
			t = t >> 16;
		}

	}
}

int cbd_eta(
	uint8_t scale,
	int16_t *res,
	const uint8_t *buf
) {
	switch (scale) {
	case 1:
		cbd1(res, buf);
		break;
	case 2:
		cbd2(res, buf);
		break;
	case 3:
		cbd3(res, buf);
		break;
	case 4:
		cbd4(res, buf);
		break;
	case 8:
	case 12:
		cbd8(res, buf);
		break;
	default:
		return -1;
	}
	return 0;
}
