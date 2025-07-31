/// Last modified at 2025年07月31日 星期四 14时12分14秒
#include "aigis_const.h"
#include "debug.h"
#include "entropy/baby_png.h"

#include <string.h>

#if (AIGIS_SIG_ETA_E == 3)
	#define __SIG_ETA_E_MASK 0x7
	#define __SIG_ETA_E_BITS 5
#else
	#define __SIG_ETA_E_MASK 0xF
	#define __SIG_ETA_E_BITS 4
#endif

static uint32_t tsig_rej_eta_e(
	uint32_t *a,
	uint32_t len,
	const uint8_t *buf,
    uint64_t buf_len
) {
	uint32_t ctr = 0, pos = 0;
	uint8_t t0, t1;
    /*
	do {
		t0 = buf[pos] & __SIG_ETA_E_MASK;
		t1 = buf[pos++] >> __SIG_ETA_E_BITS;
		if (t0 <= 2 * AIGIS_SIG_ETA_E)
			a[ctr++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_ETA_E - t0;
		if (t1 <= 2 * AIGIS_SIG_ETA_E)
			a[ctr++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_ETA_E - t1;
	} while (ctr < len - 2);

	do {
		t0 = buf[pos] & __SIG_ETA_E_MASK;
		t1 = buf[pos++] >> __SIG_ETA_E_BITS;
		if (t0 <= 2 * AIGIS_SIG_ETA_E)
			a[ctr++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_ETA_E - t0;
		if (t1 <= 2 * AIGIS_SIG_ETA_E && ctr < len)
			a[ctr++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_ETA_E - t1;
	} while (ctr < len);
    */
    for (; pos < buf_len && ctr < len; pos ++) {
        t0 = buf[pos] & __SIG_ETA_E_MASK;
		t1 = buf[pos] >> __SIG_ETA_E_BITS;
        if (t0 <= AIGIS_SIG_ETA_E<<1) {
			a[ctr++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_ETA_E - t0;
        }
		if (t1 <= AIGIS_SIG_ETA_E<<1 && ctr < len) {
			a[ctr++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_ETA_E - t1;
        }
    }
	return pos;
}


static unsigned int rej_eta2(
    uint32_t *a,
    unsigned int len,
    const unsigned char *buf
) {
#if AIGIS_SIG_ETA_E >7 || AIGIS_SIG_ETA_E < 3
#error "rej_eta2() assumes 3 <= AIGIS_SIG_ETA_E <=7"
#endif

	unsigned int ctr = 0, pos = 0;
	unsigned char t0, t1;

	do {
#if AIGIS_SIG_ETA_E == 3
		t0 = buf[pos] & 0x07;
		t1 = buf[pos++] >> 5;
#else
		t0 = buf[pos] & 0x0F;
		t1 = buf[pos++] >> 4;
#endif
		if (t0 <= 2 * AIGIS_SIG_ETA_E)
			a[ctr++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_ETA_E - t0;
		if (t1 <= 2 * AIGIS_SIG_ETA_E)
			a[ctr++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_ETA_E - t1;
	} while (ctr < len - 2);


	do {
#if AIGIS_SIG_ETA_E == 3
		t0 = buf[pos] & 0x07;
		t1 = buf[pos++] >> 5;
#else
		t0 = buf[pos] & 0x0F;
		t1 = buf[pos++] >> 4;
#endif

		if (t0 <= 2 * AIGIS_SIG_ETA_E)
			a[ctr++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_ETA_E - t0;
		if (t1 <= 2 * AIGIS_SIG_ETA_E && ctr<len)
			a[ctr++] = AIGIS_SIG_MOD_Q + AIGIS_SIG_ETA_E - t1;
	} while (ctr < len);

	return pos;
}

uint32_t res[AIGIS_N];
uint8_t buf[AIGIS_N] = {
      1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15,  16,
     17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,
     33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
     49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64,
     65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,  80,
     81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,  96,
     97,  98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
    113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128,
    129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144,
    145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160,
    161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176,
    177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192,
    193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208,
    209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
    241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 0,
}; // 参考 poly_uniform_eta2，虽然后面有用223或者33的情况
uint8_t ref_buf[AIGIS_N] = {
      1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15,  16,
     17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,
     33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
     49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64,
     65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,  80,
     81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,  96,
     97,  98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
    113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128,
    129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144,
    145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160,
    161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176,
    177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192,
    193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208,
    209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
    241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 0
};
uint32_t ref_res[AIGIS_N];

int t_check() {
    int flag = 0;
    for (int i = 0; i < AIGIS_N; i ++) {
        if (ref_res[i] ^ res[i]) {
            printf("diff:[%03d]:%d:%d\n", i, ref_res[i], res[i]);
            flag = 1;
            break;
        }
    }
    if (flag) {
        for (int i = 0; i < AIGIS_N; i ++) {
            printf("%02x", buf[i]);
            if (!((i+1)&31)) { puts(""); }
        }
    }
    return flag;
}

#define ROUND 1024

int main() {
    int i = ROUND, ret = 0;
    while (i--) {
        randombytes(ref_buf, AIGIS_N);
        memcpy(buf, ref_buf, AIGIS_N);
        rej_eta2(ref_res, AIGIS_N, ref_buf);
        tsig_rej_eta_e(res, AIGIS_N, buf, AIGIS_N);
        if (t_check()) {
            ret = 1;
            break;
        }
        rej_eta2(ref_res, 223, ref_buf);
        tsig_rej_eta_e(res, 223, buf, AIGIS_N);
        if (t_check()) {
            ret = 1;
            break;
        }
        rej_eta2(&ref_res[223], 33, ref_buf);
        tsig_rej_eta_e(&res[223], 33, buf, AIGIS_N);
        if (t_check()) {
            ret = 1;
            break;
        }
    }
    return 0;
}
