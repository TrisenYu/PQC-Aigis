
#include "aigis_const.h"
#include "poly.h"

// #ifdef __DEBUG
// #include "debug.h"
// #include <stdio.h>
// #endif 

#ifndef __COMP_H__
#define __COMP_H__


/// 解压缩算法
static void comp_poly_3(
	uint8_t *res, 
	const enc_poly a 
) {
	uint32_t i = 0, j, k = 0, t[8];
	for (; i < AIGIS_N; i += 8, k += 3) {
		for (j = 0; j < 8; j ++) {
			// q/2？
			t[j] = ((((uint32_t)a[i+j] << 3) + (AIGIS_ENC_MOD_Q>>1)) / AIGIS_ENC_MOD_Q) & 7;
		}
		res[k] = t[0] | (t[1] << 3) | (t[2] << 6);
		res[k+1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
		res[k+2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
	}
}

static void comp_poly_4(
	uint8_t *res, 
	const enc_poly a 
) {
	uint32_t i = 0, t[2];
	for (; i < AIGIS_N >> 1; i ++) {
		t[0] = ((((uint32_t)a[i << 1] << 4) + (AIGIS_ENC_MOD_Q>>1)) / AIGIS_ENC_MOD_Q) & 0xF;
		t[1] = ((((uint32_t)a[i << 1 | 1] << 4) + (AIGIS_ENC_MOD_Q>>1)) / AIGIS_ENC_MOD_Q) & 0xF;
		res[i] = t[0] | (t[1] << 4);
	}
}

static void comp_poly_5(
	uint8_t *res, 
	const enc_poly a 
) {
	uint32_t i = 0, j, k = 0, t[8];
	for (; i < AIGIS_N; i += 8, k += 5) {
		for (j = 0; j < 8; j++) {
			t[j] = ((((uint32_t)a[i + j] << 5) + (AIGIS_ENC_MOD_Q>>1)) / AIGIS_ENC_MOD_Q) & 0x1f;
		}
		res[k] = t[0] | (t[1] << 5);
		res[k + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
		res[k + 2] = (t[3] >> 1) | (t[4] << 4);
		res[k + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
		res[k + 4] = (t[6] >> 2) | (t[7] << 3);
	}
}

static void comp_poly_7(
	uint8_t *res,
	const enc_poly a
) {
	uint32_t i = 0, j, k = 0, t[8];
	for (; i < AIGIS_N; i ++, k += 7) {
		for (j = 0; j < 8; j ++) {
			t[j] = ((((uint32_t)a[i+j] << 7) + (AIGIS_ENC_MOD_Q>>1))/AIGIS_ENC_MOD_Q) & 0x7F;	
		}
		res[k] = t[0] | (t[1] << 7);
		res[k + 1] = (t[1] >> 1) | (t[2] << 6);
		res[k + 2] = (t[2] >> 2) | (t[3] << 5);
		res[k + 3] = (t[3] >> 3) | (t[4] << 4);
		res[k + 4] = (t[4] >> 4) | (t[5] << 3);
		res[k + 5] = (t[5] >> 5) | (t[6] << 2);
		res[k + 6] = (t[6] >> 6) | (t[7] << 1);
	}
}

static void decomp_poly_3(
	enc_poly res, 
	const uint8_t *a
) {
	uint32_t i = 0;
	for (; i < AIGIS_N; i += 8, a += 3) {
		res[i + 0] = (((a[0] & 7) * AIGIS_ENC_MOD_Q) + 4) >> 3;
		res[i + 1] = ((((a[0] >> 3) & 7) * AIGIS_ENC_MOD_Q) + 4) >> 3;
		res[i + 2] = ((((a[0] >> 6) | ((a[1] << 2) & 4)) * AIGIS_ENC_MOD_Q) + 4) >> 3;
		res[i + 3] = ((((a[1] >> 1) & 7) * AIGIS_ENC_MOD_Q) + 4) >> 3;
		res[i + 4] = ((((a[1] >> 4) & 7) * AIGIS_ENC_MOD_Q) + 4) >> 3;
		res[i + 5] = ((((a[1] >> 7) | ((a[2] << 1) & 6)) * AIGIS_ENC_MOD_Q) + 4) >> 3;
		res[i + 6] = ((((a[2] >> 2) & 7) * AIGIS_ENC_MOD_Q) + 4) >> 3;
		res[i + 7] = ((((a[2] >> 5)) * AIGIS_ENC_MOD_Q) + 4) >> 3;
	}
}

static void decomp_poly_4(
	enc_poly res, 
	const uint8_t *a
) {
	for (uint32_t i = 0; i < AIGIS_N / 2; i++) {
		res[i << 1] = (((a[i] & 0xf) * AIGIS_ENC_MOD_Q) + 8) >> 4;
		res[i << 1 | 1] = ((a[i] >> 4)* AIGIS_ENC_MOD_Q + 8) >> 4;
	}
}

static void decomp_poly_5(
	enc_poly res, 
	const uint8_t *a
) {
	uint32_t i = 0;
	for (; i < AIGIS_N; i += 8, a += 5) {
		res[i + 0] = (((a[0] & 0x1f) * AIGIS_ENC_MOD_Q) + 16) >> 5;
		res[i + 1] = ((((a[0] >> 5) | ((a[1] & 3) << 3)) * AIGIS_ENC_MOD_Q) + 16) >> 5;
		res[i + 2] = ((((a[1] >> 2) & 0x1f) * AIGIS_ENC_MOD_Q) + 16) >> 5;
		res[i + 3] = ((((a[1] >> 7) | ((a[2] & 0xf)<<1)) * AIGIS_ENC_MOD_Q) + 16) >> 5;
		res[i + 4] = ((((a[2] >> 4) | ((a[3] & 0x1)<<4)) * AIGIS_ENC_MOD_Q) + 16) >> 5;
		res[i + 5] = ((((a[3] >> 1) & 0x1f) * AIGIS_ENC_MOD_Q) + 16) >> 5;
		res[i + 6] = ((((a[3] >> 6) | ((a[4] & 0x7)<<2)) * AIGIS_ENC_MOD_Q) + 16) >> 5;
		res[i + 7] = ((((a[4] >> 3)) * AIGIS_ENC_MOD_Q) + 16) >> 5;
	}
}

static void decomp_poly_7(
	enc_poly res, 
	const uint8_t *a
) {
	uint32_t i = 0;
	for (; i < AIGIS_N; i += 8, a += 7) {
		res[i + 0] = (((a[0] & 0x7f) * AIGIS_ENC_MOD_Q) + 64) >> 7;
		res[i + 1] = ((((a[0] >> 7) | ((a[1] & 0x3f) << 1)) * AIGIS_ENC_MOD_Q) + 64) >> 7;
		res[i + 2] = ((((a[1] >> 6) | ((a[2] & 0x1f) << 2)) * AIGIS_ENC_MOD_Q) + 64) >> 7;
		res[i + 3] = ((((a[2] >> 5) | ((a[3] & 0xf) << 3)) * AIGIS_ENC_MOD_Q) + 64) >> 7;
		res[i + 4] = ((((a[3] >> 4) | ((a[4] & 0x7) << 4)) * AIGIS_ENC_MOD_Q) + 64) >> 7;
		res[i + 5] = ((((a[4] >> 3) | ((a[5] & 0x3) << 5)) * AIGIS_ENC_MOD_Q) + 64) >> 7;
		res[i + 6] = ((((a[5] >> 2) | ((a[6] & 0x1) << 6)) * AIGIS_ENC_MOD_Q) + 64) >> 7;
		res[i + 7] = ((((a[6] >> 1)) * AIGIS_ENC_MOD_Q) + 64) >> 7;
	}
}



static void comp_pvec_9(
	uint8_t *res, 
	const enc_pvec a 
) {
    int i = 0, j, k;
	uint16_t t[8], cpbytes = ((AIGIS_N * 9) >> 3);
    // the bytes for storing a polynomial in compressed form
	for (; i < AIGIS_ENC_K; i++) {
		for (j = 0; j < AIGIS_N / 8; j++) {
			for (k = 0; k<8; k++) {
				t[k] = ((((uint32_t)(a[i][8 * j + k]) << 9) + (AIGIS_ENC_MOD_Q >> 1)) / AIGIS_ENC_MOD_Q) & 0x1ff;
            }
			res[9 * j + 0] = t[0] & 0xff;
			res[9 * j + 1] = (t[0] >> 8) | ((t[1] & 0x7f) << 1);
			res[9 * j + 2] = (t[1] >> 7) | ((t[2] & 0x3f) << 2);
			res[9 * j + 3] = (t[2] >> 6) | ((t[3] & 0x1f) << 3);
			res[9 * j + 4] = (t[3] >> 5) | ((t[4] & 0x0f) << 4);
			res[9 * j + 5] = (t[4] >> 4) | ((t[5] & 0x07) << 5);
			res[9 * j + 6] = (t[5] >> 3) | ((t[6] & 0x03) << 6);
			res[9 * j + 7] = (t[6] >> 2) | ((t[7] & 0x01) << 7);
			res[9 * j + 8] = (t[7] >> 1);
		}
		res += cpbytes;
	}
}

static void comp_pvec_10(
	uint8_t *res, 
	const enc_pvec a 
) {
    int i = 0, j, k;
	uint16_t t[4];
	uint16_t cpbytes = ((AIGIS_N * 10) >> 3);//the bytes for storing a polynomial in compressed form
	for (; i < AIGIS_ENC_K; i++) {
		for (j = 0; j < AIGIS_N / 4; j++) {
			for (k = 0; k < 4; k++) {
				t[k] = ((((uint32_t)(a[i][4 * j + k]) << 10) + (AIGIS_ENC_MOD_Q >> 1)) / AIGIS_ENC_MOD_Q) & 0x3ff;
			}
			res[5 * j + 0] = t[0] & 0xff;
			res[5 * j + 1] = (t[0] >> 8) | ((t[1] & 0x3f) << 2);
			res[5 * j + 2] = (t[1] >> 6) | ((t[2] & 0x0f) << 4);
			res[5 * j + 3] = (t[2] >> 4) | ((t[3] & 0x03) << 6);
			res[5 * j + 4] = (t[3] >> 2);
		}
		res += cpbytes;
    }
}

static void comp_pvec_11(
	uint8_t *res, 
	const enc_pvec a
) {
    int i = 0, j, k;
	uint16_t t[8],
             cpbytes = ((AIGIS_N * 11) >> 3);
    // the bytes for storing a polynomial in compressed form

	for (; i < AIGIS_ENC_K; i++) {
		for (j = 0; j < AIGIS_N / 8; j++) {
			for (k = 0; k < 8; k++) {
				t[k] = ((((uint32_t)a[i][8 * j + k] << 11) + (AIGIS_ENC_MOD_Q >> 1)) / AIGIS_ENC_MOD_Q) & 0x7ff;
            }
			res[11 * j + 0] = t[0] & 0xff;                       
			res[11 * j + 1] = (t[0] >> 8) | ((t[1] & 0x1f) << 3);
			res[11 * j + 2] = (t[1] >> 5) | ((t[2] & 0x03) << 6);
			res[11 * j + 3] = (t[2] >> 2) & 0xff;
			res[11 * j + 4] = (t[2] >> 10) | ((t[3] & 0x7f) << 1);
			res[11 * j + 5] = (t[3] >> 7) | ((t[4] & 0x0f) << 4);
			res[11 * j + 6] = (t[4] >> 4) | ((t[5] & 0x01) << 7);
			res[11 * j + 7] = (t[5] >> 1) & 0xff;
			res[11 * j + 8] = (t[5] >> 9) | ((t[6] & 0x3f) << 2);
			res[11 * j + 9] = (t[6] >> 6) | ((t[7] & 0x07) << 5);
			res[11 * j + 10] = (t[7] >> 3);
		}
		res += cpbytes;
	}
}

static void decomp_pvec_9(
	enc_pvec res, 
	const uint8_t *a
) {
	int i = 0, j;
	uint16_t cpbytes = ((AIGIS_N * 9) >> 3);
    // the bytes for storing a polynomial in compressed form
	for (; i < AIGIS_ENC_K; i++) {
		for (j = 0; j < AIGIS_N / 8; j++) {
			res[i][8*j+0] = (((a[9 * j + 0] | (((uint32_t)a[9 * j + 1] & 0x01) << 8)) * AIGIS_ENC_MOD_Q) + 256) >> 9;
			res[i][8*j+1] = ((((a[9 * j + 1] >> 1) | (((uint32_t)a[9 * j + 2] & 0x03) << 7)) * AIGIS_ENC_MOD_Q) + 256) >> 9;
			res[i][8*j+2] = ((((a[9 * j + 2] >> 2) | (((uint32_t)a[9 * j + 3] & 0x07) << 6)) * AIGIS_ENC_MOD_Q) + 256) >> 9;
			res[i][8*j+3] = ((((a[9 * j + 3] >> 3) | (((uint32_t)a[9 * j + 4] & 0x0f) << 5)) * AIGIS_ENC_MOD_Q) + 256) >> 9;
			res[i][8*j+4] = ((((a[9 * j + 4] >> 4) | (((uint32_t)a[9 * j + 5] & 0x1f) << 4)) * AIGIS_ENC_MOD_Q) + 256) >> 9;
			res[i][8*j+5] = ((((a[9 * j + 5] >> 5) | (((uint32_t)a[9 * j + 6] & 0x3f) << 3)) * AIGIS_ENC_MOD_Q) + 256) >> 9;
			res[i][8*j+6] = ((((a[9 * j + 6] >> 6) | (((uint32_t)a[9 * j + 7] & 0x7f) << 2)) * AIGIS_ENC_MOD_Q) + 256) >> 9;
			res[i][8*j+7] = ((((a[9 * j + 7] >> 7) | (((uint32_t)a[9 * j + 8]) << 1)) * AIGIS_ENC_MOD_Q) + 256) >> 9;
		}
		a += cpbytes;
	}
}

static void decomp_pvec_10(
	enc_pvec res, 
	const uint8_t *a
) {
	int i = 0, j;
	uint16_t cpbytes = ((AIGIS_N * 10) >> 3);
    // the bytes for storing a polynomial in compressed form
	for (; i < AIGIS_ENC_K; i++) {
		for (j = 0; j < AIGIS_N / 4; j++) {
			res[i][4*j+0] = (((a[5 * j + 0] | (((uint32_t)a[5 * j + 1] & 0x03) << 8)) * AIGIS_ENC_MOD_Q) + 512) >> 10;
			res[i][4*j+1] = ((((a[5 * j + 1] >> 2) | (((uint32_t)a[5 * j + 2] & 0x0f) << 6)) * AIGIS_ENC_MOD_Q) + 512) >> 10;
			res[i][4*j+2] = ((((a[5 * j + 2] >> 4) | (((uint32_t)a[5 * j + 3] & 0x3f) << 4)) * AIGIS_ENC_MOD_Q) + 512) >> 10;
			res[i][4*j+3] = ((((a[5 * j + 3] >> 6) | (((uint32_t)a[5 * j + 4]) << 2)) * AIGIS_ENC_MOD_Q) + 512) >> 10;
		}
		// 666 const +=
		// 虽然 const 是内容不可改动
		a += cpbytes;
	}
}

static void decomp_pvec_11(
	enc_pvec res, 
	const uint8_t *a
) {
	int i = 0, j;
	uint16_t cpbytes = ((AIGIS_N * 11) >> 3);//the bytes for storing a polynomial in compressed form
	for (; i < AIGIS_ENC_K; i++) {
		for (j = 0; j < AIGIS_N / 8; j++) {
			res[i][8*j+0] = (((a[11*j+0] | (((uint32_t)a[11 * j + 1] & 0x07) << 8)) * AIGIS_ENC_MOD_Q) + 1024) >> 11;
			res[i][8*j+1] = ((((a[11*j+1] >> 3) | (((uint32_t)a[11 * j + 2] & 0x3f) << 5)) * AIGIS_ENC_MOD_Q) + 1024) >> 11;
			res[i][8*j+2] = ((((a[11*j+2] >> 6) | (((uint32_t)a[11 * j + 3] & 0xff) << 2) | (((uint32_t)a[11 * j + 4] & 0x01) << 10)) * AIGIS_ENC_MOD_Q) + 1024) >> 11;
			res[i][8*j+3] = ((((a[11*j+4] >> 1) | (((uint32_t)a[11 * j + 5] & 0x0f) << 7)) * AIGIS_ENC_MOD_Q) + 1024) >> 11;
			res[i][8*j+4] = ((((a[11*j+5] >> 4) | (((uint32_t)a[11 * j + 6] & 0x7f) << 4)) * AIGIS_ENC_MOD_Q) + 1024) >> 11;
			res[i][8*j+5] = ((((a[11*j+6] >> 7) | (((uint32_t)a[11 * j + 7] & 0xff) << 1) | (((uint32_t)a[11 * j + 8] & 0x03) << 9)) * AIGIS_ENC_MOD_Q) + 1024) >> 11;
			res[i][8*j+6] = ((((a[11*j+8] >> 2) | (((uint32_t)a[11 * j + 9] & 0x1f) << 6)) * AIGIS_ENC_MOD_Q) + 1024) >> 11;
			res[i][8*j+7] = ((((a[11*j+9] >> 5) | (((uint32_t)a[11 * j + 10] & 0xff) << 3)) * AIGIS_ENC_MOD_Q) + 1024) >> 11;
		}
		a += cpbytes;
	}
}

/// 字节转环上多项式
void enc_poly2bytes(uint8_t *res, const enc_poly a) {
    int i = 0,j;
    int16_t t[8];
    for(; i < AIGIS_N >> 3; i ++) { // 32 * 13 = 416
        for(j = 0; j < 8; j ++) {
            t[j] = a[8*i+j];
        }
        res[13*i+ 0] =  t[0]        & 0xff;
        res[13*i+ 1] = (t[0] >>  8) | ((t[1] & 0x07) << 5);
        res[13*i+ 2] = (t[1] >>  3) & 0xff;
        res[13*i+ 3] = (t[1] >> 11) | ((t[2] & 0x3f) << 2);
        res[13*i+ 4] = (t[2] >>  6) | ((t[3] & 0x01) << 7);
        res[13*i+ 5] = (t[3] >>  1) & 0xff;
        res[13*i+ 6] = (t[3] >>  9) | ((t[4] & 0x0f) << 4);
        res[13*i+ 7] = (t[4] >>  4) & 0xff;
        res[13*i+ 8] = (t[4] >> 12) | ((t[5] & 0x7f) << 1);
        res[13*i+ 9] = (t[5] >>  7) | ((t[6] & 0x03) << 6);
        res[13*i+10] = (t[6] >>  2) & 0xff;
        res[13*i+11] = (t[6] >> 10) | ((t[7] & 0x1f) << 3);
        res[13*i+12] = (t[7] >>  5);
    }
}

void enc_bytes2poly(enc_poly res, const uint8_t *a) {
	for(uint64_t i = 0; i < AIGIS_N >> 3; i ++) {
		res[(i << 3) + 0] =  a[13*i+ 0]       | (((uint16_t)a[13*i+ 1] & 0x1f) << 8);
		res[(i << 3) + 1] = (a[13*i+ 1] >> 5) | (((uint16_t)a[13*i+ 2]       ) << 3) | (((uint16_t)a[13*i+ 3] & 0x03) << 11);
		res[(i << 3) + 2] = (a[13*i+ 3] >> 2) | (((uint16_t)a[13*i+ 4] & 0x7f) << 6);
		res[(i << 3) + 3] = (a[13*i+ 4] >> 7) | (((uint16_t)a[13*i+ 5]       ) << 1) | (((uint16_t)a[13*i+ 6] & 0x0f) <<  9);
		res[(i << 3) + 4] = (a[13*i+ 6] >> 4) | (((uint16_t)a[13*i+ 7]       ) << 4) | (((uint16_t)a[13*i+ 8] & 0x01) << 12);
		res[(i << 3) + 5] = (a[13*i+ 8] >> 1) | (((uint16_t)a[13*i+ 9] & 0x3f) << 7);
		res[(i << 3) + 6] = (a[13*i+ 9] >> 6) | (((uint16_t)a[13*i+10]       ) << 2) | (((uint16_t)a[13*i+11] & 0x07) << 10);
		res[(i << 3) + 7] = (a[13*i+11] >> 3) | (((uint16_t)a[13*i+12]       ) << 5);
	}

}

/// 在下面选择相应的配置
void (*enc_pub_compresser) (
    uint8_t *res, 
    const enc_pvec a 
) = 
#if AIGIS_ENC_BITS_PUB == 9
    comp_pvec_9;
#elif AIGIS_ENC_BITS_PUB == 10
    comp_pvec_10;
#elif AIGIS_ENC_BITS_PUB == 11
    comp_pvec_11;
#else
    #error "unsupported config on AIGIS_ENC_BITS_PUB, " \
           "only accept {9, 10, 11}!"
#endif // check AIGIS_ENC_BITS_PUB for pub_compresser


void (*enc_pub_decompresser) (
    enc_pvec res, 
    const uint8_t *a
) = 
#if AIGIS_ENC_BITS_PUB == 9
    decomp_pvec_9;
#elif AIGIS_ENC_BITS_PUB == 10
    decomp_pvec_10;
#elif AIGIS_ENC_BITS_PUB == 11
    decomp_pvec_11;
#else
    #error "unsupported config on AIGIS_ENC_BITS_PUB, " \
           "only accept {9, 10, 11}!"
#endif  // check AIGIS_ENC_BITS_PUB for pub_decompresser

void (*enc_cft_pvec_compresser) (
	uint8_t *res, 
    const enc_pvec a
) = 
#if AIGIS_ENC_BITS_CFT == 9
	comp_pvec_9;
#elif AIGIS_ENC_BITS_CFT == 10
    comp_pvec_10;
#elif AIGIS_ENC_BITS_CFT == 11
    comp_pvec_11;
#else
    #error "unsupported config on AIGIS_ENC_BITS_CFT, " \
           "only accept {9, 10, 11}!"
#endif // check AIGIS_ENC_BITS_CFT for aigis_cipher_compresser

void (*enc_cft_pvec_decompresser) (
	enc_pvec a, 
    const uint8_t *res
) = 
#if AIGIS_ENC_BITS_CFT == 9
	decomp_pvec_9;
#elif AIGIS_ENC_BITS_CFT == 10
    decomp_pvec_10;
#elif AIGIS_ENC_BITS_CFT == 11
    decomp_pvec_11;
#else
    #error "unsupported config on AIGIS_ENC_BITS_CFT, " \
           "only accept {9, 10, 11}!"
#endif // check AIGIS_ENC_BITS_CFT for aigis_cipher_decompresser


void (*enc_cft_poly_compresser) (
    uint8_t *res, 
    const enc_poly a
) = 
#if AIGIS_ENC_BITS_CFT2 == 3
	comp_poly_3;
#elif AIGIS_ENC_BITS_CFT2 == 4
	comp_poly_4;
#elif AIGIS_ENC_BITS_CFT2 == 5
	comp_poly_5;
#elif AIGIS_ENC_BITS_CFT2 == 7
	comp_poly_7;
#else
	#error "unsupported config on AIGIS_ENC_BITS_CFT2"
#endif // configuration for poly_compresser().

void (*enc_cft_poly_decompresser) (
    enc_poly res, 
    const uint8_t *a
) = 
#if AIGIS_ENC_BITS_CFT2 == 3
	decomp_poly_3;
#elif AIGIS_ENC_BITS_CFT2 == 4
	decomp_poly_4;
#elif AIGIS_ENC_BITS_CFT2 == 5
	decomp_poly_5;
#elif AIGIS_ENC_BITS_CFT2 == 7
	decomp_poly_7;
#else
	#error "unsupport configuration for poly_decompressor!"
#endif // configuration for poly_decompresser().

/// 和签名解压缩有关的算法

/// sig多项式编译期检查
/// TODO: 写得太神秘了
#if AIGIS_SIG_QBITS - AIGIS_SIG_D != 8
	#error "polyt1_pack() assumes AIGIS_SIG_QBITS - AIGIS_SIG_D == 8"
#endif // 对AIGIS_SIG_QBITS的检查
#if AIGIS_SIG_D != 13 && AIGIS_SIG_D != 14
	#error "polyt0_unpack() assumes AIGIS_SIG_D== 13 or 14"
#endif // 对AIGIS_SIG_D的检查
#if AIGIS_SIG_MOD_Q > 8*AIGIS_SIG_ALPHA
#endif // pack_poly_w1


/// 签名算法打包函数
static uint8_t sig_comp_poly1_4(
	uint8_t *res,
	uint32_t eta_val,
	const sig_poly a
) {
  	uint8_t t[8];
	for (int i = 0; i < AIGIS_N / 4; ++i) {
		for (int j = 0; j < 4; j ++) {
			t[j] = AIGIS_SIG_MOD_Q + eta_val - a[4*i+j];
		}
		res[i] = t[0] | (t[1] << 2) | (t[2] << 4) | (t[3] << 6);
	}
	return 0;
}

static uint8_t sig_comp_poly3_8(
	uint8_t *res,
	uint32_t eta_val,
	const sig_poly a
) {
	uint8_t t[8];
	for(int i = 0; i < AIGIS_N/8; ++i) {
		for (int j = 0; j < 8; j ++) {
			t[j] = AIGIS_SIG_MOD_Q + eta_val - a[8*i+j];
		}
		res[3*i+0]  = t[0];
		res[3*i+0] |= t[1] << 3;
		res[3*i+0] |= t[2] << 6;
		res[3*i+1]  = t[2] >> 2;
		res[3*i+1] |= t[3] << 1;
		res[3*i+1] |= t[4] << 4;
		res[3*i+1] |= t[5] << 7;
		res[3*i+2]  = t[5] >> 1;
		res[3*i+2] |= t[6] << 2;
		res[3*i+2] |= t[7] << 5;
	}
	return 0;
}

static uint8_t sig_comp_poly1_2(
	uint8_t *res,
	uint32_t eta_val,
	const sig_poly a
) {
	uint8_t t[2];
	for(int i = 0; i < AIGIS_N>>1; ++i) {
		t[0] = AIGIS_SIG_MOD_Q + eta_val - a[2*i+0];
		t[1] = AIGIS_SIG_MOD_Q + eta_val - a[2*i+1];
		res[i] = t[0] | (t[1] << 4);
	}
	return 0;
}


static uint8_t sig_comp_poly13_8(
	uint8_t *res,
	const sig_poly a
) {
	uint32_t t[8];
	for(int i = 0; i < AIGIS_N/8; ++i) {
		for (int j = 0; j < 8; j ++) {
			t[j] = AIGIS_SIG_MOD_Q + 4096 - a[8*i+j];
		}
		res[13*i+0]   =  t[0];
		res[13*i+1]   =  t[0] >> 8;
		res[13*i+1]  |=  t[1] << 5;
		res[13*i+2]   =  t[1] >> 3;
		res[13*i+3]   =  t[1] >> 11;
		res[13*i+3]  |=  t[2] << 2;
		res[13*i+4]   =  t[2] >> 6;
		res[13*i+4]  |=  t[3] << 7;
		res[13*i+5]   =  t[3] >> 1;
		res[13*i+6]   =  t[3] >> 9;
		res[13*i+6]  |=  t[4] << 4;
		res[13*i+7]   =  t[4] >> 4;
		res[13*i+8]   =  t[4] >> 12;
		res[13*i+8]  |=  t[5] << 1;
		res[13*i+9]   =  t[5] >> 7;
		res[13*i+9]  |=  t[6] << 6;
		res[13*i+10]  =  t[6] >> 2;
		res[13*i+11]  =  t[6] >> 10;
		res[13*i+11] |=  t[7] << 3;
		res[13*i+12]  =  t[7] >> 5;
	}
	return 0;
}

static uint8_t sig_comp_poly7_4(
	uint8_t *res,
	const sig_poly a
) {
	uint32_t t[4];
	for(int i = 0; i < AIGIS_N/4; ++i) {
		for (int j = 0; j < 4; j ++) {
			t[j] = AIGIS_SIG_MOD_Q + 8192 - a[4*i+j];
		}
		res[7*i+0]  =  t[0];
		res[7*i+1]  =  t[0] >> 8;
		res[7*i+1] |=  t[1] << 6;
		res[7*i+2]  =  t[1] >> 2;
		res[7*i+3]  =  t[1] >> 10;
		res[7*i+3] |=  t[2] << 4;
		res[7*i+4]  =  t[2] >> 4;
		res[7*i+5]  =  t[2] >> 12;
		res[7*i+5] |=  t[3] << 2;
		res[7*i+6]  =  t[3] >> 6;
	}  
	return 0;
}

/// 签名算法解包函数
static uint8_t sig_decomp_poly2_1(
	sig_poly res,
	uint32_t eta_val,
	const uint8_t *a
) {
	for(int i = 0; i < AIGIS_N>>1; ++i) {
		res[2*i+0] = a[i] & 0x0F;
		res[2*i+1] = a[i]>>4;
		res[2*i+0] = AIGIS_SIG_MOD_Q + eta_val - res[2*i+0];
		res[2*i+1] = AIGIS_SIG_MOD_Q + eta_val - res[2*i+1];
	}
	return 0;
}


static uint8_t sig_decomp_poly4_1(
	sig_poly res,
	uint32_t eta_val,
	const uint8_t *a
) {
	for (int i = 0; i < AIGIS_N >> 2; i ++) {
		res[4*i+0] =  a[i] & 0b11;	
		res[4*i+1] = (a[i]>>2) & 0b11;	
		res[4*i+2] = (a[i]>>4) & 0b11;	
		res[4*i+3] = (a[i]>>6) & 0b11;

		res[4*i+0] = AIGIS_SIG_MOD_Q + eta_val - res[4*i+0];
		res[4*i+1] = AIGIS_SIG_MOD_Q + eta_val - res[4*i+1];
		res[4*i+2] = AIGIS_SIG_MOD_Q + eta_val - res[4*i+2];
		res[4*i+3] = AIGIS_SIG_MOD_Q + eta_val - res[4*i+3];
	}
	return 0;
}

static uint8_t sig_decomp_poly8_3(
	sig_poly res,
	uint32_t eta_val,
	const uint8_t *a
) {
	/// TODO: 为什么第15个总是不对？
	for (int i = 0; i < AIGIS_N >> 3; i ++) {
		res[8*i+0] =  a[3*i+0] & 0b111;
		res[8*i+1] = (a[3*i+0]>>3) & 0b111;
		res[8*i+2] = (a[3*i+0]>>6) | ((a[3*i+1]&0b001) << 2);
		res[8*i+3] = (a[3*i+1]>>1) & 0b111;
		res[8*i+4] = (a[3*i+1]>>4) & 0b111;
		res[8*i+5] = (a[3*i+1]>>7) | ((a[3*i+2]&0b011) << 1);
		res[8*i+6] = (a[3*i+2]>>2) & 0b111;
		res[8*i+7] = (a[3*i+2]>>5);

		for (int j = 0; j < 8; j ++) {
			res[8*i+j] = AIGIS_SIG_MOD_Q + eta_val - res[8*i+j];
		}
	}
	return 0;
}


static uint8_t sig_decomp_poly8_13(
	sig_poly res,
	const uint8_t *a
) {
	for (int i = 0; i < AIGIS_N>>3; i++) {
		res[8*i+0]  = a[13*i+0];
		res[8*i+0] |= (uint32_t)(a[13*i+1] & 0x1F)<<8;

		res[8*i+1]  = a[13*i+1]>>5;
		res[8*i+1] |= (uint32_t)a[13*i+2]<< 3;
		res[8*i+1] |= (uint32_t)(a[13*i+3] & 0x3)<< 11;

		res[8*i+2]  = a[13*i+3]>>2;
		res[8*i+2] |= (uint32_t)(a[13*i+4] & 0x7F)<< 6;

		res[8*i+3]  = a[13*i+4]>>7;
		res[8*i+3] |= (uint32_t)a[13*i+5]<< 1;
		res[8*i+3] |= (uint32_t)(a[13*i+6] & 0x0F)<< 9;

		res[8*i+4]  = a[13*i+ 6]>>4;
		res[8*i+4] |= (uint32_t)a[13*i+ 7]<< 4;
		res[8*i+4] |= (uint32_t)(a[13*i+8] & 0x01)<< 12;

		res[8*i+5]  = a[13*i+8]>>1;
		res[8*i+5] |= (uint32_t)(a[13*i+9] & 0x3F)<< 7;

		res[8*i+6]  = a[13*i+9]>>6;
		res[8*i+6] |= (uint32_t)a[13*i+10]<< 2;
		res[8*i+6] |= (uint32_t)(a[13*i+11] & 0x07)<< 10;

		res[8*i+7]  = a[13*i+11]>>3;
		res[8*i+7] |= (uint32_t)a[13*i+12]<< 5;

		/// 12 = AIGIS_SIG_D - 1
		/// 1 << 12 = 4096 
		for (int j = 0; j < 8; j ++) {
			res[8*i+j] = AIGIS_SIG_MOD_Q + 4096 - res[8*i+j];
		}
	}
	return 0;
}

static uint8_t sig_decomp_poly4_7(
	sig_poly res,
	const uint8_t *a
) {
	for(int i = 0; i < AIGIS_N>>2; ++i) {
		res[4*i+0]  = a[7*i+0];
		res[4*i+0] |= (uint32_t)(a[7*i+1] & 0x3F) << 8;

		res[4*i+1]  = a[7*i+1] >> 6;
		res[4*i+1] |= (uint32_t)a[7*i+2] << 2;
		res[4*i+1] |= (uint32_t)(a[7*i+3] & 0x0F) << 10;
		
		res[4*i+2]  = a[7*i+3] >> 4;
		res[4*i+2] |= (uint32_t)a[7*i+4] << 4;
		res[4*i+2] |= (uint32_t)(a[7*i+5] & 0x03) << 12;

		res[4*i+3]  = a[7*i+5] >> 2;
		res[4*i+3] |= (uint32_t)a[7*i+6] << 6;

		/// 13 = AIGIS_SIG_D - 1
		/// 1 << 13 = 4096
		for (int j = 0; j < 4; j ++) {
			res[4*i+j] = AIGIS_SIG_MOD_Q + 8192 - res[4*i+j];
		}
	}
	return 0;
}

/// 其它部分
void sig_poly_z_compresser(
	uint8_t *res,
	const sig_poly a
) {
	uint32_t i, t[4];
	for(i = 0; i < AIGIS_N/4; ++i) {
		/* Map to {0,...,2*AIGIS_SIG_GAMMA1 - 2} */ // 18-bit
		t[0] = AIGIS_SIG_GAMMA1 - 1 - a[4*i+0];
		t[0] += ((int32_t)t[0] >> 31) & AIGIS_SIG_MOD_Q;
		t[1] = AIGIS_SIG_GAMMA1 - 1 - a[4*i+1];
		t[1] += ((int32_t)t[1] >> 31) & AIGIS_SIG_MOD_Q;
		t[2] = AIGIS_SIG_GAMMA1 - 1 - a[4*i+2];
		t[2] += ((int32_t)t[2] >> 31) & AIGIS_SIG_MOD_Q;
		t[3] = AIGIS_SIG_GAMMA1 - 1 - a[4*i+3];
		t[3] += ((int32_t)t[3] >> 31) & AIGIS_SIG_MOD_Q;

		res[9*i+0]  = t[0];
		res[9*i+1]  = t[0] >> 8;
		res[9*i+2]  = t[0] >> 16;
		res[9*i+2] |= t[1] << 2;
		res[9*i+3]  = t[1] >> 6;
		res[9*i+4]  = t[1] >> 14;
		res[9*i+4] |= t[2] << 4;
		res[9*i+5]  = t[2] >> 4;
		res[9*i+6]  = t[2] >> 12;
		res[9*i+6] |= t[3] << 6;
		res[9*i+7]  = t[3] >> 2;
		res[9*i+8]  = t[3] >> 10;

	}
}

void sig_poly_z_decompresser(
	sig_poly res,
	const uint8_t *a
) {
	for(int i = 0; i < AIGIS_N>>2; ++i) {
		res[4*i+0]  = a[9*i+0];
		res[4*i+0] |= (uint32_t)a[9*i+1] << 8;
		res[4*i+0] |= (uint32_t)(a[9*i+2] & 0x03) << 16;
		res[4*i+0] = AIGIS_SIG_GAMMA1 - 1 - res[4*i+0];
		res[4*i+0] += ((int32_t)res[4*i+0] >> 31) & AIGIS_SIG_MOD_Q;

		res[4*i+1]  = a[9*i+2] >> 2;
		res[4*i+1] |= (uint32_t)a[9*i+3] << 6;
		res[4*i+1] |= (uint32_t)(a[9*i+4] & 0x0F) << 14;
		res[4*i+1] = AIGIS_SIG_GAMMA1 - 1 - res[4*i+1];
		res[4*i+1] += ((int32_t)res[4*i+1] >> 31) & AIGIS_SIG_MOD_Q;

		res[4*i+2]  = a[9*i+4] >> 4;
		res[4*i+2] |= (uint32_t)a[9*i+5] << 4;
		res[4*i+2] |= (uint32_t)(a[9*i+6] & 0x3F) << 12;
		res[4*i+2] = AIGIS_SIG_GAMMA1 - 1 - res[4*i+2];
		res[4*i+2] += ((int32_t)res[4*i+2] >> 31) & AIGIS_SIG_MOD_Q;


		res[4*i+3]  = a[9*i+6] >> 6;
		res[4*i+3] |= (uint32_t)a[9*i+7] << 2;
		res[4*i+3] |= (uint32_t)a[9*i+8] << 10;
		res[4*i+3] = AIGIS_SIG_GAMMA1 - 1 - res[4*i+3];
		res[4*i+3] += ((int32_t)res[4*i+3] >> 31) & AIGIS_SIG_MOD_Q;
	}
}

/// 要是c支持curry也不至于这么写


uint8_t sig_poly_eta_s_compresser(
	uint8_t *res,
	const sig_poly a 
) {
	switch(AIGIS_SIG_ETA_S) {
	case 1:
		return sig_comp_poly1_4(res, 1, a);
	default:
		return sig_comp_poly3_8(res, AIGIS_SIG_ETA_S, a);
	}
}

uint8_t sig_poly_eta_s_decompresser(
	sig_poly res,
	const uint8_t *a
) {
	switch(AIGIS_SIG_ETA_S) {
	case 1:
		return sig_decomp_poly4_1(res, 1, a);
	default:
		return sig_decomp_poly8_3(res, AIGIS_SIG_ETA_S, a);
	}
}

uint8_t sig_poly_eta_e_compresser(
	uint8_t *res,
	const sig_poly a
) {
	if (AIGIS_SIG_ETA_E <= 3) {
		return sig_comp_poly3_8(res, AIGIS_SIG_ETA_E, a);
	}
	return sig_comp_poly1_2(res, AIGIS_SIG_ETA_E, a);
}

#define UNPACK_ERR 1
uint8_t sig_poly_eta_e_decompresser(
	sig_poly res,
	const uint8_t *a
) {
	if (AIGIS_SIG_ETA_E <= 3) {
		return sig_decomp_poly8_3(res, AIGIS_SIG_ETA_E, a);
	} else if (AIGIS_SIG_ETA_E > 7) {
		return UNPACK_ERR;
	}
	return sig_decomp_poly2_1(res, AIGIS_SIG_ETA_E, a);
}
#define PACK_ERR UNPACK_ERR
uint8_t sig_poly_t0_compresser(
	uint8_t *res,
	const sig_poly a 
) {
	switch(AIGIS_SIG_D) {
	case 13:
		return sig_comp_poly13_8(res, a);
	case 14:
		return sig_comp_poly7_4(res, a);
	default:
		return PACK_ERR;
	}
}
#undef PACK_ERR

uint8_t sig_poly_t0_decompresser(
	sig_poly res,
	const uint8_t *a
) {
	switch(AIGIS_SIG_D) {
	case 13:
		return sig_decomp_poly8_13(res, a);
	case 14:
		return sig_decomp_poly4_7(res, a);
	default:
		return UNPACK_ERR;	
	}
}
#undef UNPACK_ERR


/// 大小不匹配啊
void sig_poly_t1_compresser(
	uint8_t *res,
	const sig_poly a 
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		res[i] = a[i];	
	}
}
/// 大小不匹配啊
void sig_poly_t1_decompresser(
	sig_poly res,
	const uint8_t *a
) {
	for (int i = 0; i < AIGIS_N; i ++) {
		res[i] = a[i];	
	}
}

void sig_poly_w1_compresser(
	uint8_t *res,
	const sig_poly a
) {
	for (int i = 0; i < AIGIS_N >> 3; i ++) {
    	res[3*i+0] = a[8*i+0]      | (a[8*i+1] << 3) | (a[8*i+ 2] << 6);
		res[3*i+1] = (a[8*i+2]>>2) | (a[8*i+3] << 1) | (a[8*i+ 4] << 4) | (a[8*i+ 5] << 7);
		res[3*i+2] = (a[8*i+5]>>1) | (a[8*i+6] << 2) | (a[8*i+ 7] << 5);
	}
}

#endif // COMP_H
