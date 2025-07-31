/// SPDX-LICENSE-IDENTIFIER: GPL2.0
///
/// (C) All rights reserved. Author: <kisfg@hotmail.com> in 2025
/// Created at 2025年07月31日 星期四 23时06分52秒
/// Last modified at 2025年07月31日 星期四 23时07分13秒
#include "debug.h"
void dump_enc_poly(const int16_t a[AIGIS_N]) {
    for (int i = 0; i < AIGIS_N; i ++) {
        printf("%04x", a[i]);
    }
    puts("");
}

void dump_enc_veck(const int16_t a[AIGIS_ENC_K][AIGIS_N]) {
    for (int i = 0; i < AIGIS_ENC_K; i ++) {
		printf("%d:|\n", i);
        dump_enc_poly(a[i]);
		puts("");
    }
	puts("");
}

void dump_sig_poly(const uint32_t a[AIGIS_N]) {
    for (int i = 0; i < AIGIS_N; i ++) {
        printf("%x,", a[i]);
        if (!((i + 1) & 15)) {
            puts("");
        }
    }
    puts("");
}

void dump_sig_vecl(const uint32_t a[AIGIS_SIG_L][AIGIS_N]) {
    for (int i = 0; i < AIGIS_SIG_L; i ++) {
		printf("%d:|\n", i);
        dump_sig_poly(a[i]);
		puts("");
    }
	puts("");
}

void dump_sig_veck(const uint32_t a[AIGIS_SIG_K][AIGIS_N]) {
    for (int i = 0; i < AIGIS_SIG_K; i ++) {
		printf("%d:|\n", i);
        dump_sig_poly(a[i]);
		puts("");
    }
	puts("");
}

void dump_u8arr(const uint8_t *a, uint64_t lena) {
    for (int i = 0; i < lena; i ++) {
        printf("%02x,", a[i]);
        if (!((i + 1) & 31)) {
            puts("");
        }
    }
    puts("");
}
