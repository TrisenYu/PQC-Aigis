
#include <stdint.h>
#include "poly.h"

#ifndef __DEBUG_H__
#define __DEBUG_H__
void dump_enc_poly(enc_poly a) {
    for (int i = 0; i < AIGIS_N; i ++) {
        printf("%04x", a[i]);
        // if (!((i + 1) & 7)) {
        //     puts("");
        // }
    }
    puts("");
}

void dump_enc_pvec(enc_pvec a) {
    for (int i = 0; i < AIGIS_ENC_K; i ++) {
		printf("%d:|\n", i);
        dump_enc_poly(a[i]);
		puts("");
    }
	puts("_-_-_-_-_-_-");
}

void dump_u8arr(uint8_t *a, uint64_t lena) {
    for (int i = 0; i < lena; i ++) {
        printf("%02x", a[i]);
        if (!((i + 1) & 7)) {
            puts("");
        }
    }
    puts("");
}
#endif // DEBUG_H
