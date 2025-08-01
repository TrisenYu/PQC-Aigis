/// Last modified at 2025年07月31日 星期四 23时08分31秒
#include <stdint.h>
#include <stdio.h>
#include "aigis_const.h"
#ifndef __DEBUG_H__
#define __DEBUG_H__

void dump_enc_poly(const int16_t a[AIGIS_N]);
void dump_enc_veck(const int16_t a[AIGIS_ENC_K][AIGIS_N]);
void dump_sig_poly(const uint32_t a[AIGIS_N]);
void dump_sig_vecl(const uint32_t a[AIGIS_SIG_L][AIGIS_N]);
void dump_sig_veck(const uint32_t a[AIGIS_SIG_K][AIGIS_N]);
void dump_u8arr(const uint8_t *a, uint64_t lena);

#endif // DEBUG_H
