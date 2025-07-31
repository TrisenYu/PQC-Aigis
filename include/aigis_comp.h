/// Last modified at 2025年07月31日 星期四 16时00分45秒

#include "aigis_const.h"
#include "aigis_poly.h"

#ifndef __AIGIS_COMP_H__
#define __AIGIS_COMP_H__

/// 解压缩算法
typedef void (*comp_poly_fn)(uint8_t *res, const enc_poly a);
typedef void (*decomp_poly_fn)(enc_poly res, const uint8_t *a);
typedef void (*comp_veck_fn)(uint8_t *res, const enc_veck a);
typedef void (*decomp_veck_fn)(enc_veck res, const uint8_t *a);
typedef uint8_t (*comp_restrained_poly_fn)(uint8_t *res, uint32_t eta_val, const sig_poly a);
typedef uint8_t (*comp_sig_poly_fn)(uint8_t *res, const sig_poly a);
typedef uint8_t (*decomp_restrained_poly_fn)(sig_poly res, uint32_t eta_val, const uint8_t *a);
typedef uint8_t (*decomp_sig_poly_fn)(sig_poly res, const uint8_t *a);

static void comp_poly_3(uint8_t *res, const enc_poly a);
static void comp_poly_4(uint8_t *res, const enc_poly a);
static void comp_poly_5(uint8_t *res, const enc_poly a);
static void comp_poly_7(uint8_t *res, const enc_poly a);
void enc_poly2bytes(uint8_t *res, const enc_poly a);
void enc_cft_poly_compresser(uint8_t *res, const enc_poly a);
static void decomp_poly_3(enc_poly res, const uint8_t *a);
static void decomp_poly_4(enc_poly res, const uint8_t *a);
static void decomp_poly_5(enc_poly res, const uint8_t *a);
static void decomp_poly_7(enc_poly res, const uint8_t *a);
void enc_bytes2poly(enc_poly res, const uint8_t *a);
void enc_cft_poly_decompresser(enc_poly res, const uint8_t *a);
static void comp_veck_9(uint8_t *res, const enc_veck a);
static void comp_veck_10(uint8_t *res, const enc_veck a);
static void comp_veck_11(uint8_t *res, const enc_veck a);
/// 压缩器
void enc_pub_compresser(uint8_t *res, const enc_veck a);
void enc_cft_veck_compresser(uint8_t *res, const enc_veck a);

static void decomp_veck_9(enc_veck res, const uint8_t *a);
static void decomp_veck_10(enc_veck res, const uint8_t *a);
static void decomp_veck_11(enc_veck res, const uint8_t *a);
/// 解压缩器
void enc_pub_decompresser(enc_veck res, const uint8_t *a);
void enc_cft_veck_decompresser(enc_veck res, const uint8_t *a);;

/// 和签名解压缩有关的算法
/// 签名算法打包函数
static uint8_t sig_comp_poly1_4(uint8_t *res, uint32_t eta_val, const sig_poly a);
static uint8_t sig_comp_poly3_8(uint8_t *res, uint32_t eta_val, const sig_poly a);
static uint8_t sig_comp_poly1_2(uint8_t *res, uint32_t eta_val, const sig_poly a);
static uint8_t sig_comp_poly13_8(uint8_t *res, const sig_poly a);
static uint8_t sig_comp_poly7_4(uint8_t *res, const sig_poly a);
static uint8_t sig_decomp_poly2_1(sig_poly res, uint32_t eta_val, const uint8_t *a);
static uint8_t sig_decomp_poly4_1(sig_poly res, uint32_t eta_val, const uint8_t *a);
static uint8_t sig_decomp_poly8_3(sig_poly res, uint32_t eta_val, const uint8_t *a);
static uint8_t sig_decomp_poly8_13(sig_poly res, const uint8_t *a);
static uint8_t sig_decomp_poly4_7(sig_poly res, const uint8_t *a);

/// 要是c支持curry也不至于这么写
uint8_t sig_poly_eta_s_compresser(
	uint8_t *res,
	const sig_poly a
);
uint8_t sig_poly_eta_s_decompresser(
	sig_poly res,
	const uint8_t *a
);
uint8_t sig_poly_eta_e_compresser(
	uint8_t *res,
	const sig_poly a
);
uint8_t sig_poly_eta_e_decompresser(
	sig_poly res,
	const uint8_t *a
);
uint8_t sig_poly_t0_compresser(
	uint8_t *res,
	const sig_poly a
);
uint8_t sig_poly_t0_decompresser(
	sig_poly res,
	const uint8_t *a
);
void sig_poly_t1_compresser(
	uint8_t *res,
	const sig_poly a
);
void sig_poly_t1_decompresser(
	sig_poly res,
	const uint8_t *a
);
void sig_poly_z_compresser(
	uint8_t *res,
	const sig_poly a
);
void sig_poly_z_decompresser(
	sig_poly res,
	const uint8_t *a
);
void sig_poly_w1_compresser(
	uint8_t *res,
	const sig_poly a
);
void sig_poly_w1_decompresser(
	sig_poly res,
	const uint8_t *a
);

#endif // AIGIS_COMP_H
