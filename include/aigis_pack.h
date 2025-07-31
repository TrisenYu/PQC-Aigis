/// Last modified at 2025年07月31日 星期四 15时58分19秒
/// 密钥交换和签名算法所使用到的打包函数集合
#include "aigis_poly.h"

#ifndef __AIGIS_PACK_H__
#define __AIGIS_PACK_H__

void enc_pack_pub(
    uint8_t res_pub[AIGIS_ENC_PUB_SIZE],
    const enc_veck raw_pub,
    const uint8_t *seed
);
void enc_unpack_pub(
    enc_veck res_pub,
    uint8_t *seed,
    const uint8_t comp_pub[AIGIS_ENC_PUB_SIZE]
);
void enc_pack_sec(
    uint8_t res_sec[AIGIS_ENC_SEC_SIZE],
    const enc_veck raw_sec
);
void enc_unpack_sec(
    enc_veck res_sec,
    const uint8_t comp_sec[AIGIS_ENC_SEC_SIZE]
);
void enc_pack_ciphertext(
    uint8_t res[AIGIS_ENC_CFT_SIZE],
    const enc_veck cipher_vec1,
    const enc_poly cipher_poly2
);
void enc_unpack_ciphertext(
    enc_veck res_veck,
    enc_poly res_poly,
    const uint8_t comp_cipher[AIGIS_ENC_CFT_SIZE]
);
/// 签名封装函数
void sig_pack_pub(
	uint8_t res_pub[AIGIS_SIG_PUB_SIZE],
	const uint8_t rho[AIGIS_SEED_SIZE],
	const sig_veck t1
);
void sig_unpack_pub(
	uint8_t res_rho[AIGIS_SEED_SIZE],
	sig_veck res_t1,
	const uint8_t pub[AIGIS_SIG_PUB_SIZE]
);
void sig_pack_sec(
	uint8_t res_sec[AIGIS_SIG_SEC_SIZE],
	const uint8_t buf[AIGIS_SEED_SIZE*2+AIGIS_CRH_SIZE],
	const sig_vecl s1,
	const sig_veck s2,
	const sig_veck t0
);
void sig_unpack_sec(
	uint8_t  res_buf[AIGIS_SEED_SIZE*2+AIGIS_CRH_SIZE],
	sig_vecl res_s1,
	sig_veck res_s2,
	sig_veck res_t0,
	const uint8_t sec[AIGIS_SIG_SEC_SIZE]
);
void sig_pack_sig(
	uint8_t sig[AIGIS_SIG_SIG_SIZE],
	const sig_vecl z,
	const sig_veck h,
	const sig_poly c
);
int sig_unpack_sig(
	sig_vecl res_z,
	sig_veck res_h,
	sig_poly res_c,
	const uint8_t sig[AIGIS_SIG_SIG_SIZE]
);
#endif // AIGIS_PACK_H
