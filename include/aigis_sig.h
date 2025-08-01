/// Last modified at 2025年07月31日 星期四 13时33分30秒
/// 用于存放签名算法
#include "aigis_poly.h"
#include "aigis_pack.h"
#include "samplers/rej_samp.h"

// TODO: 熵源
#include "entropy/baby_png.h"

#ifndef __AIGIS_SIG_H__
#define __AIGIS_SIG_H__
void sig_challenge(
	sig_poly ch,
	const uint8_t mu[AIGIS_CRH_SIZE],
	const sig_veck w1
);
int aigis_inner_keypair(
	uint8_t *res_pub,
	uint8_t *res_sec,
	uint8_t *coins
);
int aigis_sig_keypair(
	uint8_t *res_pub,
	uint8_t *res_sec
);
int aigis_inner_sign(
	uint8_t *sig,
	size_t *sig_len,
	const uint8_t *msg,
	size_t msg_len,
	const uint8_t *sec
);
int aigis_sign_gen(
	uint8_t *sig,
	size_t *sig_len,
	const uint8_t *m,
	size_t msg_len,
	const uint8_t *ctx,
	size_t ctx_len,
	const uint8_t *sec
);
int aigis_create_sign(
	uint8_t *sig_msg,
	size_t *smsg_len,
	const uint8_t *m,
	size_t msg_len,
	const uint8_t *ctx,
	size_t ctx_len,
	const uint8_t *sec
);
int aigis_inner_verify(
  const uint8_t *sig, size_t sig_len,
  const uint8_t *msg, size_t msg_len,
  const uint8_t *pub
);
int aigis_sign_verify(
	const uint8_t *sig,
	size_t sig_len,
	const uint8_t *m,
	size_t msg_len,
	const uint8_t *ctx,
	size_t ctx_len,
	const uint8_t *pub
);
int aigis_reveal_sign(
	uint8_t *msg,
	size_t *msg_len,
	const uint8_t *sig_msg,
	size_t smsg_len,
	const uint8_t *ctx,
	size_t ctx_len,
	const uint8_t *pub
);

#endif // AIIGS_SIG_H
