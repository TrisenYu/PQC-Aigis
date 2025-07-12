/// Last modified at 2025年07月12日 星期六 14时35分27秒
#include "../../aigis_poly.h"
#include "../../aigis_enc.h"
#include "../../debug.h"

uint8_t seed[AIGIS_N], buf[2048];
uint8_t buf1[2048], msg[AIGIS_SEED_SIZE] = "helloworld?!?!?!";
uint8_t tsed[AIGIS_SEED_SIZE];
enc_matr mat, mata;
enc_veck a, b, c, sv, ev, tpub, tsec;
enc_poly msg_poly, cip_poly, err_poly;
enc_poly tcip_poly, tmsg_poly;
enc_veck tb, tsv;

int main() {
	enc_gen_matr(mat, seed, 0);
	// for (int i = 0; i < AIGIS_ENC_K; i ++) {
	// 	for (int j = 0; j < AIGIS_ENC_K; j ++) {
	// 		printf("alpha_{%d%d}:\n", i, j);
	// 		for (int k = 0; k < AIGIS_N; k ++) {
	// 			// printf("%08x,", &mat[i][j][k]);
	// 			printf("%04x", mat[i][j][k]);
	// 			if (!((i+1)&7)) { puts(""); }
	// 		}
	// 		puts("");
	// 	}
	// }
	int nonce = 1;
	enc_gen_veck_via_noise(
		a,
		AIGIS_ENC_ETA_S_INP_SIZE,
		seed,
		nonce
	);
	nonce += 1;
	enc_gen_veck_via_noise(
		b,
		AIGIS_ENC_ETA_E_INP_SIZE,
		seed,
		nonce
	);
	// dump_enc_veck(a);
	// dump_enc_veck(b);
	enc_veck_ntt(a);
	enc_ntt_matr_act(c, mat, a);
	enc_veck_inv_ntt(c);
	enc_veck_add(c, c, b);
	enc_veck_shrink_q(c, enc_nq_q);
	enc_veck_shrink_q(a, enc_nq_q);

	enc_pack_pub(buf, c, seed);	
	// AIGIS_ENC_PUB_SIZE
	enc_pack_sec(buf1, a);
	// for (int i = 0; i < AIGIS_ENC_SEC_SIZE; i ++) {
	// 	printf("%02x", buf1[i]);
	// 	if (!((i+1)&31)) { puts(""); }
	// }

	// dump_enc_veck(c);
	// dump_enc_veck(a);
	enc_unpack_pub(tpub, tsed, buf);
	enc_veck_ntt(tpub);
	// unpack_comp_sec(tsec, buf1);
	// dump_enc_veck(c);
	// dump_enc_veck(tpub);
	enc_poly_from_msg(msg_poly, msg);
	// dump_enc_poly(msg_poly);	

	enc_gen_matr(mata, tsed, 1);
	// dump_enc_veck(mata[0]);	

	enc_gen_veck_via_noise(
		sv,
		AIGIS_ENC_ETA_S_INP_SIZE,
		tsed,
		nonce
	);
	nonce += 1;
	enc_gen_veck_via_noise(
		ev,
		AIGIS_ENC_ETA_E_INP_SIZE,
		tsed,
		nonce
	);
	enc_veck_ntt(sv);
	enc_ntt_matr_act(b, mata, sv);
	// for (int i = 0; i < AIGIS_ENC_K; i ++) {
	// 	for (int j = 0; j < AIGIS_N; j ++) {
	// 		printf("%d,", b[i][j]);
	// 		if (!((j+1)&7)) { puts(""); }
	// 	}
	// 	puts("");
	// }
	// puts("after ntt and matr");
	enc_veck_inv_ntt(b);
	// puts("after inv-ntt");
	// dump_enc_veck(b);
	// for (int i = 0; i < AIGIS_ENC_K; i ++) {
	// 	for (int j = 0; j < AIGIS_N; j ++) {
	// 		printf("%d,", b[i][j]);
	// 		if (!((j+1)&7)) { puts(""); }
	// 	}
	// 	puts("");
	// }
	enc_veck_add(b, b, ev);
	enc_gen_poly_in_eta_e(err_poly, tsed, nonce+AIGIS_ENC_K);
	enc_inner_mul(cip_poly, tpub, sv);
	enc_inv_ntt(cip_poly);
	enc_poly_add(cip_poly, cip_poly, err_poly);
	enc_poly_sub(cip_poly, cip_poly, msg_poly);
	enc_poly_shrink_q(cip_poly, enc_n2q_q);
	enc_veck_shrink_q(b, enc_nq_q);

	enc_pack_ciphertext(buf, b, cip_poly);
	/// 有点奇怪，做了这么久都对得上？
	/// 那可能只有解密出错了

	// for (int i = 0; i < AIGIS_ENC_CFT_SIZE; i ++) {
	// 	printf("%02x", buf[i]);
	// 	if (!((i+1)&31)) { puts(""); }
	// }
	enc_unpack_ciphertext(tb, tcip_poly, buf);
	enc_unpack_sec(tsv, buf1);	
	enc_veck_ntt(tb);
	enc_inner_mul(tmsg_poly, tsv, tb);
	enc_inv_ntt(tmsg_poly); /// TODO: 似乎是 ntt 出问题
	enc_poly_sub(tmsg_poly, tmsg_poly, tcip_poly);
	enc_poly_shrink_q(tmsg_poly, enc_n2q_q);
	enc_poly_to_msg(buf, tmsg_poly);
	for (int i = 0; i < AIGIS_SEED_SIZE; i ++) {
		printf("%c", buf[i]);
	}
	puts("");
	// dump_enc_veck(tsv);
	// dump_enc_poly(tmsg_poly);
	// dump_enc_veck(tb);
	// dump_enc_veck(sv);
	// dump_enc_veck(ev);
	return 0;
}
