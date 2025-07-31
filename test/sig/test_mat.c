/// Last modified at 2025年07月31日 星期四 14时12分01秒
#define __DEBUG

#include "aigis_sig.h"
#include "debug.h"
sig_matr_kl mat;
sig_vecl s1;
sig_veck s2;
uint8_t sed[AIGIS_SEED_SIZE];

uint8_t pub[AIGIS_SIG_PUB_SIZE],
		sec[AIGIS_SIG_SEC_SIZE],
		ctx[AIGIS_SEED_SIZE];

int main() {
	sig_expand_mat(mat, sed);
	/*
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		for (int j = 0; j < AIGIS_SIG_L; j ++) {
			dump_sig_poly(mat[i][j]);
		}
	}
	*/
	/*
	uint32_t nonce = 0;
	puts("-=-=-=-=-=-== before eta_s -=-=-=-=-=-=");
	for (int i = 0; i < AIGIS_SIG_L; i ++) {
		sig_poly_eta_s_uniform(s1[i], sed, nonce++);
		dump_sig_poly(s1[i]);
	}
	puts("-=-=-=-=-=-== before eta_e -=-=-=-=-=-=");
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_eta_e_uniform(s2[i], sed, nonce++);
		dump_sig_poly(s2[i]);
	}
	printf("%d %d\n", AIGIS_SIG_K, AIGIS_SIG_L);
	*/
	return 0;
}
