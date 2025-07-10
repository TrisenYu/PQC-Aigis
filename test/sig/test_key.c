/// SPDX-LICENSE-IDENTIFIER: GPL2.0
///
/// (C) All rights reversed.
/// Author: <kisfg@hotmail.com> in 2025
/// FileName: test_key.c
/// Created at 2025年07月09日 星期三 12时21分43秒
#define __DEBUG
#include "../../aigis_sig.h"
#include "../../debug.h"

uint8_t pub[AIGIS_SIG_PUB_SIZE],
		sec[AIGIS_SIG_SEC_SIZE],
		sed[AIGIS_SEED_SIZE];
uint8_t msg[1024] = "helloworld!?!?!?!?!?",
		sig[4096];
size_t sig_len;
int main() {
	sig_inner_keypair(pub, sec, sed);
	// dump_u8arr(pub, AIGIS_SIG_PUB_SIZE);
	// puts("sec");
	// dump_u8arr(sec, AIGIS_SIG_SEC_SIZE);
	// unsigned char *sig, 
	// size_t *sig_len, 
	// const unsigned char *msg, 
	// size_t msg_len, 
	// const unsigned char *sec
	/*
	 *	1852 20
		00,a2,f6,84,b5,ca,00,66,e0,88,ee,94,a3,fe,f9,41,
		cd,e9,32,52,83,66,c5,c8,28,8b,4a,d8,f0,5c,01,e5,
		41,73,02,9d,01,3f,cb,c5,6b,8f,26,4f,df,5d,9c,e2,
		eb,cc,9e,19,42,9e,25,4a,8e,8a,44,06,f7,c7,cf,2d
	 * */
	crypto_sign_signature_internal(sig, &sig_len, msg, 20, sec);
	// dump_u8arr(sig, AIGIS_SIG_SIG_SIZE);
	// printf("%zu\n", sig_len);

	size_t msg_len = 20;
	// const unsigned char *sig, size_t sig_len,
	// const unsigned char *msg, size_t msg_len,
	// const unsigned char *pub
	int ret = crypto_sign_verify_internal(sig, sig_len, msg, msg_len, pub);
	printf("%d", ret);
	return ret;
}

