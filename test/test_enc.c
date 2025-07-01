#include "../aigis_enc.h"
#include "../debug.h"

uint8_t msg[AIGIS_SEED_SIZE] = "helloworld?!?!?!?!";

uint8_t pubkey[AIGIS_ENC_PUB_SIZE],
        seckey[AIGIS_ENC_SEC_SIZE],
        test_cipher[AIGIS_ENC_CFT_SIZE],
        test_text[AIGIS_SEED_SIZE],
        coins[AIGIS_SEED_SIZE<<1];

uint8_t check_msg(uint8_t *a, uint8_t *b) {
    for (int i = 0; i < AIGIS_SEED_SIZE; i ++) {
        if (a[i] ^ b[i]) { return 1; }
    }
    return 0;
}

// #include <assert.h>

int main() {
    int ret = aigis_enc_keygen(pubkey, seckey);
    if (ret) {
        puts("keygen failed!");
        return 1;
    }
    ret = aigis_enc_encrypt(test_cipher, msg, pubkey, coins);
    if (ret) {
        return 1 * puts("encryption failed!");
    }
    // dump_u8arr(test_cipher, AIGIS_ENC_CFT_SIZE);
    aigis_enc_decrypt(test_text, test_cipher, seckey);
    if (check_msg(test_text, msg)) {
        puts("recovering failed!\nmsg:");
        dump_u8arr(msg, AIGIS_SEED_SIZE);
        puts("recover:");
        dump_u8arr(test_text, AIGIS_SEED_SIZE);
        return 1;    
    }
	for (int i = 0; i < AIGIS_SEED_SIZE; i ++) {
		putchar(test_text[i]);
	}
    puts("well done!");
    return 0;
}
