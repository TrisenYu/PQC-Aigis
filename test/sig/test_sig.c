/// Last modified at 2025年07月31日 星期四 14时12分21秒
#include "aigis_sig.h"
#include "entropy/baby_png.h"
uint8_t msg1[AIGIS_SIG_SIG_SIZE],
        msg2[AIGIS_SIG_SIG_SIZE + AIGIS_SEED_SIZE],
        sig_msg[AIGIS_SIG_SIG_SIZE + AIGIS_SEED_SIZE];

uint8_t pub[AIGIS_SIG_PUB_SIZE],
        sec[AIGIS_SIG_SEC_SIZE],
        ctx[AIGIS_SEED_SIZE];

#define ROUND 500
int main() {
    size_t sig_msg_len = 0, msg_len = 0;
    randombytes(ctx, AIGIS_SEED_SIZE);
    int i = ROUND;
    while (i--) {
        randombytes(msg1, AIGIS_SEED_SIZE);
        int ret = sig_keypair(pub, sec);
        if (ret) {
            puts("unable to correctly generate sign-keypair!");
            return 1;
        }
        // 调试用输出msg
        ret = crypto_sign(sig_msg, &sig_msg_len, msg1, AIGIS_SEED_SIZE, ctx, AIGIS_SEED_SIZE, sec);
        if (ret || sig_msg_len != AIGIS_SIG_SIG_SIZE + AIGIS_SEED_SIZE) {
            puts("unable to correctly sign message!");
            return 1;
        }
        ret = crypto_sign_open(msg2, &msg_len, sig_msg, sig_msg_len, ctx, AIGIS_SEED_SIZE, pub);
        if (ret || msg_len != AIGIS_SEED_SIZE) {
            puts("unable to verify signature!");
            return 1;
        }
        if (msg_len != AIGIS_SEED_SIZE) {
            puts("incorrect msg_len!");
            return 1;
        }
        for (int j = 0; j < msg_len; j ++) {
            if (msg1[j] ^ msg2[j]) {
                puts("incorrect msg_content!");
                return 1;
            }
        }
        //最后再测伪造
        uint8_t pos;
        randombytes(&pos, 1);
        do {
            randombytes(msg2, 1);
        } while(!msg2[0]);
        sig_msg[pos % AIGIS_SIG_SIG_SIZE] += msg2[0];
        ret = crypto_sign_open(msg2, &msg_len, sig_msg, sig_msg_len, ctx, AIGIS_SEED_SIZE, pub);
        if (!ret) {
            puts("impossible condition!");
            return 1;
        }
    }
    return 0 * puts("ok");
}
