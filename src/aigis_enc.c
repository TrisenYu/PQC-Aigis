/// Last modified at 2025年08月01日 星期五 18时30分42秒
#include "aigis_enc.h"

#define NEED_TRANSPOSE 1
#define DONT_TRANSPOSE 0

/// 从此处生成公钥和私钥
static int aigis_enc_keypair(
    uint8_t res_pub[AIGIS_ENC_PUB_SIZE],
    uint8_t res_sec[AIGIS_ENC_SEC_SIZE],
    const uint8_t coins[AIGIS_SEED_SIZE]
) {
    enc_veck *pub_vec = (enc_veck*)malloc(sizeof(enc_veck)),
             *sec_vec = (enc_veck*)malloc(sizeof(enc_veck)),
             *err_vec = (enc_veck*)malloc(sizeof(enc_veck));
    enc_matr *mat_a   = (enc_matr*)malloc(sizeof(enc_matr));
    uint8_t buf[AIGIS_SEED_SIZE<<1],
            *pub_seed = buf,
            *err_seed = buf + AIGIS_SEED_SIZE;
    int nonce = 0;
    memcpy(buf, coins, AIGIS_SEED_SIZE);
    hash_g(buf, buf, AIGIS_SEED_SIZE);
    // 生成矩阵
    enc_gen_matr(*mat_a, pub_seed, DONT_TRANSPOSE);
    // 获取 sec
    int ret = enc_gen_veck_via_noise(
        *sec_vec, AIGIS_ENC_ETA_S_INP_SIZE,
        err_seed, nonce
    );
    if (ret) { goto end; }
    nonce += AIGIS_ENC_K;
    // 获取误差向量
    ret = enc_gen_veck_via_noise(
        *err_vec, AIGIS_ENC_ETA_E_INP_SIZE,
        err_seed, nonce
    );
    if (ret) { goto end; }
    nonce += AIGIS_ENC_K;
    // s = ntt(s)
    enc_veck_ntt(*sec_vec);
    // pub = A_hat o s_hat
    enc_ntt_matr_act(*pub_vec, *mat_a, *sec_vec);
    enc_veck_inv_ntt(*pub_vec);
    // pub = As + e
    enc_veck_add(*pub_vec, *pub_vec, *err_vec);
    // 将负值归约到[0, q)范围内
    enc_veck_shrink_q(*pub_vec, enc_nq_q);
    enc_veck_shrink_q(*sec_vec, enc_nq_q);

    // 封装密钥
    enc_pack_pub(res_pub, *pub_vec, pub_seed);
    enc_pack_sec(res_sec, *sec_vec);
end:
    free(pub_vec);
    free(sec_vec);
    free(err_vec);
    free(mat_a);
    return ret;
}

int aigis_enc_encrypt(
    uint8_t res_cipher[AIGIS_ENC_CFT_SIZE],
    const uint8_t msg[AIGIS_SEED_SIZE],
    const uint8_t comp_pub[AIGIS_ENC_PUB_SIZE],
    const uint8_t coins[AIGIS_SEED_SIZE]
) {
    enc_veck *s_vec        = (enc_veck*)malloc(sizeof(enc_veck)),
             *pub_vec      = (enc_veck*)malloc(sizeof(enc_veck)),
             *err_vec      = (enc_veck*)malloc(sizeof(enc_veck)),
             *cipher_vec1  = (enc_veck*)malloc(sizeof(enc_veck));
    enc_matr *mat_at       = (enc_matr*)malloc(sizeof(enc_matr));
    enc_poly *cipher_poly2 = (enc_poly*)malloc(sizeof(enc_poly)),
             *msg_poly     = (enc_poly*)malloc(sizeof(enc_poly)),
             *err_poly     = (enc_poly*)malloc(sizeof(enc_poly));
    uint8_t seed[AIGIS_SEED_SIZE],
            nonce = 0;

    enc_unpack_pub(*pub_vec, seed, comp_pub);
    enc_veck_ntt(*pub_vec);

    // 将消息编码到多项式上
    enc_poly_from_msg(*msg_poly, msg);
    // 矩阵 A^T
    enc_gen_matr(*mat_at, seed, NEED_TRANSPOSE);
    int ret = enc_gen_veck_via_noise(
        *s_vec, AIGIS_ENC_ETA_S_INP_SIZE,
        coins, nonce
    );
    if (ret) { goto end; }
    nonce += AIGIS_ENC_K;
    ret = enc_gen_veck_via_noise(
        *err_vec, AIGIS_ENC_ETA_E_INP_SIZE,
        coins, nonce
    );
    if (ret) { goto end; }
	nonce += AIGIS_ENC_K;
    enc_gen_poly_in_eta_e(*err_poly, coins, nonce);

    enc_veck_ntt(*s_vec);
    // st At + err_v
    enc_ntt_matr_act(*cipher_vec1, *mat_at, *s_vec);
    enc_veck_inv_ntt(*cipher_vec1);
    enc_veck_add(*cipher_vec1, *cipher_vec1, *err_vec);

    // pub s_vec + err_poly - msg_poly
    enc_inner_mul(*cipher_poly2, *pub_vec, *s_vec);
    enc_inv_ntt(*cipher_poly2);

    enc_poly_add(*cipher_poly2, *cipher_poly2, *err_poly);
    enc_poly_sub(*cipher_poly2, *cipher_poly2, *msg_poly);

    enc_poly_shrink_q(*cipher_poly2, enc_n2q_q);
    enc_veck_shrink_q(*cipher_vec1, enc_nq_q);

    enc_pack_ciphertext(res_cipher, *cipher_vec1, *cipher_poly2);
end:
    free(s_vec);
    free(pub_vec);
    free(err_vec);
    free(cipher_vec1);
    free(mat_at);
    free(cipher_poly2);
    free(msg_poly);
    free(err_poly);
    return ret;
}
#undef NEED_TRANSPOSE
#undef DONT_TRANSPOSE

void aigis_enc_decrypt(
    uint8_t res_msg[AIGIS_SEED_SIZE],
    const uint8_t cipher[AIGIS_ENC_CFT_SIZE],
    const uint8_t comp_sec[AIGIS_ENC_SEC_SIZE]
) {
    enc_veck *sec_veck = (enc_veck*)malloc(sizeof(enc_veck)),
             *cip_veck = (enc_veck*)malloc(sizeof(enc_veck));
    enc_poly *cip_poly = (enc_poly*)malloc(sizeof(enc_poly)),
             *msg_poly = (enc_poly*)malloc(sizeof(enc_poly));

    enc_unpack_ciphertext(*cip_veck, *cip_poly, cipher);
    enc_unpack_sec(*sec_veck, comp_sec);

    enc_veck_ntt(*cip_veck);
    enc_inner_mul(*msg_poly, *sec_veck, *cip_veck);
    enc_inv_ntt(*msg_poly);
    enc_poly_sub(*msg_poly, *msg_poly, *cip_poly);
    enc_poly_shrink_q(*msg_poly, enc_n2q_q);
    enc_poly_to_msg(res_msg, *msg_poly);

    free(sec_veck);
    free(cip_veck);
    free(cip_poly);
    free(msg_poly);
}

void aigis_enc_encryptor(
    uint8_t *res_cipher,
    uint8_t *shared_sec,
    const uint8_t *pub
) {
    uint8_t coins[AIGIS_SEED_SIZE] = {0},
            buf[AIGIS_SEED_SIZE*3],
            kr[AIGIS_SEED_SIZE];

	/// TODO: entropy
    randombytes(coins, AIGIS_SEED_SIZE);
    // buf := H(coins)||H(pub)

	/// TODO: hash_h
    hash_h(buf, coins, AIGIS_SEED_SIZE);
    hash_h(buf+AIGIS_SEED_SIZE, pub, AIGIS_ENC_PUB_SIZE);

    // kr := H{H(coins)||H(pub)}
	/// TODO: hash_h
    hash_h(kr, buf, AIGIS_SEED_SIZE<<1);
    // msg := buf, coins := kr
    aigis_enc_encrypt(res_cipher, buf, pub, kr);

	/// TODO: hash_h
    hash_h(buf+AIGIS_SEED_SIZE*2, res_cipher, AIGIS_ENC_CFT_SIZE);
    hash_h(shared_sec, buf, AIGIS_SEED_SIZE*3);
}


void aigis_enc_decryptor(
    uint8_t *res_shared_sec,
    const uint8_t *cipher,
    const uint8_t *comp_sec
) {
    uint8_t cmp[AIGIS_ENC_CFT_SIZE];
    uint8_t buf[AIGIS_SEED_SIZE*3];
    uint8_t kr[AIGIS_SEED_SIZE];
    const uint8_t *pub_pos = comp_sec + AIGIS_ENC_PVEC_SIZE;

    aigis_enc_decrypt(buf, cipher, comp_sec);
    for (int i = 0; i < AIGIS_SEED_SIZE; i ++) {
        buf[AIGIS_SEED_SIZE+i] = comp_sec[i+AIGIS_ENC_SEC_SIZE-AIGIS_SEED_SIZE*2];
    }
	/// TODO: hash_h
    hash_h(kr, buf, AIGIS_SEED_SIZE<<1);
    aigis_enc_encrypt(cmp, buf, pub_pos, kr);

    int fail = is_arr_eq(cipher, cmp, AIGIS_ENC_CFT_SIZE);
    cmov(
        buf, comp_sec+AIGIS_ENC_SEC_SIZE-AIGIS_SEED_SIZE,
        AIGIS_SEED_SIZE, fail
    );
	/// TODO: hash_h
    hash_h(res_shared_sec, buf, AIGIS_SEED_SIZE*3);
}


int aigis_enc_keygen(uint8_t *pub, uint8_t *sec) {
    uint8_t coins[AIGIS_SEED_SIZE << 1] = {0};
    randombytes(coins, AIGIS_SEED_SIZE << 1);
    int ret = aigis_enc_keypair(pub, sec, coins);
    if (ret) { return ret; }
    for (int i = 0; i < AIGIS_ENC_PUB_SIZE; i++) {
        sec[i + AIGIS_ENC_PVEC_SIZE] = pub[i];
    }
	/// TODO: hash_h
    hash_h(
        sec+AIGIS_ENC_SEC_SIZE-AIGIS_SEED_SIZE*2,
        pub, AIGIS_ENC_PUB_SIZE
    );
    memcpy(
        sec+AIGIS_ENC_SEC_SIZE-AIGIS_SEED_SIZE,
        coins+AIGIS_SEED_SIZE, AIGIS_SEED_SIZE
    );
    return 0;
}
