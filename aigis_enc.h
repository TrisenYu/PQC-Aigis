#include "aigis_const.h"
#include "ntt.h"
#include "kdf_aux.h"
#include "entropy/baby_png.h"

#include "poly.h"
#include "comp.h"
#include "check.h"

#ifndef __AIGIS_ENC_H__
#define __AIGIS_ENC_H__

/*
    需要:
    compresser/decompresser
    reject-sampler
*/

/// 调用此函数封装公钥
/// comp_pub := pub||seed
void pack_pub(
    uint8_t *res_pub, 
    const enc_pvec raw_pub,
    const uint8_t *seed
) {
    int i = 0;
    enc_pub_compresser(res_pub, raw_pub);
    for (; i < AIGIS_SEED_SIZE; i ++) {
        res_pub[i+AIGIS_COMP_PUB_SIZE] = seed[i];
    }
}
/// 调用此函数解封公钥
void unpack_comp_pub(
    enc_pvec res_pub, 
    uint8_t *seed,
    const uint8_t *comp_pub
) {
    int i = 0;
    for (; i < AIGIS_SEED_SIZE; i ++) {
        seed[i] = comp_pub[i + AIGIS_COMP_PUB_SIZE];
    }
    enc_pub_decompresser(res_pub, comp_pub);

}
/// 调用此函数封装私钥
void pack_sec(
    uint8_t *res_sec,
    const enc_pvec raw_sec
) {
    int i = 0;
    for (; i < AIGIS_ENC_K; i ++) {
        enc_poly2bytes(res_sec+i*AIGIS_ENC_POLY_SIZE, raw_sec[i]);
    }
}
/// 调用此函数解封私钥
void unpack_comp_sec(
    enc_pvec res_sec, 
    const uint8_t *comp_sec
) {
    int i = 0;
    for (; i < AIGIS_ENC_K; i ++) {
        enc_bytes2poly(res_sec[i], comp_sec+i*AIGIS_ENC_POLY_SIZE);
    }

}

void pack_ciphertext(
    uint8_t *res,
    const enc_pvec cipher_vec1,
    const enc_poly cipher_poly2
) {
    enc_cft_pvec_compresser(res, cipher_vec1);
    enc_cft_poly_compresser(res+AIGIS_COMP_CFT_SIZE, cipher_poly2);
}

void unpack_ciphertext(
    enc_pvec res_pvec,
    enc_poly res_poly,
    const uint8_t *comp_cipher
) {
    enc_cft_poly_decompresser(res_poly, comp_cipher+AIGIS_COMP_CFT_SIZE);
    enc_cft_pvec_decompresser(res_pvec, comp_cipher);
}

#define NEED_TRANSPOSE 1
#define DONT_TRANSPOSE 0

/// 从此处生成公钥和私钥
static int aigis_enc_keypair(
    uint8_t res_pub[AIGIS_ENC_PUB_SIZE], 
    uint8_t res_sec[AIGIS_ENC_SEC_SIZE], 
    const uint8_t coins[AIGIS_SEED_SIZE]
) {
    enc_pvec pub_vec, 
             sec_vec, 
             err_vec;
    enc_matr mat_a; 
    uint8_t buf[AIGIS_SEED_SIZE<<1],
            *pub_seed = buf, 
            *err_seed = buf + AIGIS_SEED_SIZE;
    int nonce = 0;
    memcpy(buf, coins, AIGIS_SEED_SIZE);
    hash_g(buf, buf, AIGIS_SEED_SIZE);
    // 生成矩阵
    enc_gen_matr(mat_a, pub_seed, DONT_TRANSPOSE);
    // 获取 sec
    int ret = enc_gen_pvec_via_noise(
        sec_vec, 
        AIGIS_ENC_ETA_S_INP_SIZE, 
        err_seed, 
        nonce
    );
    if (ret) {
        return ret;
    }
    nonce += AIGIS_ENC_K;
    // 获取 err
    ret = enc_gen_pvec_via_noise(
        err_vec,
        AIGIS_ENC_ETA_E_INP_SIZE,
        err_seed, 
        nonce
    );
    if (ret) {
        return ret;
    }
    nonce += AIGIS_ENC_K;
    // s = ntt(s)
    enc_pvec_ntt(sec_vec);
    // pub = A_hat o s_hat
    enc_ntt_matr_act(pub_vec, mat_a, sec_vec);
    enc_pvec_inv_ntt(pub_vec);

    // pub += err 
    // => pub = As + e
    enc_pvec_add(pub_vec, pub_vec, err_vec);
    // 将负值归约到[0, q)范围内
    enc_pvec_nq_q(pub_vec);
    enc_pvec_nq_q(sec_vec);

    // 封装密钥
    pack_pub(res_pub, pub_vec, pub_seed);
    pack_sec(res_sec, sec_vec);
    return 0;
}

int aigis_enc_encrypt(
    uint8_t res_cipher[AIGIS_ENC_CFT_SIZE],
    const uint8_t msg[AIGIS_SEED_SIZE],
    const uint8_t comp_pub[AIGIS_ENC_PUB_SIZE],
    const uint8_t coins[AIGIS_SEED_SIZE] 
) {
    enc_pvec *s_vec       = (enc_pvec*)malloc(sizeof(enc_pvec)),
             *pub_vec     = (enc_pvec*)malloc(sizeof(enc_pvec)),
             *err_vec     = (enc_pvec*)malloc(sizeof(enc_pvec)),
             *cipher_vec1 = (enc_pvec*)malloc(sizeof(enc_pvec));
    enc_matr *mat_at      = (enc_matr*)malloc(sizeof(enc_matr));
    enc_poly *cipher_poly2= (enc_poly*)malloc(sizeof(enc_poly)),
             *msg_poly    = (enc_poly*)malloc(sizeof(enc_poly)),
             *err_poly    = (enc_poly*)malloc(sizeof(enc_poly));
    uint8_t seed[AIGIS_SEED_SIZE], 
            nonce = 0;

    unpack_comp_pub(*pub_vec, seed, comp_pub);
    enc_pvec_ntt(*pub_vec);

    // 将消息编码到多项式上
    // TODO:
    //      还是有点奇怪，
    //      这个函数要求的msg长度为 AIGIS_SEED_SIZE.
    //      照理来说应该能对任意字节都能做才是
    // 感觉可能要改成循环？然后剩余的补零
    enc_poly_from_msg(*msg_poly, msg);
    // 矩阵 A^T
    enc_gen_matr(*mat_at, seed, NEED_TRANSPOSE);
    int ret = enc_gen_pvec_via_noise(
        *s_vec, 
        AIGIS_ENC_ETA_S_INP_SIZE, 
        coins, 
        nonce
    );
    if (ret) {
        return ret;
    }
    nonce += AIGIS_ENC_K;
    ret = enc_gen_pvec_via_noise(
        *err_vec, 
        AIGIS_ENC_ETA_E_INP_SIZE, 
        coins, 
        nonce
    );
    if (ret) {
        return ret;
    }
	nonce += AIGIS_ENC_K;
    enc_gen_poly_in_eta_e(*err_poly, coins, nonce);

    enc_pvec_ntt(*s_vec);

    enc_ntt_matr_act(*cipher_vec1, *mat_at, *s_vec);
    enc_pvec_inv_ntt(*cipher_vec1);
    enc_pvec_add(*cipher_vec1, *cipher_vec1, *err_vec);

    // 向量 pub 点乘向量 s
    enc_inner_mul(*cipher_poly2, *pub_vec, *s_vec);
    enc_inv_ntt(*cipher_poly2);

    enc_poly_add(*cipher_poly2, *cipher_poly2, *err_poly);
    enc_poly_sub(*cipher_poly2, *cipher_poly2, *msg_poly);

    enc_poly_n2q_q(*cipher_poly2);
    enc_pvec_nq_q(*cipher_vec1);
    
    // TODO: 比如分段做
    pack_ciphertext(res_cipher, *cipher_vec1, *cipher_poly2);
    free(s_vec);
    free(pub_vec);
    free(err_vec);
    free(cipher_vec1);
    free(mat_at);
    free(cipher_poly2);
    free(msg_poly);
    free(err_poly);
    return 0;
}
#undef NEED_TRANSPOSE
#undef DONT_TRANSPOSE

void aigis_enc_decrypt(
    uint8_t res_msg[AIGIS_SEED_SIZE],
    const uint8_t cipher[AIGIS_ENC_CFT_SIZE],
    const uint8_t comp_sec[AIGIS_ENC_SEC_SIZE]
) {
    enc_pvec *sec_pvec = (enc_pvec*)malloc(sizeof(enc_pvec)),
             *cip_pvec = (enc_pvec*)malloc(sizeof(enc_pvec));
    enc_poly *cip_poly = (enc_poly*)malloc(sizeof(enc_poly)), 
             *msg_poly = (enc_poly*)malloc(sizeof(enc_poly));

    unpack_ciphertext(*cip_pvec, *cip_poly, cipher);
    unpack_comp_sec(*sec_pvec, comp_sec);


    enc_pvec_ntt(*cip_pvec);
    enc_inner_mul(*msg_poly, *sec_pvec, *cip_pvec);
    enc_inv_ntt(*msg_poly);
    enc_poly_sub(*msg_poly, *msg_poly, *cip_poly);
    enc_poly_n2q_q(*msg_poly);
    enc_poly_to_msg(res_msg, *msg_poly);
    free(sec_pvec);
    free(cip_pvec);
    free(cip_poly);
    free(msg_poly);
}

void aigis_enc_encryptor(
    uint8_t *res_cipher, 
    uint8_t *shared_sec,
    const uint8_t *pub 
) {
    uint8_t coins[AIGIS_SEED_SIZE], 
            buf[AIGIS_SEED_SIZE*3],
            kr[AIGIS_SEED_SIZE];

    randombytes(coins, AIGIS_SEED_SIZE);
    // buf := H(coins)||H(pub)
    hash_h(buf, coins, AIGIS_SEED_SIZE);
    hash_h(buf+AIGIS_SEED_SIZE, pub, AIGIS_ENC_PUB_SIZE);
    // kr := H{H(coins)||H(pub)}
    hash_h(kr, buf, AIGIS_SEED_SIZE<<1);
    // msg := buf, coins := kr 
    aigis_enc_encrypt(res_cipher, buf, pub, kr);  
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
    hash_h(kr, buf, AIGIS_SEED_SIZE<<1);
    aigis_enc_encrypt(cmp, buf, pub_pos, kr);

    int fail = is_arr_eq(cipher, cmp, AIGIS_ENC_CFT_SIZE);
    cmov(
        buf, 
        comp_sec+AIGIS_ENC_SEC_SIZE-AIGIS_SEED_SIZE, 
        AIGIS_SEED_SIZE, 
        fail
    );
    hash_h(res_shared_sec, buf, AIGIS_SEED_SIZE*3);
}


/// 什么情况下会失败呢？
int aigis_enc_keygen(uint8_t *pub, uint8_t *sec) {
    uint8_t coins[AIGIS_SEED_SIZE << 1];
    randombytes(coins, AIGIS_SEED_SIZE << 1);
    int ret = aigis_enc_keypair(pub, sec, coins);
    if (ret) {
        return ret;
    }
    for (int i = 0; i < AIGIS_ENC_PUB_SIZE; i++) {
        sec[i + AIGIS_ENC_PVEC_SIZE] = pub[i];
    }
    hash_h(
        sec+AIGIS_ENC_SEC_SIZE-AIGIS_SEED_SIZE*2, 
        pub, 
        AIGIS_ENC_PUB_SIZE
    );
    memcpy(
        sec+AIGIS_ENC_SEC_SIZE-AIGIS_SEED_SIZE, 
        coins+AIGIS_SEED_SIZE, 
        AIGIS_SEED_SIZE
    );
    return 0;
} 
#endif // AIGIS_ENC_H
