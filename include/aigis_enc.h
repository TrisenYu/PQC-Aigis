/// Last modified at 2025年07月31日 星期四 13时33分23秒
#include "ntt.h"
#include "aigis_const.h"
#include "aigis_poly.h"
#include "aigis_comp.h"
#include "aigis_pack.h"

#include "hash/kdf_aux.h"
#include "entropy/baby_png.h"

#ifndef __AIGIS_ENC_H__
#define __AIGIS_ENC_H__



/*************************************************
* Name:        is_arr_eq
*
* Description: Compare two arrays for equality in constant time.
*
* Arguments:   const uint8_t *a: pointer to first byte array
*              const uint8_t *b: pointer to second byte array
*              size_t len:             length of the byte arrays
*
* Returns 0 if the byte arrays are equal, 1 otherwise
**************************************************/
static int is_arr_eq(
    const uint8_t *a,
    const uint8_t *b,
    size_t len
) {
    uint64_t r = 0;
    size_t i = 0;

    for (; i < len; i ++){
        r |= a[i] ^ b[i];
    }
    r = (0-r) >> 63;
    return r;
}

/*************************************************
* Name:        cmov
*
* Description: Copy len bytes from x to r if b is 1;
*              don't modify x if b is 0. Requires b to be in {0,1};
*              assumes two's complement representation of negative integers.
*              Runs in constant time.
*
* Arguments:   uint8_t *r:       pointer to output byte array
*              const uint8_t *x: pointer to input byte array
*              size_t len:             Amount of bytes to be copied
*              uint8_t b:        Condition bit; has to be in {0,1}
**************************************************/
static void cmov(
    uint8_t *r,
    const uint8_t *x,
    size_t len,
    uint8_t b
) {
    size_t i = 0;

    b = -b;
    for (; i < len; i++) {
        r[i] ^= b & (x[i] ^ r[i]);
    }
}

static int aigis_enc_keypair(
    uint8_t res_pub[AIGIS_ENC_PUB_SIZE],
    uint8_t res_sec[AIGIS_ENC_SEC_SIZE],
    const uint8_t coins[AIGIS_SEED_SIZE]
);
int aigis_enc_encrypt(
    uint8_t res_cipher[AIGIS_ENC_CFT_SIZE],
    const uint8_t msg[AIGIS_SEED_SIZE],
    const uint8_t comp_pub[AIGIS_ENC_PUB_SIZE],
    const uint8_t coins[AIGIS_SEED_SIZE]
);
void aigis_enc_decrypt(
    uint8_t res_msg[AIGIS_SEED_SIZE],
    const uint8_t cipher[AIGIS_ENC_CFT_SIZE],
    const uint8_t comp_sec[AIGIS_ENC_SEC_SIZE]
);
void aigis_enc_encryptor(
    uint8_t *res_cipher,
    uint8_t *shared_sec,
    const uint8_t *pub
);
void aigis_enc_decryptor(
    uint8_t *res_shared_sec,
    const uint8_t *cipher,
    const uint8_t *comp_sec
);
int aigis_enc_keygen(uint8_t *pub, uint8_t *sec);
#endif // AIGIS_ENC_H
