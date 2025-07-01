#include "hash/sm3/sm3.h"
#include "hash/sm3/kdf.h"
#include "hash/keccak/fips202.h"

#include <string.h>
#include <stdlib.h>

#ifndef __KDF_AUX_H__
#define __KDF_AUX_H__

/// 声明状态及辅助宏
typedef struct {
    uint8_t *buf; // 自己拟定大小
    size_t len;
    uint32_t cnt;
} aigis_kdf_state;

#define SM3_STATE_CNT_SIZE  4
#define SHAKE_STATE_CNT_SIZE 200 // 25*8

/// 初始化函数
static void init_sm3(aigis_kdf_state *res, size_t buf_size) {
    res->buf = (uint8_t*)malloc(buf_size+SM3_STATE_CNT_SIZE);
    res->len = buf_size;
    res->cnt = 0;
}

static void init_sha_ke_128(aigis_kdf_state *res, size_t buf_size) {
    res->buf = (uint8_t*)malloc(buf_size+SHAKE_STATE_CNT_SIZE);
    res->len = buf_size;
    res->cnt = 0;
}


/// 吸收函数
static void sm3_absorb(
    aigis_kdf_state* self, 
    const uint8_t* inp, 
    size_t inlen
) {
    size_t choice = inlen >= self->len ? self->len : inlen;
    memcpy(self->buf + SM3_STATE_CNT_SIZE, inp, choice);
	self->cnt = 0;
}

static void sha_ke128_absorb(
    aigis_kdf_state* self, 
    const uint8_t* inp, 
    size_t inlen
) {
    keccak_absorb_once((uint64_t*)(self->buf), SHAKE128_RATE, inp, inlen, 0x1F);
    self->len = SHAKE128_RATE;
}

/// 压缩函数
static void sm3_squeeze(
    aigis_kdf_state *self, 
    uint8_t *res,
    uint64_t nblocks
) {
    uint8_t *nonce = self->buf, *rec = res;
    uint64_t cnt = self->cnt, i = 0;
    while (i < nblocks) {
        for (int j = 0; j < 4; j ++) {
            nonce[j] = (cnt >> ((3 - j) << 3)) & 0xFF;
        }
        sm3(nonce, self->len + SM3_STATE_CNT_SIZE, rec);
        i ++;
        cnt ++;
        rec += SM3_KDF_RATE;
    }
    self->cnt = cnt;
}

static void sha_ke128_squeeze(
    aigis_kdf_state *self, 
    uint8_t *res,
    uint64_t nblocks
) {
    keccak_squeezeblocks(res, nblocks, (uint64_t*)(self->buf), SHAKE128_RATE);
}

/// 手册内的 h 函数。（任意长字节流映射到 l 字节长的摘要）
static void sm3_256(
    uint8_t *res,
    const uint8_t *inp, 
    uint64_t inp_len
) {
    sm3_extented(res, 32, inp, inp_len);
}

/// 手册内的 g 函数。映射到2个l字节长的摘要。
static void sm3_512(
    uint8_t *res,
    const uint8_t *inp, 
    uint64_t inp_len
) {
    sm3_extented(res, 64, inp, inp_len);
}

#ifndef AIGIS_KDF_CONF
    #error "yet to pass essential parameter:AIGIS_KDF_CONF!"
#endif
#if (AIGIS_KDF_CONF < 0 || AIGIS_KDF_CONF > 1)
    #error "invalid configuration upon AIGIS_KDF_CONF!"
#endif // check for AIGIS_KDF_CONF

/// 全局 kdf 定义
typedef void (*_kdf_init)(aigis_kdf_state*, size_t);
typedef void (*_kdf_absorb) (
    aigis_kdf_state*, 
    const uint8_t * /*inp*/, 
    size_t /*inlen*/
);
typedef void (*_kdf_squeeze) (
    aigis_kdf_state*, 
    uint8_t * /*res*/,
    uint64_t /*nblocks*/
);

typedef void (*_hash_x) (
    uint8_t *res, 
    const uint8_t *inp, 
    uint64_t inp_len
);

/// XOF 
typedef void (*_kdf_xof) (
    uint8_t *res, 
    uint64_t res_len,
    const uint8_t *inp, 
    uint64_t inp_len
);

#if (AIGIS_KDF_CONF == 0) 
    _kdf_init kdf_init = init_sm3;
    _kdf_absorb kdf_absorb = sm3_absorb;
    _kdf_squeeze kdf_squeeze = sm3_squeeze;

    _hash_x hash_h = sm3_256;
    _hash_x hash_g = sm3_512;

    _kdf_xof kdf_xof128 = sm3_extented;
    _kdf_xof kdf_xof256 = sm3_extented; // 非常难绷
    #define KDF128_RATE 32
    #define KDF256_RATE KDF128_RATE
#elif (AIGIS_KDF_CONF == 1)
    _kdf_init kdf_init = init_sha_ke_128;
    _kdf_absorb kdf_absorb = sha_ke128_absorb;
    _kdf_squeeze kdf_squeeze = sha_ke128_squeeze;

    _hash_x hash_h = sha3_256;
    _hash_x hash_g = sha3_512;

    _kdf_xof kdf_xof128 = shake128;
    _kdf_xof kdf_xof256 = shake256;

    #define KDF128_RATE SHAKE128_RATE // 168
    #define KDF256_RATE SHAKE256_RATE // 136
#endif // check for AIGIS_KDF_CONF
// = aigis_squeeze_list[AIGIS_KDF_CONF];

void kdf_destroy(aigis_kdf_state* a) {
    free(a->buf);
    a->buf = NULL;
    a->cnt = a->len = 0;
}

#endif // KDF_AUX_H
