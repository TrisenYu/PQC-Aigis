/// Last modified at 2025/09/06 星期六 00:28:31
#include "sm3/sm3.h"
#include "sm3/kdf.h"
#include "keccak/fips202.h"

#include <string.h>
#include <stdlib.h>

#ifndef __KDF_AUX_H__
#define __KDF_AUX_H__

#define KDF200_SUB_32_RATE 168 // 200 - 32
#define KDF200_SUB_64_RATE 136 // 200 - 64

/// 声明状态及辅助宏
typedef struct {
    uint8_t *buf; // 自己拟定大小
    size_t len;
    uint32_t cnt;
} kdf_state;

#define SM3_STATE_CNT_SIZE  4
#define SHAKE_STATE_CNT_SIZE 200 // 25*8

/// 初始化函数
// 注意，需要手动销毁 malloc 带来的影响
#define init_gen(name, state_size)								\
static void init_##name(kdf_state *res, size_t buf_size) {		\
    res->buf = (uint8_t*)calloc(buf_size+state_size, 1);		\
    res->len = buf_size;										\
    res->cnt = 0;												\
}

init_gen(sm3, SM3_STATE_CNT_SIZE);
init_gen(sha_ke, SHAKE_STATE_CNT_SIZE);
#undef init_gen

/// 更改input_buf
static void sm3_alter_inp_buf(
    kdf_state *res,
    size_t pos,
    uint8_t val
) {
    if (res->buf == NULL || pos > res->len) {
        return;
    }
    res->buf[pos+SM3_STATE_CNT_SIZE] = val;
}
// sha_ke128改不了

/// 吸收函数
static void sm3_absorb(
    kdf_state* self,
    const uint8_t* inp,
    size_t inlen
) {
    size_t choice = inlen >= self->len ? self->len : inlen;
    memcpy(self->buf + SM3_STATE_CNT_SIZE, inp, choice);
	self->cnt = 0;
}

static void sha_ke128_absorb(
    kdf_state* self,
    const uint8_t* inp,
    size_t inlen
) {
    keccak_absorb_once(
		(uint64_t*)(self->buf),
		KDF200_SUB_32_RATE,
		inp, inlen, 0x1F
	);
    self->cnt = KDF200_SUB_32_RATE;
}
static void sha_ke256_absorb(
    kdf_state* self,
    const uint8_t* inp,
    size_t inlen
) {
    keccak_absorb_once(
		(uint64_t*)(self->buf),
		KDF200_SUB_64_RATE,
		inp, inlen, 0x1F
	);
    self->cnt = KDF200_SUB_64_RATE;
}

/// 压缩函数
#define sm3_squeezer_blocks_gen(name, expand_scale)		\
static void sm3_##name##_squeeze_blocks(				\
    kdf_state *self,									\
    uint8_t *res,						 				\
    uint64_t nblocks									\
) {														\
	nblocks *= expand_scale;							\
    uint8_t *nonce = self->buf;							\
    uint64_t cnt = self->cnt, lena = nblocks,			\
			 st_pos = self->len+SM3_STATE_CNT_SIZE;		\
	uint8_t *rec = (uint8_t*)malloc(SM3_KDF_RATE);		\
	nblocks += SM3_KDF_RATE;							\
    while (nblocks > SM3_KDF_RATE) {					\
        for (int j = 0; j < 4; j ++) {					\
            nonce[j] = (cnt >> ((3 - j) << 3)) & 0xFF;	\
        }												\
        sm3(nonce, st_pos, rec);						\
		nblocks -= SM3_KDF_RATE;						\
		uint64_t choice = nblocks >= SM3_KDF_RATE ?		\
						  SM3_KDF_RATE : nblocks;		\
		memcpy(res+cnt*SM3_KDF_RATE, rec, choice);		\
        cnt ++;											\
    }													\
    self->cnt = cnt;									\
	free(rec);											\
}

sm3_squeezer_blocks_gen(128_sig, KDF200_SUB_32_RATE);
sm3_squeezer_blocks_gen(256_sig, KDF200_SUB_64_RATE);
#undef sm3_squeezer_blocks_gen

static void sm3_squeeze(
    kdf_state *self,
    uint8_t *res,
    uint64_t out_len
) {
    sm3_extented(
		res, out_len,
		self->buf+SM3_STATE_CNT_SIZE, self->len
	);
}

static void sha_ke128_squeeze_blocks(
    kdf_state *self,
    uint8_t *res,
    uint64_t nblocks
) {
    keccak_squeezeblocks(
		res, nblocks, (uint64_t*)(self->buf),
		KDF200_SUB_32_RATE
	);
}

static void sha_ke128_squeeze(
    kdf_state *self,
    uint8_t *res,
    uint64_t out_len
) {
    self->cnt = keccak_squeeze(
		res, out_len, (uint64_t*)(self->buf),
		self->cnt, KDF200_SUB_32_RATE
	);
}

static void sha_ke256_squeeze_blocks(
    kdf_state *self,
    uint8_t *res,
    uint64_t nblocks
) {
    keccak_squeezeblocks(
		res, nblocks, (uint64_t*)(self->buf),
		KDF200_SUB_64_RATE
	);
}

static void sha_ke256_squeeze(
    kdf_state *self,
    uint8_t *res,
    uint64_t out_len
) {
    self->cnt = keccak_squeeze(
		res, out_len, (uint64_t*)(self->buf),
		self->cnt, KDF200_SUB_64_RATE
	);
}


/// 手册内的 h 函数。（任意长字节流映射到 l 字节长的摘要）
static void sm3_256(
    uint8_t *res,
    const uint8_t *inp,
    size_t inp_len
) {
    sm3_extented(res, 32, inp, inp_len);
}

/// 手册内的 g 函数。映射到2个l字节长的摘要。
static void sm3_512(
    uint8_t *res,
    const uint8_t *inp,
    size_t inp_len
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
typedef void (*_kdf_init)(kdf_state*, size_t);
typedef void (*_kdf_alter_inp_buf) (
    kdf_state*,
    size_t /*pos*/,
    uint8_t /*val*/
);
typedef void (*_kdf_absorb) (
    kdf_state*,
    const uint8_t * /*inp*/,
    size_t /*inlen*/
);
typedef void (*_kdf_squeeze_blocks) (
    kdf_state*,
    uint8_t* /*res*/,
    uint64_t /*nblocks*/
);

typedef void (*_kdf_squeeze) (
    kdf_state*,
    uint8_t * /*res*/,
    uint64_t /* outlen */
);

typedef void (*_hash_x) (
    uint8_t *res,
    const uint8_t *inp,
    size_t inp_len
);

/// XOF
typedef void (*_kdf_xof) (
    uint8_t *res,
    size_t res_len,
    const uint8_t *inp,
    size_t inp_len
);

void kdf_destroy(kdf_state *);
extern _kdf_init				kdf_init;
extern _kdf_alter_inp_buf		kdf_alter_inp_buf;
extern _kdf_squeeze				kdf_squeeze;
extern _kdf_absorb				kdf128_absorb;
extern _kdf_squeeze_blocks		kdf128_sig_squeeze_blocks;
extern _kdf_absorb				kdf256_absorb;
extern _kdf_squeeze_blocks		kdf256_sig_squeeze_blocks;
extern _hash_x					hash_h;
extern _hash_x 					hash_g;
extern _kdf_xof					kdf_xof128;
extern _kdf_xof					kdf_xof256;

#if (AIGIS_KDF_CONF == 0)
    #define KDF128_RATE 32
    #define KDF256_RATE 32
#elif (AIGIS_KDF_CONF == 1)
    #define KDF128_RATE KDF200_SUB_32_RATE
    #define KDF256_RATE KDF200_SUB_64_RATE
#else
	#error "unsupport AIGIS_KDF_CONF! Only accept {0, 1}"
#endif // AIGIS_KDF_CONF
#endif // KDF_AUX_H
