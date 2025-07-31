/// Last modified at 2025年07月31日 星期四 16时12分55秒
/// 烦的就是满天乱飞的宏定义。
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef __SM3_H__
#define __SM3_H__

#define     SM3_BLOCK_SIZE      64
#define     SM3_DIGEST_SIZE     32
#define 	SM3_KDF_RATE		32
#define     SM3_STATE_WORDS     8


typedef struct {
    uint32_t digest[SM3_STATE_WORDS];
    uint64_t nblocks;
    uint8_t  block[SM3_BLOCK_SIZE];
    size_t   num;
} SM3_CTX;


static uint32_t K[64] = {
	0x79cc4519U, 0xf3988a32U, 0xe7311465U, 0xce6228cbU,
	0x9cc45197U, 0x3988a32fU, 0x7311465eU, 0xe6228cbcU,
	0xcc451979U, 0x988a32f3U, 0x311465e7U, 0x6228cbceU,
	0xc451979cU, 0x88a32f39U, 0x11465e73U, 0x228cbce6U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
	0x7a879d8aU, 0xf50f3b14U, 0xea1e7629U, 0xd43cec53U,
	0xa879d8a7U, 0x50f3b14fU, 0xa1e7629eU, 0x43cec53dU,
	0x879d8a7aU, 0x0f3b14f5U, 0x1e7629eaU, 0x3cec53d4U,
	0x79d8a7a8U, 0xf3b14f50U, 0xe7629ea1U, 0xcec53d43U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
};

void sm3_compress_blocks(uint32_t digest[8], const uint8_t *data, size_t blocks);
void sm3_init(SM3_CTX *ctx);
void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t data_len);
void sm3_finish(SM3_CTX *ctx, uint8_t *digest);
size_t sm3(const uint8_t *data, size_t datalen, uint8_t *dgst);
#endif // SM3_H
