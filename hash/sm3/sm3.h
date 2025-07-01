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

#define GETU16(p) 			  ( \
	 (uint16_t)(p)[0] <<  8 |   \
	 (uint16_t)(p)[1]		    \
)

#define GETU32(p) \
	((uint32_t)(p)[0] << 24 |   \
	 (uint32_t)(p)[1] << 16 |   \
	 (uint32_t)(p)[2] <<  8 |   \
	 (uint32_t)(p)[3])

#define GETU64(p) \
	((uint64_t)(p)[0] << 56 |   \
	 (uint64_t)(p)[1] << 48 |   \
	 (uint64_t)(p)[2] << 40 |   \
	 (uint64_t)(p)[3] << 32 |   \
	 (uint64_t)(p)[4] << 24 |   \
	 (uint64_t)(p)[5] << 16 |   \
	 (uint64_t)(p)[6] <<  8 |   \
	 (uint64_t)(p)[7])


// WARNING: must not write PUTU32(buf, val++)
#define PUTU16(p,V) \
	((p)[0] = (uint8_t)((V) >> 8), \
	 (p)[1] = (uint8_t)(V))

#define PUTU32(p,V) \
	((p)[0] = (uint8_t)((V) >> 24), \
	 (p)[1] = (uint8_t)((V) >> 16), \
	 (p)[2] = (uint8_t)((V) >>  8), \
	 (p)[3] = (uint8_t)(V))

#define PUTU64(p,V) \
	((p)[0] = (uint8_t)((V) >> 56), \
	 (p)[1] = (uint8_t)((V) >> 48), \
	 (p)[2] = (uint8_t)((V) >> 40), \
	 (p)[3] = (uint8_t)((V) >> 32), \
	 (p)[4] = (uint8_t)((V) >> 24), \
	 (p)[5] = (uint8_t)((V) >> 16), \
	 (p)[6] = (uint8_t)((V) >>  8), \
	 (p)[7] = (uint8_t)(V))

/* Little Endian R/W */

#define GETU16_LE(p)	(*(const uint16_t *)(p))
#define GETU32_LE(p)	(*(const uint32_t *)(p))
#define GETU64_LE(p)	(*(const uint64_t *)(p))

#define PUTU16_LE(p,V)	*(uint16_t *)(p) = (V)
#define PUTU32_LE(p,V)	*(uint32_t *)(p) = (V)
#define PUTU64_LE(p,V)	*(uint64_t *)(p) = (V)


/// bit-rotation functions
#define ROL32(a,n)      (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))
#define ROL64(a,n)	    (((a)<<(n))|((a)>>(64-(n))))

#define ROR32(a,n)	    ROL32((a),32-(n))
#define ROR64(a,n)	    ROL64(a,64-n)

/// boolean functions
#define P0(x)           ((x) ^ ROL32((x), 9) ^ ROL32((x),17))
#define P1(x)           ((x) ^ ROL32((x),15) ^ ROL32((x),23))

#define FF00(x,y,z)     ((x) ^ (y) ^ (z))
#define FF16(x,y,z)     (((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define GG00(x,y,z)     ((x) ^ (y) ^ (z))
#define GG16(x,y,z)     ((((y)^(z)) & (x)) ^ (z))

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

void sm3_compress_blocks(uint32_t digest[8], const uint8_t *data, size_t blocks) {
	uint32_t A, B, C, D, E, F, G, H, W[68];
	uint32_t SS0, SS1, SS2;
	int j;
#define SM3_ROUND_0(j,A,B,C,D,E,F,G,H)			    \
	SS0 = ROL32(A, 12);				                \
	SS1 = ROL32(SS0 + E + K[j], 7);			        \
	SS2 = SS1 ^ SS0;				                \
	D += FF00(A, B, C) + SS2 + (W[j] ^ W[j + 4]);	\
	SS1 += GG00(E, F, G) + H + W[j];		        \
	B = ROL32(B, 9);				                \
	H = P0(SS1);					                \
	F = ROL32(F, 19);				                \
	W[j+16] = P1(W[j] ^ W[j+7] ^ ROL32(W[j+13], 15)) ^ ROL32(W[j+3], 7) ^ W[j+10];

#define SM3_ROUND_1(j,A,B,C,D,E,F,G,H)			    \
	SS0 = ROL32(A, 12);				                \
	SS1 = ROL32(SS0 + E + K[j], 7);			        \
	SS2 = SS1 ^ SS0;				                \
	D += FF16(A, B, C) + SS2 + (W[j] ^ W[j + 4]);	\
	SS1 += GG16(E, F, G) + H + W[j];		        \
	B = ROL32(B, 9);					            \
	H = P0(SS1);					                \
	F = ROL32(F, 19);				                \
	W[j+16] = P1(W[j] ^ W[j+7] ^ ROL32(W[j+13], 15)) ^ ROL32(W[j+3], 7) ^ W[j+10];


#define SM3_ROUND_2(j,A,B,C,D,E,F,G,H)			    \
	SS0 = ROL32(A, 12);				                \
	SS1 = ROL32(SS0 + E + K[j], 7);			        \
	SS2 = SS1 ^ SS0;				                \
	D += FF16(A, B, C) + SS2 + (W[j] ^ W[j + 4]);	\
	SS1 += GG16(E, F, G) + H + W[j];		        \
	B = ROL32(B, 9);				                \
	H = P0(SS1);					                \
	F = ROL32(F, 19);

	while (blocks--) {

		A = digest[0];
		B = digest[1];
		C = digest[2];
		D = digest[3];
		E = digest[4];
		F = digest[5];
		G = digest[6];
		H = digest[7];

		for (j = 0; j < 16; j++) {
			W[j] = GETU32(data + j*4);
		}

		SM3_ROUND_0( 0, A,B,C,D, E,F,G,H);
		SM3_ROUND_0( 1, D,A,B,C, H,E,F,G);
		SM3_ROUND_0( 2, C,D,A,B, G,H,E,F);
		SM3_ROUND_0( 3, B,C,D,A, F,G,H,E);
		SM3_ROUND_0( 4, A,B,C,D, E,F,G,H);
		SM3_ROUND_0( 5, D,A,B,C, H,E,F,G);
		SM3_ROUND_0( 6, C,D,A,B, G,H,E,F);
		SM3_ROUND_0( 7, B,C,D,A, F,G,H,E);
		SM3_ROUND_0( 8, A,B,C,D, E,F,G,H);
		SM3_ROUND_0( 9, D,A,B,C, H,E,F,G);
		SM3_ROUND_0(10, C,D,A,B, G,H,E,F);
		SM3_ROUND_0(11, B,C,D,A, F,G,H,E);
		SM3_ROUND_0(12, A,B,C,D, E,F,G,H);
		SM3_ROUND_0(13, D,A,B,C, H,E,F,G);
		SM3_ROUND_0(14, C,D,A,B, G,H,E,F);
		SM3_ROUND_0(15, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(16, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(17, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(18, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(19, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(20, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(21, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(22, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(23, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(24, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(25, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(26, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(27, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(28, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(29, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(30, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(31, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(32, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(33, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(34, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(35, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(36, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(37, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(38, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(39, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(40, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(41, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(42, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(43, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(44, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(45, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(46, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(47, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(48, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(49, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(50, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(51, B,C,D,A, F,G,H,E);
		SM3_ROUND_2(52, A,B,C,D, E,F,G,H);
		SM3_ROUND_2(53, D,A,B,C, H,E,F,G);
		SM3_ROUND_2(54, C,D,A,B, G,H,E,F);
		SM3_ROUND_2(55, B,C,D,A, F,G,H,E);
		SM3_ROUND_2(56, A,B,C,D, E,F,G,H);
		SM3_ROUND_2(57, D,A,B,C, H,E,F,G);
		SM3_ROUND_2(58, C,D,A,B, G,H,E,F);
		SM3_ROUND_2(59, B,C,D,A, F,G,H,E);
		SM3_ROUND_2(60, A,B,C,D, E,F,G,H);
		SM3_ROUND_2(61, D,A,B,C, H,E,F,G);
		SM3_ROUND_2(62, C,D,A,B, G,H,E,F);
		SM3_ROUND_2(63, B,C,D,A, F,G,H,E);

		digest[0] ^= A;
		digest[1] ^= B;
		digest[2] ^= C;
		digest[3] ^= D;
		digest[4] ^= E;
		digest[5] ^= F;
		digest[6] ^= G;
		digest[7] ^= H;

		data += 64;
	}
}


/// 初始化 sm3 的向量
void sm3_init(SM3_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;
}

void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t data_len) {
	size_t blocks;

	ctx->num &= 0x3f;
	if (ctx->num) {
		size_t left = SM3_BLOCK_SIZE - ctx->num;
		if (data_len < left) {
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			sm3_compress_blocks(ctx->digest, ctx->block, 1);
			ctx->nblocks++;
			data += left;
			data_len -= left;
		}
	}

	blocks = data_len / SM3_BLOCK_SIZE;
	if (blocks) {
		sm3_compress_blocks(ctx->digest, data, blocks);
		ctx->nblocks += blocks;
		data += SM3_BLOCK_SIZE * blocks;
		data_len -= SM3_BLOCK_SIZE * blocks;
	}

	ctx->num = data_len;
	if (data_len) {
		memcpy(ctx->block, data, data_len);
	}
}

void sm3_finish(SM3_CTX *ctx, uint8_t *digest) {
	int i;

	ctx->num &= 0x3f;
	ctx->block[ctx->num] = 0x80;

	if (ctx->num <= SM3_BLOCK_SIZE - 9) {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		sm3_compress_blocks(ctx->digest, ctx->block, 1);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	PUTU32(ctx->block + 56, ctx->nblocks >> 23);
	PUTU32(ctx->block + 60, (ctx->nblocks << 9) + (ctx->num << 3));
	sm3_compress_blocks(ctx->digest, ctx->block, 1);

	for (i = 0; i < 8; i++) {
		PUTU32(digest + i*4, ctx->digest[i]);
	}
}

size_t sm3(const uint8_t *data, size_t datalen, uint8_t *dgst) {
	SM3_CTX ctx;

	sm3_init(&ctx);
	sm3_update(&ctx, data, datalen);
	sm3_finish(&ctx, dgst);

	memset(&ctx, 0, sizeof(SM3_CTX));
	return SM3_DIGEST_SIZE;
}

#endif // SM3_H