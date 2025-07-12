/// Last modified at 2025年07月12日 星期六 13时28分49秒

#include "sm3.h"

#ifndef __KDF_H__
#define __KDF_H__

#define add_nonce(out, nonce)                   \
    do{                                         \
        out[0] = (uint8_t)(nonce >> 24) & 0xff; \
        out[1] = (uint8_t)(nonce >> 16) & 0xff; \
        out[2] = (uint8_t)(nonce >> 8) & 0xff;  \
        out[3] = (uint8_t)(nonce) & 0xff;       \
    } while(0)


/* kdf_extented.
	通过多次对已扩展的数据做sm3，以使sm3支持任意输出长度。
*/
void sm3_extented(
    uint8_t *out, 
    size_t outlen, 
    const uint8_t *in, 
    size_t inlen
) {
    uint32_t nonce = 0;
    uint8_t *in_ext = (uint8_t*)malloc(inlen + 4);
    uint8_t *res = (uint8_t*)malloc(SM3_DIGEST_SIZE);
	size_t running_outlen = outlen + SM3_DIGEST_SIZE;
    memcpy(in_ext+4, in, inlen);
    while (running_outlen > SM3_DIGEST_SIZE) {
        add_nonce(in_ext, nonce);
        sm3(in_ext, inlen + 4, res);
        running_outlen -= SM3_DIGEST_SIZE;
		size_t choice = running_outlen > SM3_DIGEST_SIZE ? 
						SM3_DIGEST_SIZE : running_outlen;
		memcpy(out+nonce*SM3_DIGEST_SIZE, res, choice);
        nonce++;
    }
    free(in_ext);
    free(res);
}
#endif // KDF_H
