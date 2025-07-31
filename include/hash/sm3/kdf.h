/// Last modified at 2025年07月31日 星期四 16时11分00秒

#include "sm3.h"

#ifndef __KDF_H__
#define __KDF_H__
/* kdf_extented.
	通过多次对已扩展的数据做sm3，以使sm3支持任意输出长度。
*/
void sm3_extented(
    uint8_t *out,
    size_t outlen,
    const uint8_t *in,
    size_t inlen
);
#endif // KDF_H
