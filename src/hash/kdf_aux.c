/// SPDX-LICENSE-IDENTIFIER: GPL2.0
///
/// (C) All rights reserved. Author: <kisfg@hotmail.com> in 2025
/// Created at 2025年07月31日 星期四 16时27分29秒
/// Last modified at 2025/09/06 星期六 00:27:56
#include "hash/kdf_aux.h"
#if (AIGIS_KDF_CONF == 0)
    _kdf_init				kdf_init			=		init_sm3;
    _kdf_alter_inp_buf		kdf_alter_inp_buf	= 		sm3_alter_inp_buf;
	_kdf_squeeze			kdf_squeeze			= 		sm3_squeeze;

    _kdf_absorb				kdf128_absorb		=		sm3_absorb;
    _kdf_squeeze_blocks 	kdf128_sig_squeeze_blocks = sm3_128_sig_squeeze_blocks;

    _kdf_absorb				kdf256_absorb		=		sm3_absorb;
    _kdf_squeeze_blocks 	kdf256_sig_squeeze_blocks = sm3_256_sig_squeeze_blocks;

    _hash_x hash_h = sm3_256;
    _hash_x hash_g = sm3_512;

    _kdf_xof kdf_xof128 = sm3_extented;
    _kdf_xof kdf_xof256 = sm3_extented;

#elif (AIGIS_KDF_CONF == 1)
    _kdf_init				kdf_init = init_sha_ke;
    _kdf_alter_inp_buf		kdf_alter_inp_buf	=		NULL;
    _kdf_squeeze			kdf_squeeze			=		sha_ke128_squeeze;

    _kdf_absorb				kdf128_absorb		= 		sha_ke128_absorb;
    _kdf_squeeze_blocks		kdf128_sig_squeeze_blocks = sha_ke128_squeeze_blocks;

    _kdf_absorb				kdf256_absorb		= 		sha_ke256_absorb;
    _kdf_squeeze_blocks 	kdf256_sig_squeeze_blocks = sha_ke256_squeeze_blocks;

    _hash_x hash_h = sha3_256;
    _hash_x hash_g = sha3_512;

    _kdf_xof kdf_xof128 = shake128;
    _kdf_xof kdf_xof256 = shake256;
#endif // check for AIGIS_KDF_CONF
void kdf_destroy(kdf_state* a) {
    free(a->buf);
    a->buf = NULL;
    a->cnt = a->len = 0;
}
