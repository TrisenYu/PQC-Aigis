/// Last modified at 2025年07月31日 星期四 15时58分29秒
#include "aigis_pack.h"
#include "aigis_comp.h"

/// 调用此函数封装公钥
/// comp_pub := pub||seed
void enc_pack_pub(
    uint8_t res_pub[AIGIS_ENC_PUB_SIZE],
    const enc_veck raw_pub,
    const uint8_t *seed
) {
    int i = 0;
    enc_pub_compresser(res_pub, raw_pub);
    for (; i < AIGIS_SEED_SIZE; i ++) {
        res_pub[i+AIGIS_ENC_COMP_PUB_SIZE] = seed[i];
    }
}
/// 调用此函数解封公钥
void enc_unpack_pub(
    enc_veck res_pub,
    uint8_t *seed,
    const uint8_t comp_pub[AIGIS_ENC_PUB_SIZE]
) {
    int i = 0;
    for (; i < AIGIS_SEED_SIZE; i ++) {
        seed[i] = comp_pub[i + AIGIS_ENC_COMP_PUB_SIZE];
    }
    enc_pub_decompresser(res_pub, comp_pub);

}
/// 调用此函数封装私钥
void enc_pack_sec(
    uint8_t res_sec[AIGIS_ENC_SEC_SIZE],
    const enc_veck raw_sec
) {
    int i = 0;
    for (; i < AIGIS_ENC_K; i ++) {
        enc_poly2bytes(res_sec+i*AIGIS_ENC_POLY_SIZE, raw_sec[i]);
    }
}
/// 调用此函数解封私钥
void enc_unpack_sec(
    enc_veck res_sec,
    const uint8_t comp_sec[AIGIS_ENC_SEC_SIZE]
) {
    int i = 0;
    for (; i < AIGIS_ENC_K; i ++) {
        enc_bytes2poly(res_sec[i], comp_sec+i*AIGIS_ENC_POLY_SIZE);
    }

}

void enc_pack_ciphertext(
    uint8_t res[AIGIS_ENC_CFT_SIZE],
    const enc_veck cipher_vec1,
    const enc_poly cipher_poly2
) {
    enc_cft_veck_compresser(res, cipher_vec1);
    enc_cft_poly_compresser(res+AIGIS_ENC_COMP_CFT_SIZE, cipher_poly2);
}

void enc_unpack_ciphertext(
    enc_veck res_veck,
    enc_poly res_poly,
    const uint8_t comp_cipher[AIGIS_ENC_CFT_SIZE]
) {
    enc_cft_poly_decompresser(res_poly, comp_cipher+AIGIS_ENC_COMP_CFT_SIZE);
    enc_cft_veck_decompresser(res_veck, comp_cipher);
}



/// 签名算法打包函数
/*************************************************
* pack the public key pk,
* where pk = rho|t1
**************************************************/
void sig_pack_pub(
	uint8_t res_pub[AIGIS_SIG_PUB_SIZE],
	const uint8_t rho[AIGIS_SEED_SIZE],
	const sig_veck t1
) {
	int i = 0;
	for (; i < AIGIS_SEED_SIZE; i ++) {
		res_pub[i] = rho[i];
	}
	res_pub += AIGIS_SEED_SIZE;
	for (i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_t1_compresser(res_pub+i*AIGIS_SIG_POLY_T1_COMP_SIZE, t1[i]);
	}
}

void sig_unpack_pub(
	uint8_t res_rho[AIGIS_SEED_SIZE],
	sig_veck res_t1,
	const uint8_t pub[AIGIS_SIG_PUB_SIZE]
) {
	int i = 0;
	for (; i < AIGIS_SEED_SIZE; i ++) {
		res_rho[i] = pub[i];
	}
	pub += AIGIS_SEED_SIZE;
	for (i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_t1_decompresser(res_t1[i], pub + i*AIGIS_SIG_POLY_T1_COMP_SIZE);
	}
}


/*************************************************
* pack the secret key sk,
* where sk = rho|key|hash(pk)|s1|s2|t0
**************************************************/
void sig_pack_sec(
	uint8_t res_sec[AIGIS_SIG_SEC_SIZE],
	const uint8_t buf[AIGIS_SEED_SIZE*2+AIGIS_CRH_SIZE],
	const sig_vecl s1,
	const sig_veck s2,
	const sig_veck t0
) {
	int i = 0;
	for (; i < AIGIS_SEED_SIZE*2 + AIGIS_CRH_SIZE; i ++) {
		res_sec[i] = buf[i];
	}
	res_sec += AIGIS_SEED_SIZE*2 + AIGIS_CRH_SIZE;
	for (i = 0; i < AIGIS_SIG_L; i ++) {
		sig_poly_eta_s_compresser(&res_sec[i*AIGIS_SIG_POLY_ETA_S_COMP_SIZE], s1[i]);
	}
	res_sec += AIGIS_PVEC_L_ETA_S_SIZE;
	for (i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_eta_e_compresser(&res_sec[i*AIGIS_SIG_POLY_ETA_E_COMP_SIZE], s2[i]);
	}
	res_sec += AIGIS_PVEC_K_ETA_E_SIZE;
	for (i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_t0_compresser(&res_sec[i*AIGIS_SIG_POLY_T0_COMP_SIZE], t0[i]);
	}
}

void sig_unpack_sec(
	uint8_t  res_buf[AIGIS_SEED_SIZE*2+AIGIS_CRH_SIZE],
	sig_vecl res_s1,
	sig_veck res_s2,
	sig_veck res_t0,
	const uint8_t sec[AIGIS_SIG_SEC_SIZE]
) {
	int i = 0;
	for (; i < AIGIS_SEED_SIZE*2 + AIGIS_CRH_SIZE; i ++) {
		res_buf[i] = sec[i];
	}
	sec += 2*AIGIS_SEED_SIZE + AIGIS_CRH_SIZE;
	for (i = 0; i < AIGIS_SIG_L; i ++) {
		sig_poly_eta_s_decompresser(res_s1[i], &sec[i*AIGIS_SIG_POLY_ETA_S_COMP_SIZE]);
	}
	sec += AIGIS_PVEC_L_ETA_S_SIZE;
	for (i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_eta_e_decompresser(res_s2[i], &sec[i*AIGIS_SIG_POLY_ETA_E_COMP_SIZE]);
	}
	sec += AIGIS_PVEC_K_ETA_E_SIZE;
	for (i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_t0_decompresser(res_t0[i], &sec[i*AIGIS_SIG_POLY_T0_COMP_SIZE]);
	}
}

/*************************************************
* pack the signature sig,
* where sig = z|h|c
**************************************************/
void sig_pack_sig(
	uint8_t sig[AIGIS_SIG_SIG_SIZE],
	const sig_vecl z,
	const sig_veck h,
	const sig_poly c
) {
	for (int i = 0; i < AIGIS_SIG_L; i ++) {
		sig_poly_z_compresser(sig+i*AIGIS_SIG_POLY_Z_COMP_SIZE, z[i]);
	}
	sig += AIGIS_PVEC_L_Z_SIZE;
	// 编码 h
	int cnt = 0;
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		for (int j = 0; j < AIGIS_N; j ++) {
			if (h[i][j] == 1) { // TODO: 是实际等于1还是说存在就行？
				sig[cnt++] = j;
			} else {
				continue;
			}
		}
		sig[AIGIS_SIG_OMEGA+i] = cnt;
	}
	while (cnt < AIGIS_SIG_OMEGA) { sig[cnt++] = 0; }
	sig += AIGIS_SIG_OMEGA + AIGIS_SIG_K;

	// 编码 c
	uint64_t sign = 0, mask = 1;
	for(int i = 0; i < AIGIS_N >> 3; ++i) {
    	sig[i] = 0;
    	for(int j = 0; j < 8; ++j) {
      		if(!c[8*i+j]) { continue; }
			sig[i] |= (1 << j);
			if(c[8*i+j] == (AIGIS_SIG_MOD_Q - 1)) {
				sign |= mask;
			}
			mask <<= 1;
    	}
  	}
	sig += AIGIS_N >> 3;
  	for(int i = 0; i < 8; ++i) {
    	sig[i] = sign >> (i<<3);
	}
}

int sig_unpack_sig(
	sig_vecl res_z,
	sig_veck res_h,
	sig_poly res_c,
	const uint8_t sig[AIGIS_SIG_SIG_SIZE]
) {
	for (int i = 0; i < AIGIS_SIG_L; i ++) {
		sig_poly_z_decompresser(res_z[i], sig+i*AIGIS_SIG_POLY_Z_COMP_SIZE);
	}
	sig += AIGIS_PVEC_L_Z_SIZE;

	// 这个解码有点绕
	uint32_t cnt = 0;
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		for (int j = 0; j < AIGIS_N; j ++) {
			res_h[i][j] = 0;
		}
		uint32_t tmp = sig[AIGIS_SIG_OMEGA+i];
		if (tmp < cnt || tmp > AIGIS_SIG_OMEGA) {
			return 1;
		}
		for (int j = cnt; j < tmp; j ++) {
			if (j > cnt && sig[j] <= sig[j-1]) {
				return 1;
			}
			res_h[i][sig[j]] = 1;
		}
		cnt = tmp;
	}
	for (int i = cnt; i < AIGIS_SIG_OMEGA; i ++) {
		if (sig[i]) {
			return 1;
		}
	}
	sig += AIGIS_SIG_OMEGA + AIGIS_SIG_K;

	for (int i = 0; i < AIGIS_N; i ++) {
		res_c[i] = 0;
	}
	uint64_t sign = 0, mask = 1;
	for (int i = 0; i < 8; i ++) {
		sign |= (uint64_t)sig[(AIGIS_N>>3)+i] << (i << 3);
	}
	for (int i = 0; i < AIGIS_N>>3; i ++) {
		for (int j = 0; j < 8; j ++) {
			if ((sig[i] >> j) & 0x01) {
				res_c[8*i+j] = (sign & mask) ? AIGIS_SIG_MOD_Q - 1 : 1;
				mask <<= 1;
			}
		}
	}
	return 0;
}
