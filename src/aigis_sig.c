/// Last modified at 2025年08月01日 星期五 00时11分29秒
#include "aigis_comp.h"
#include "aigis_sig.h"
#include "aigis_pack.h"

// #define __DEBUG
#ifdef __DEBUG
#include "debug.h"
#endif //DEBUG

void sig_challenge(
	sig_poly ch,
	const uint8_t mu[AIGIS_CRH_SIZE],
	const sig_veck w1
) {
	uint8_t *inp_buf = (uint8_t*)calloc(AIGIS_CRH_SIZE+AIGIS_PVEC_K_W1_SIZE+1, 1);
	uint8_t *out_buf = (uint8_t*)calloc(AIGIS_SIG_KDF256_RATE, 1);
	uint64_t sign = 0, mask = 1;

	memcpy(inp_buf, mu, AIGIS_CRH_SIZE);
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_w1_compresser(
			inp_buf+AIGIS_CRH_SIZE+i*AIGIS_SIG_POLY_W1_COMP_SIZE,
			w1[i]
		);
	}

	/// TODO: KDF
	kdf_state state;
	kdf_init(&state, AIGIS_CRH_SIZE+AIGIS_PVEC_K_W1_SIZE+1);
	kdf256_absorb(&state, inp_buf, AIGIS_CRH_SIZE+AIGIS_PVEC_K_W1_SIZE+1);
	kdf256_sig_squeeze_blocks(&state, out_buf, 1);

	for (int i = 0; i < 8; i ++) {
		sign |= (uint64_t)out_buf[i] << 8*i;
	}
	for (int i = 0; i < AIGIS_N; i ++) {
		ch[i] = 0;
	}
	uint32_t pos = 8, b = 0;
	for (int i = 196; i < AIGIS_N; i ++) {
		do {
			if (pos >= AIGIS_SIG_KDF256_RATE) {
				/// TODO: KDF
				kdf256_sig_squeeze_blocks(&state, out_buf, 1);
				pos = 0;
			}
			b = out_buf[pos++];
		} while (b > i);
		ch[i] = ch[b];
		ch[b] = (sign & mask) ? AIGIS_SIG_MOD_Q - 1 : 1;
		mask <<= 1;
	}
	kdf_destroy(&state);
	free(inp_buf);
	free(out_buf);
}


int sig_inner_keypair(
	uint8_t *res_pub,
	uint8_t *res_sec,
	uint8_t *coins
) {
	uint16_t nonce = 0;
	uint8_t buf[AIGIS_SEED_SIZE*3+AIGIS_CRH_SIZE]={0};
	sig_vecl *s1		= (sig_vecl*)calloc(1, sizeof(sig_vecl)),
			 *s1_hat	= (sig_vecl*)calloc(1, sizeof(sig_vecl));
	sig_veck *s2		= (sig_veck*)calloc(1, sizeof(sig_veck)),
			 *t1 		= (sig_veck*)calloc(1, sizeof(sig_veck)),
			 *t0 		= (sig_veck*)calloc(1, sizeof(sig_veck));
	sig_matr_kl *mat	= (sig_matr_kl*)calloc(1, sizeof(sig_matr_kl));

	/// TODO: XOF256
	kdf_xof256(buf, 3*AIGIS_SEED_SIZE, coins, AIGIS_SEED_SIZE);
	sig_expand_mat(*mat, &buf[AIGIS_SEED_SIZE]);
#ifdef __DEBUG
	// puts("xof256-buf");
	// dump_u8arr(buf, AIGIS_SEED_SIZE*3+AIGIS_CRH_SIZE);
	// puts("mat");
	// dump_sig_poly((*mat)[1][1]);
#endif //DEBUG

	for (int i = 0; i < AIGIS_SIG_L; i ++) {
		sig_poly_eta_s_uniform((*s1)[i], buf, nonce++);
		for (int j = 0; j < AIGIS_N; j ++) {
			(*s1_hat)[i][j] = (*s1)[i][j];
		}
		sig_ntt((*s1_hat)[i]);
	}
	for (int i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_eta_e_uniform((*s2)[i], buf, nonce++);
	}

	sig_matr_kl_ntt_act(*t0, *mat, *s1_hat);
	sig_veck_add(*t0, *t0, *s2);

	sig_veck_try_shrink(*t0, sig_try_shrink2);
	sig_veck_pow2round(*t0, *t1);
	sig_pack_pub(res_pub, &buf[AIGIS_SEED_SIZE], *t1);
	/// TODO: XOF256
	kdf_xof256(
		buf+3*AIGIS_SEED_SIZE, AIGIS_CRH_SIZE,
		res_pub, AIGIS_SIG_PUB_SIZE
	);
	sig_pack_sec(res_sec, &buf[AIGIS_SEED_SIZE], *s1, *s2, *t0);

	free(s1);
	free(s1_hat);
	free(s2);
	free(t1);
	free(t0);
	free(mat);
	return 0;
}

/*************************************************
* Name:		crypto_sign_keypair_internal
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pub: pointer to output public key (allocated
*							 array of CRYPTO_PUBLICKEYBYTES bytes)
*			  - uint8_t *sec: pointer to output private key (allocated
*							 array of CRYPTO_SECRETKEYBYTES bytes)
*			  - const uint8_t *coins: pointer to random message
*							 (of length AIGIS_SEED_SIZE bytes)
* Returns 0 (success)
* generate a pair of public key pub and secret key sec,
* where pub = rho|t1
*	   sec = rho|key|hash(pub)|s1|s2|t0
**************************************************/
int sig_keypair(
	uint8_t *res_pub,
	uint8_t *res_sec
) {
	uint8_t coins[AIGIS_SEED_SIZE] = {0};
  	randombytes(coins, AIGIS_SEED_SIZE);
	return sig_inner_keypair(res_pub, res_sec, coins);
}

/// TODO: 写注释，理解清楚签名函数的步骤

/*************************************************
* Name:		crypto_sign_signature_internal
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig: pointer to output signature
*			  - size_t *sig_len: pointer to output length of signature
*			  - uint8_t *m:	 pointer to message to be signed
*			  - size_t msg_len:	length of message
*			  - uint8_t *sec:	pointer to bit-packed secret key
*
* Returns 0 (success), -1 (context string too long error)
**************************************************/
/*************************************************
* create a signature sig_msg on message m, where
* sig_msg = z|h|c
**************************************************/
int crypto_sign_signature_internal(
	uint8_t *sig,
	size_t *sig_len,
	const uint8_t *msg,
	size_t msg_len,
	const uint8_t *sec
) {
	size_t i, j;
	uint32_t n;
	uint8_t *buf;
	uint16_t nonce = 0;
	sig_poly	*c		= (sig_poly*)calloc(1, sizeof(sig_poly)),
				*chat	= (sig_poly*)calloc(1, sizeof(sig_poly));
	sig_matr_kl *mat  	= (sig_matr_kl*)calloc(1, sizeof(sig_matr_kl));
	sig_vecl	*s1		= (sig_vecl*)calloc(1, sizeof(sig_vecl)),
				*y		= (sig_vecl*)calloc(1, sizeof(sig_vecl)),
				*yhat	= (sig_vecl*)calloc(1, sizeof(sig_vecl)),
				*z		= (sig_vecl*)calloc(1, sizeof(sig_vecl));
	sig_veck	*s2		= (sig_veck*)calloc(1, sizeof(sig_veck)),
				*t0		= (sig_veck*)calloc(1, sizeof(sig_veck)),
				*w		= (sig_veck*)calloc(1, sizeof(sig_veck)),
				*w1		= (sig_veck*)calloc(1, sizeof(sig_veck)),
				*h		= (sig_veck*)calloc(1, sizeof(sig_veck)),
				*wcs2	= (sig_veck*)calloc(1, sizeof(sig_veck)),
				*wcs20	= (sig_veck*)calloc(1, sizeof(sig_veck)),
				*ct0	= (sig_veck*)calloc(1, sizeof(sig_veck)),
				*tmp	= (sig_veck*)calloc(1, sizeof(sig_veck));

  	buf = (uint8_t*)calloc(2*AIGIS_SEED_SIZE + AIGIS_CRH_SIZE + msg_len, 1);
	sig_unpack_sec(buf, *s1, *s2, *t0, sec);

	for(i=0;i<msg_len;i++) {
		buf[2*AIGIS_SEED_SIZE + AIGIS_CRH_SIZE + i] = msg[i];
	}

	/// TODO: KDF256
	kdf_xof256(
		buf+AIGIS_SEED_SIZE*2,
		AIGIS_CRH_SIZE,
		buf+AIGIS_SEED_SIZE*2,
		AIGIS_CRH_SIZE+msg_len
	);

	sig_expand_mat(*mat, buf);
	sig_vecl_ntt(*s1);
	sig_veck_ntt(*s2);
	sig_veck_ntt(*t0);

st_resamp:
	for(i = 0; i < AIGIS_SIG_L; ++i) {
		sig_poly_gamma1_m1_uniform(
			(*y)[i], &buf[AIGIS_SEED_SIZE],
			nonce
		);
		nonce ++;
	}
	for (i = 0; i < AIGIS_SIG_L; i ++) {
		for (j = 0; j < AIGIS_N; j ++) {
			(*yhat)[i][j] = (*y)[i][j];
		}
	}
	sig_vecl_ntt(*yhat);
	sig_matr_kl_ntt_act(*w, *mat, *yhat);
	sig_veck_try_shrink(*w, sig_try_shrink);
	sig_veck_decomp(*tmp, *w1, *w);
	sig_challenge(*c, &buf[AIGIS_SEED_SIZE<<1], *w1);
	for (j = 0; j < AIGIS_N; j ++) {
		(*chat)[j] = (*c)[j];
	}
	sig_ntt(*chat);
	int res = 0;
	for (i = 0; i < AIGIS_SIG_L; i ++) {
		sig_poly_dot_mul((*z)[i], *chat, (*s1)[i]);
		sig_inv_ntt((*z)[i]);
		sig_poly_add((*z)[i], (*z)[i], (*y)[i]);
		sig_poly_shrink((*z)[i], sig_try_shrink2);
		res |= sig_poly_check_norm(
			(*z)[i], AIGIS_SIG_GAMMA1 - AIGIS_SIG_BETA1
		);
	}
	if (res) {
		goto st_resamp;
	}

	for (i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_dot_mul((*wcs2)[i], *chat, (*s2)[i]);
		sig_inv_ntt((*wcs2)[i]);
		sig_poly_sub((*wcs2)[i], (*w)[i], (*wcs2)[i]);
		sig_poly_shrink((*wcs2)[i], sig_try_shrink2);
		sig_poly_decomp((*wcs20)[i], (*tmp)[i], (*wcs2)[i]);
		sig_poly_shrink((*wcs20)[i], sig_try_shrink);
		res |= sig_poly_check_norm((*wcs20)[i], AIGIS_SIG_GAMMA2 - AIGIS_SIG_BETA2);
		for (j = 0; j < AIGIS_N; j ++) {
			res |= (*tmp)[i][j] != (*w1)[i][j];
		}
	}
	if (res) {
		goto st_resamp;
	}
	for (i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_dot_mul((*ct0)[i], *chat, (*t0)[i]);
		sig_inv_ntt((*ct0)[i]);
		sig_poly_shrink((*ct0)[i], sig_try_shrink);
		res |= sig_poly_check_norm((*ct0)[i], AIGIS_SIG_GAMMA2);
	}
	if (res) {
		goto st_resamp;
	}
	for (i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_add((*tmp)[i], (*wcs2)[i], (*ct0)[i]);
		sig_poly_neg((*ct0)[i]);
		sig_poly_shrink((*tmp)[i], sig_try_shrink);
	}
	n = sig_veck_make_hint(*h, *tmp, *ct0);
	if (n > AIGIS_SIG_OMEGA) {
		goto st_resamp;
	}
	sig_pack_sig(sig, *z, *h, *c);
	*sig_len = AIGIS_SIG_SIG_SIZE;

	free(buf);
	free(c);
	free(chat);
	free(mat);
	free(s1);
	free(y);
	free(yhat);
	free(z);
	free(s2);
	free(t0);
	free(w);
	free(w1);
	free(h);
	free(wcs2);
	free(wcs20);
	free(ct0);
	free(tmp);
	return 0;
}

/*************************************************
* Name:		crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature
*			  - size_t *sig_len: pointer to output length of signature
*			  - uint8_t *m:	 pointer to message to be signed
*			  - size_t msg_len:	length of message
*			  - uint8_t *ctx:   pointer to ctx string
*			  - size_t ctx_len: length of ctx string
*			  - uint8_t *sec:	pointer to bit-packed secret key
*
* Returns 0 (success), -1 (context string too long error)
**************************************************/
int crypto_sign_signature(
	uint8_t *sig,
	size_t *sig_len,
	const uint8_t *m,
	size_t msg_len,
	const uint8_t *ctx,
	size_t ctx_len,
	const uint8_t *sec
) {

	if(ctx_len > 255) {
		return -1;
	}

	uint8_t *m_extended = (uint8_t*)malloc(msg_len + ctx_len + 2);


	m_extended[0] = 0;
	m_extended[1] = (uint8_t)ctx_len;
	if (ctx) {
		memcpy(m_extended + 2, ctx, ctx_len);
	}
	memcpy(m_extended + 2 + ctx_len, m, msg_len);

	int ret = crypto_sign_signature_internal(
		sig, sig_len, m_extended,
		msg_len + ctx_len + 2, sec
	);
	free(m_extended);
	return ret;
}

/*************************************************
* Name:		crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sig_msg: pointer to output signed message (allocated
*							 array with AIGIS_SIG_SIG_SIZE + msg_len bytes),
*							 can be equal to m
*			  - size_t *sig_msgsg_len: pointer to output length of signed
*							   message
*			  - uint8_t *m: pointer to message to be signed
*			  - size_t msg_len: length of message
*			  - uint8_t *ctx:   pointer to ctx string
*			  - size_t ctx_len: length of ctx string
*			  - uint8_t *sec: pointer to bit-packed secret key
*
* Returns 0 (success), -1 (context string too long error)
**************************************************/
int crypto_sign(
	uint8_t *sig_msg,
	size_t *smsg_len,
	const uint8_t *m,
	size_t msg_len,
	const uint8_t *ctx,
	size_t ctx_len,
	const uint8_t *sec
) {
	size_t i;

	for(i = 0; i < msg_len; ++i) {
		sig_msg[AIGIS_SIG_SIG_SIZE + msg_len - 1 - i] = m[msg_len - 1 - i];
	}
	int ret = crypto_sign_signature(
		sig_msg, smsg_len,
		sig_msg + AIGIS_SIG_SIG_SIZE,
		msg_len, ctx, ctx_len, sec
	);
	*smsg_len += msg_len;
  	return ret;
}

/*************************************************
* Name:		crypto_sign_verify_internal
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*			  - size_t sig_len: length of signature
*			  - const uint8_t *m: pointer to message
*			  - size_t msg_len: length of message
*			  - const uint8_t *pub: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify_internal(
  const uint8_t *sig, size_t sig_len,
  const uint8_t *msg, size_t msg_len,
  const uint8_t *pub
) {
	size_t i;
	uint8_t rho[AIGIS_SEED_SIZE] = {0};
	uint8_t *buf;
	sig_poly	*c		= (sig_poly*)malloc(sizeof(sig_poly)),
				*chat	= (sig_poly*)malloc(sizeof(sig_poly)),
				*cp		= (sig_poly*)malloc(sizeof(sig_poly));
	sig_vecl	*z		= (sig_vecl*)malloc(sizeof(sig_vecl));
	sig_matr_kl *mat	= (sig_matr_kl*)malloc(sizeof(sig_matr_kl));
	sig_veck	*t1		= (sig_veck*)malloc(sizeof(sig_veck)),
				*w1 	= (sig_veck*)malloc(sizeof(sig_veck)),
				*h  	= (sig_veck*)malloc(sizeof(sig_veck)),
				*tmp1	= (sig_veck*)malloc(sizeof(sig_veck)),
				*tmp2 	= (sig_veck*)malloc(sizeof(sig_veck));
	buf = (uint8_t*)calloc(AIGIS_CRH_SIZE + msg_len, 1);
	int ret = 0;

	if (sig_len < AIGIS_SIG_SIG_SIZE) {
		ret = -1;
		goto end;
	}
	sig_unpack_pub(rho, *t1, pub);
	if (sig_unpack_sig(*z, *h, *c, sig)) {
		ret = -1;
		goto end;
	}
	for (i = 0; i < AIGIS_SIG_L; i ++) {
		ret |= sig_poly_check_norm((*z)[i], AIGIS_SIG_GAMMA1 - AIGIS_SIG_BETA1);
	}
	if (ret){
		ret = -1;
		goto end;
	}
	for(i=0;i<msg_len;i++){
		buf[AIGIS_CRH_SIZE + i] = msg[i];
	}

	/// TODO: xof256
	kdf_xof256(buf, AIGIS_CRH_SIZE, pub, AIGIS_SIG_PUB_SIZE);
	kdf_xof256(buf, AIGIS_CRH_SIZE, buf, AIGIS_CRH_SIZE + msg_len);

	sig_expand_mat(*mat, rho);
	sig_vecl_ntt(*z);
	for (i = 0; i < AIGIS_SIG_K; i ++) {
		sig_inner_mul_vecl((*tmp1)[i], (*mat)[i], *z);
	}
	for (i = 0; i < AIGIS_N; i ++) {
		(*chat)[i] = (*c)[i];
	}
	sig_ntt(*chat);
	sig_veck_lsh(*t1, AIGIS_SIG_D);

	sig_veck_ntt(*t1);
	for (i = 0; i < AIGIS_SIG_K; i ++) {
		sig_poly_dot_mul((*tmp2)[i], *chat, (*t1)[i]);
	}

	sig_veck_sub(*tmp1, *tmp1, *tmp2); // output coefficient  <=4*Q
	sig_veck_inv_ntt(*tmp1);

	sig_veck_try_shrink(*tmp1, sig_try_shrink);
	sig_veck_use_hint(*w1, *tmp1, *h);
	sig_challenge(*cp, buf, *w1);
	for (i = 0; i < AIGIS_N; i ++) {
		if ((*c)[i] ^ (*cp)[i]) {
			ret = -1;
			break;
		}
	}
end:
	free(buf);
	free(c);
	free(chat);
	free(cp);
	free(z);
	free(mat);
	free(t1);
	free(w1);
	free(h);
	free(tmp1);
	free(tmp2);
	return ret;
}

/*************************************************
* Name:		crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*			  - size_t sig_len: length of signature
*			  - const uint8_t *m: pointer to message
*			  - size_t msg_len: length of message
*			  - uint8_t *ctx:   pointer to ctx string
*			  - size_t ctx_len: length of ctx string
*			  - const uint8_t *pub: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify(
	const uint8_t *sig,
	size_t sig_len,
	const uint8_t *m,
	size_t msg_len,
	const uint8_t *ctx,
	size_t ctx_len,
	const uint8_t *pub
) {

	if (ctx_len > 255) {
		return -1;
	}

	uint8_t *m_extended = (uint8_t*)malloc(msg_len + ctx_len + 2);

	m_extended[0] = 0;
	m_extended[1] = (uint8_t)ctx_len;
	if (ctx) {
		memcpy(m_extended + 2, ctx, ctx_len);
	}
	memcpy(m_extended + 2 + ctx_len, m, msg_len);

	int ret = 0;
	ret = crypto_sign_verify_internal(
		sig, sig_len, m_extended,
		msg_len + ctx_len + 2, pub
	);
	free(m_extended);
	return ret;
}

/*************************************************
* Name:		crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*							array with smsg_len bytes), can be equal to sig_msg
*			  - size_t *msg_len: pointer to output length of message
*			  - const uint8_t *sig_msg: pointer to signed message
*			  - size_t smsg_len: length of signed message
*			  - uint8_t *ctx:   pointer to ctx string
*			  - size_t ctx_len: length of ctx string
*			  - const uint8_t *pub: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_open(
	uint8_t *msg,
	size_t *msg_len,
	const uint8_t *sig_msg,
	size_t smsg_len,
	const uint8_t *ctx,
	size_t ctx_len,
	const uint8_t *pub
) {

#define clean_msg								\
	do { 										\
		*msg_len = -1;							\
		for (int i = 0; i < smsg_len; ++i) {	\
			msg[i] = 0;							\
		}										\
	} while(0)

	if (smsg_len < AIGIS_SIG_SIG_SIZE) {
		clean_msg;
		return -1;
	}
  	*msg_len = smsg_len - AIGIS_SIG_SIG_SIZE;
	int ret = 0;
	ret = crypto_sign_verify(
		sig_msg, AIGIS_SIG_SIG_SIZE,
		sig_msg + AIGIS_SIG_SIG_SIZE,
		*msg_len, ctx, ctx_len, pub
	);
  	if (ret) {
		clean_msg;
		return -1;
	}
#undef clean_msg

	/* All good, copy msg, return 0 */
	for (int i = 0; i < *msg_len; ++i) {
		msg[i] = sig_msg[AIGIS_SIG_SIG_SIZE + i];
	}
	return 0;
}
