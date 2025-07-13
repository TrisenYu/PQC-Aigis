/// Last modified at 2025年07月12日 星期六 23时31分22秒
/// Author: <kisfg@hotmail.com, 2025-06>
#include <stdint.h>

#ifndef __AIGIS_CONST_H__
#define __AIGIS_CONST_H__

#define         AIGIS_N                     256         // a_{0}+a_{1}X+...+a_{255}X^255 ~ (a0, a1, ..., a255)
#define         AIGIS_SEED_SIZE             32
#define         AIGIS_RNG_SEED_SIZE         48
#define         AIGIS_CRH_SIZE              AIGIS_RNG_SEED_SIZE // SIG的种子参数

#define         AIGIS_ENC_MOD_Q             7681        // Zq = Z_{7681}
#define         AIGIS_ENC_POLY_SIZE         416         // 8字节分给13个字节 => 256 / 8 * 13 = 416
#define         AIGIS_ENC_REJ_SIZE          480
#define         AIGIS_ENC_QBITS             13          // log(q) ~ 13
#define         AIGIS_ENC_QINV              57857       // AIGIS_MOD_Q ^ -1 (mod 2^16)，可能用不到
#define         AIGIS_ENC_NEG_QINV          7679        // 7679 * 7681 = -1 (mod 2^16)
#define         AIGIS_ENC_POW_2_15_Q        2044        // 2^15 mod 7681
#define         AIGIS_ENC_POW_2_32_Q        5569LL      // 2^32 mod 7681

#define         AIGIS_SIG_KDF128_RATE       168         // 168, SHAKE128_RATE
#define         AIGIS_SIG_KDF256_RATE       136         // 136, SHAKE256_RATE

#define         AIGIS_SIG_2_KDF256_RATE     (AIGIS_SIG_KDF256_RATE<<1)
#define         AIGIS_SIG_3_KDF256_RATE     (AIGIS_SIG_KDF256_RATE*3)
#define         AIGIS_SIG_5_KDF256_RATE     (AIGIS_SIG_KDF256_RATE*5)

#define         AIGIS_KDF128_PAD_SIZE       (AIGIS_SIG_KDF128_RATE*6)

#define     AIGIS_SIG_GAMMA1            131072

#if (AIGIS_PARAM_CONF == 1)
    #define     AIGIS_ENC_K                 2
    #define     AIGIS_ENC_ETA_S             4
    #define     AIGIS_ENC_ETA_E             8

    #define     AIGIS_ENC_BITS_PUB          10
    #define     AIGIS_ENC_BITS_CFT          10          // ciphertext ~ cifertext ~ cft
    #define     AIGIS_ENC_BITS_CFT2         3           // 单个密文多项式的比特长度
    /// 签名参数配置
    #define     AIGIS_SIG_MOD_Q             2021377
    #define     AIGIS_SIG_QBITS             21
    #define     AIGIS_SIG_POW_2_24_Q        606200ULL   // 2^24 mod AIGIS_SIG_N
    #define     AIGIS_SIG_POW_2_32_Q        1562548U    // 2^32 mod AIGIS_SIG_N
	#define		AIGIS_SIG_POW_2_56_Q		1356777ULL	// 2^56 mod AIGIS_SIG_N
    #define     AIGIS_SIG_POW_2_64_Q        1679445ULL  // 2^64 mod AIGIS_SIG_N
    #define     AIGIS_SIG_NEG_QINV          2849953791U // (-q)^(-1) mod 2^32
    #define     AIGIS_SIG_GENERATOR         79          // 用于生成用于ntt的 ζ
    #define     AIGIS_SIG_GAMMA2            168448ULL
    #define     AIGIS_SIG_ALPHA             (AIGIS_SIG_GAMMA2 << 1)
    #define     AIGIS_SIG_DECOMP_BITS       20
    #define     AIGIS_SIG_D                 13
    #define     AIGIS_SIG_K                 4
    #define     AIGIS_SIG_L                 3

    #define     AIGIS_SIG_ETA_S             2
    #define     AIGIS_SIG_ETA_E             3

    #define     AIGIS_SIG_ETA_S_BITS        3
    #define     AIGIS_SIG_ETA_E_BITS        3

    #define     AIGIS_SIG_EXP_MATR_SIZE     AIGIS_KDF128_PAD_SIZE
    #define     AIGIS_SIG_EXP_ETA_E_SIZE    AIGIS_SIG_2_KDF256_RATE

    #define     AIGIS_SIG_BETA1             120
    #define     AIGIS_SIG_BETA2             175
    #define     AIGIS_SIG_OMEGA             80
#elif (AIGIS_PARAM_CONF == 2)
    #define     AIGIS_ENC_K                 3
    #define     AIGIS_ENC_ETA_S             1
    #define     AIGIS_ENC_ETA_E             4

    #define     AIGIS_ENC_BITS_PUB          9
    #define     AIGIS_ENC_BITS_CFT          9
    #define     AIGIS_ENC_BITS_CFT2         4
    /// 签名参数配置
    #define     AIGIS_SIG_MOD_Q             3870721
    #define     AIGIS_SIG_QBITS             22
    #define     AIGIS_SIG_POW_2_24_Q        1294332ULL  // 2^24 mod AIGIS_SIG_N
    #define     AIGIS_SIG_POW_2_32_Q        2337707U    // 2^32 mod AIGIS_SIG_N
	#define		AIGIS_SIG_POW_2_56_Q		3146698ULL	// 2^56 mod AIGIS_SIG_N
    #define     AIGIS_SIG_POW_2_64_Q        444720ULL   // 2^64 mod AIGIS_SIG_N
    #define     AIGIS_SIG_NEG_QINV          2671448063U // (-q)^(-1) mod 2^32
    #define     AIGIS_SIG_GENERATOR         19602
    #define     AIGIS_SIG_GAMMA2            322560ULL
    #define     AIGIS_SIG_ALPHA             (AIGIS_SIG_GAMMA2 << 1)
    #define     AIGIS_SIG_DECOMP_BITS       21
    #define     AIGIS_SIG_D                 14
    #define     AIGIS_SIG_K                 5
    #define     AIGIS_SIG_L                 4

    #define     AIGIS_SIG_ETA_S             2
    #define     AIGIS_SIG_ETA_E             5

    #define     AIGIS_SIG_ETA_S_BITS        3
    #define     AIGIS_SIG_ETA_E_BITS        4

    #define     AIGIS_SIG_EXP_MATR_SIZE     (\
        AIGIS_KDF128_PAD_SIZE+               \
        AIGIS_SIG_KDF128_RATE                \
    )
    #define     AIGIS_SIG_EXP_ETA_E_SIZE    AIGIS_SIG_3_KDF256_RATE

    #define     AIGIS_SIG_BETA1             120
    #define     AIGIS_SIG_BETA2             275
    #define     AIGIS_SIG_OMEGA             96
#elif (AIGIS_PARAM_CONF == 3)
    #define     AIGIS_ENC_K                 3
    #define     AIGIS_ENC_ETA_S             2
    #define     AIGIS_ENC_ETA_E             4

    #define     AIGIS_ENC_BITS_PUB          10
    #define     AIGIS_ENC_BITS_CFT          10
    #define     AIGIS_ENC_BITS_CFT2         3
    /// 签名参数配置
    #define     AIGIS_SIG_MOD_Q             3870721
    #define     AIGIS_SIG_QBITS             22
    #define     AIGIS_SIG_POW_2_24_Q        1294332ULL  // 2^24 mod AIGIS_SIG_N
    #define     AIGIS_SIG_POW_2_32_Q        2337707U    // 2^32 mod AIGIS_SIG_N
	#define		AIGIS_SIG_POW_2_56_Q		3146698ULL	// 2^56 mod AIGIS_SIG_N
    #define     AIGIS_SIG_POW_2_64_Q        444720ULL   // 2^64 mod AIGIS_SIG_N
    #define     AIGIS_SIG_NEG_QINV          2671448063U // (-q)^(-1) mod 2^32
    #define     AIGIS_SIG_GENERATOR         19602
    #define     AIGIS_SIG_GAMMA2            322560ULL
    #define     AIGIS_SIG_ALPHA             (AIGIS_SIG_GAMMA2 << 1)
    #define     AIGIS_SIG_DECOMP_BITS       21
    #define     AIGIS_SIG_D                 14
    #define     AIGIS_SIG_K                 6
    #define     AIGIS_SIG_L                 5

    #define     AIGIS_SIG_ETA_S             1
    #define     AIGIS_SIG_ETA_E             5

    #define     AIGIS_SIG_ETA_S_BITS        2
    #define     AIGIS_SIG_ETA_E_BITS        4

    #define     AIGIS_SIG_EXP_MATR_SIZE     (\
        AIGIS_KDF128_PAD_SIZE+               \
        AIGIS_SIG_KDF128_RATE                \
    )
    #define     AIGIS_SIG_EXP_ETA_E_SIZE    AIGIS_SIG_3_KDF256_RATE


    #define     AIGIS_SIG_BETA1             60
    #define     AIGIS_SIG_BETA2             275
    #define     AIGIS_SIG_OMEGA             120
#else
    #error "Invalid configuration upon AIGIS_PARAM_CONF"
#endif // check for AIGIS_PARAM_CONF

#define         AIGIS_ENC_ETA_E_INP_SIZE        (AIGIS_ENC_ETA_E*(AIGIS_N>>2)) // 从噪声生成环上的向量
#define         AIGIS_ENC_ETA_S_INP_SIZE        (AIGIS_ENC_ETA_S*(AIGIS_N>>2))

#define         AIGIS_ENC_PVEC_SIZE             (AIGIS_ENC_K*AIGIS_ENC_POLY_SIZE)

#define         AIGIS_ENC_COMP_PUB_SIZE         (AIGIS_ENC_BITS_PUB*AIGIS_ENC_K*(AIGIS_N>>3))
#define         AIGIS_ENC_COMP_CFT_SIZE         (AIGIS_ENC_BITS_CFT*AIGIS_ENC_K*(AIGIS_N>>3))

#define         AIGIS_ENC_COMP_CFT2_SIZE        (AIGIS_ENC_BITS_CFT2*AIGIS_N >> 3) // CFT2对应为多项式形式的密文

/// 加密标准中的公私钥长度以及密文长度
#define         AIGIS_ENC_PUB_SIZE              (AIGIS_SEED_SIZE+AIGIS_ENC_COMP_PUB_SIZE)
#define         AIGIS_ENC_SEC_SIZE              (      \
    AIGIS_SEED_SIZE*2+                                 \
    AIGIS_ENC_PUB_SIZE+                                \
    AIGIS_ENC_PVEC_SIZE                                \
)
#define         AIGIS_ENC_CFT_SIZE              (AIGIS_ENC_COMP_CFT_SIZE+AIGIS_ENC_COMP_CFT2_SIZE)

/// 下列宏提供给签名密码算法使用
#define         AIGIS_SIG_POLY_Z_COMP_SIZE      (18*(AIGIS_N>>3))
#define         AIGIS_SIG_POLY_W1_COMP_SIZE     (3*(AIGIS_N>>3))
#define         AIGIS_SIG_POLY_Rq_COMP_SIZE     (AIGIS_N*AIGIS_SIG_QBITS>>3)
#define         AIGIS_SIG_POLY_T0_COMP_SIZE     (AIGIS_N*AIGIS_SIG_D>>3)
#define         AIGIS_SIG_POLY_T1_COMP_SIZE     (AIGIS_SIG_POLY_Rq_COMP_SIZE-(AIGIS_N*AIGIS_SIG_D>>3))

#define         AIGIS_SIG_POLY_ETA_S_COMP_SIZE  ((AIGIS_N*AIGIS_SIG_ETA_S_BITS) >> 3)
#define         AIGIS_SIG_POLY_ETA_E_COMP_SIZE  ((AIGIS_N*AIGIS_SIG_ETA_E_BITS) >> 3)

#define         AIGIS_PVEC_K_SIZE               (AIGIS_SIG_K*AIGIS_SIG_POLY_Rq_COMP_SIZE)
#define         AIGIS_PVEC_K_T0_SIZE            (AIGIS_SIG_K*AIGIS_SIG_POLY_T0_COMP_SIZE)
#define         AIGIS_PVEC_K_T1_SIZE            (AIGIS_SIG_K*AIGIS_SIG_POLY_T1_COMP_SIZE)
#define         AIGIS_PVEC_K_ETA_E_SIZE         (AIGIS_SIG_K*AIGIS_SIG_POLY_ETA_E_COMP_SIZE)
#define         AIGIS_PVEC_K_ETA_S_SIZE         (AIGIS_SIG_K*AIGIS_SIG_POLY_ETA_S_COMP_SIZE)
#define         AIGIS_PVEC_K_Z_SIZE             (AIGIS_SIG_K*AIGIS_SIG_POLY_Z_COMP_SIZE)
#define         AIGIS_PVEC_K_W1_SIZE            (AIGIS_SIG_K*AIGIS_SIG_POLY_W1_COMP_SIZE)
#define         AIGIS_PVEC_L_SIZE               (AIGIS_SIG_L*AIGIS_SIG_POLY_Rq_COMP_SIZE)
#define         AIGIS_PVEC_L_T0_SIZE            (AIGIS_SIG_L*AIGIS_SIG_POLY_T0_COMP_SIZE)
#define         AIGIS_PVEC_L_T1_SIZE            (AIGIS_SIG_L*AIGIS_SIG_POLY_T1_COMP_SIZE)
#define         AIGIS_PVEC_L_ETA_S_SIZE         (AIGIS_SIG_L*AIGIS_SIG_POLY_ETA_S_COMP_SIZE)
#define         AIGIS_PVEC_L_ETA_E_SIZE         (AIGIS_SIG_L*AIGIS_SIG_POLY_ETA_E_COMP_SIZE)
#define         AIGIS_PVEC_L_Z_SIZE             (AIGIS_SIG_L*AIGIS_SIG_POLY_Z_COMP_SIZE)

///
#define         AIGIS_SIG_PUB_SIZE              (AIGIS_SEED_SIZE + AIGIS_PVEC_K_T1_SIZE)
#define         AIGIS_SIG_SEC_SIZE              (      \
    AIGIS_SEED_SIZE*2 + AIGIS_PVEC_L_ETA_S_SIZE +      \
    AIGIS_PVEC_K_ETA_E_SIZE + AIGIS_CRH_SIZE +         \
    AIGIS_PVEC_K_T0_SIZE                               \
)
#define         AIGIS_SIG_SIG_SIZE          (          \
    AIGIS_PVEC_L_Z_SIZE +                              \
    (AIGIS_SIG_OMEGA + AIGIS_SIG_K) +                  \
    (AIGIS_N>>3) + 8                                   \
)

/// 编译期检查
/*
	poly.c:80:#error "rej_eta1() assumes ETA1 <= 3"
	poly.c:188:#error "rej_eta2() assumes 3 <= ETA2 <=7"
	poly.c:326:#error "poly_uniform_gamma1m1() assumes GAMMA1 == 131072"
	poly.c:390:#error "polyeta1_pack() assumes ETA1 <= 3"
	poly.c:429:#error "polyeta2_pack() assumes ETA2 <= 7"
	poly.c:546:#error "polyt1_pack() assumes QBITS - PARAM_D == 8"
	poly.c:568:#error "polyt0_unpack() assumes PARAM_D== 13 or 14"
	poly.c:702:#error "polyz_pack() assumes GAMMA1-BETA1 <= 2^{17}"
	poly.c:772:#error "polyw1_pack() assumes PARAM_Q/ALPHA -1 <= 7"
	hashkdf.h:89:// #error "kem.c/owcpa.c/alg.c only supports SEED_BYTES in {32,64}"
	rounding.c:21:#error "decompose() assumes (PARAM_Q-1) == 6*ALPHA"
*/
#if AIGIS_SEED_SIZE != 32 && AIGIS_SEED_SIZE != 64
	#error "kdf only support AIGIS_SEED_SIZE in {32, 64}!"
#endif

#if AIGIS_SIG_ETA_S > 3
	#error "sig_rej_eta_s() requires AIGIS_SIG_ETA_S <= 3!"
#endif

#if AIGIS_SIG_ETA_E > 7 || AIGIS_SIG_ETA_E < 3
	#error "sig_rej_eta_e() requires 3 <= AIGIS_SIG_ETA_E <= 7!"
#endif
#if AIGIS_SIG_QBITS - AIGIS_SIG_D != 8
	#error "sig_poly_t1_pack() requires AIGIS_SIG_QBITS - AIGIS_SIG_D == 8!"
#endif // sig_poly_t1_pack() 的要求

#if AIGIS_SIG_D != 13 && AIGIS_SIG_D != 14
	#error "sig_poly_t0_unpack() requires AIGIS_SIG_D == 13 or 14!"
#endif // sig_poly_t0_unpack() 的要求

#if AIGIS_SIG_MOD_Q > 8*AIGIS_SIG_ALPHA
	#error "sig_poly_w1_pack() requires AIGIS_SIG_MOD_Q <= AIGIS_SIG_ALPHA<<3!"
#endif // sig_poly_w1_pack() 的要求


#if AIGIS_SIG_GAMMA1 != 131072
	#error "sig_poly_uniform_gamma1 requires AIGIS_SIG_GAMMA1 == 131072!"
#endif // sig_poly_uniform_gamma1 的要求

#if AIGIS_SIG_GAMMA1 - AIGIS_SIG_BETA1 > (1 << 17)
	#error "sig_poly_z_{un}pack() assumes GAMMA1-BETA1 <= 2^{17}!"
#endif

#if AIGIS_SIG_MOD_Q-1 != 6*AIGIS_SIG_ALPHA
	#error "decompose() requires (AIGIS_SIG_Q - 1) == 6 * AIGIS_SIG_ALPHA!"
#endif

#endif // AIGIS_CONST_H
