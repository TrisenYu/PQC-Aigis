/// SPDX-LICENSE-IDENTIFIER: GPL2.0
///
/// (C) All rights reserved. Author: <kisfg@hotmail.com> in 2025
/// Created at 2025年07月31日 星期四 16时14分48秒
/// Last modified at 2025年07月31日 星期四 16时22分43秒
#include "hash/keccak/fips202.h"
/*************************************************
* Name:        shake128_init
*
* Description: Initilizes Keccak state for use as SHAKE128 XOF
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
**************************************************/
void shake128_init(keccak_state *state)
{
  keccak_init(state->s);
  state->pos = 0;
}

/*************************************************
* Name:        shake128_absorb
*
* Description: Absorb step of the SHAKE128 XOF; incremental.
*
* Arguments:   - keccak_state *state: pointer to (initialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
**************************************************/
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
  state->pos = keccak_absorb(state->s, state->pos, SHA3_128_RATE, in, inlen);
}

/*************************************************
* Name:        shake128_finalize
*
* Description: Finalize absorb step of the SHAKE128 XOF.
*
* Arguments:   - keccak_state *state: pointer to Keccak state
**************************************************/
void shake128_finalize(keccak_state *state)
{
  keccak_finalize(state->s, state->pos, SHA3_128_RATE, 0x1F);
  state->pos = SHA3_128_RATE;
}

/*************************************************
* Name:        shake128_squeeze
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes arbitraily many
*              bytes. Can be called multiple times to keep squeezing.
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t outlen : number of bytes to be squeezed (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake128_squeeze(keccak_state *state, uint8_t *out, size_t outlen)
{
  state->pos = keccak_squeeze(out, outlen, state->s, state->pos, SHA3_128_RATE);
}

/*************************************************
* Name:        shake128_absorb_once
*
* Description: Initialize, absorb into and finalize SHAKE128 XOF; non-incremental.
*
* Arguments:   - keccak_state *state:  pointer to (uninitialized) output Keccak state
*              - const uint8_t *in:    pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
**************************************************/
void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
{
  keccak_absorb_once(state->s, SHA3_128_RATE, in, inlen, 0x1F);
  state->pos = SHA3_128_RATE;
}

/*************************************************
* Name:        shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of SHA3_128_RATE bytes each.
*              Modifies the state. Can be called multiple times to keep squeezing,
*              i.e., is incremental.
*
* Arguments:   - uint8_t *output:      pointer to output blocks
*              - size_t nblocks: number of blocks to be squeezed (written to output)
*              - keccak_state *state:  pointer to in/output Keccak state
**************************************************/
void shake128_squeezeblocks(keccak_state *state, uint8_t *output, size_t nblocks)
{
  keccak_squeezeblocks(output, nblocks, state->s, SHA3_128_RATE);
}


/*************************************************
* Name:        shake256_init
*
* Description: Initilizes Keccak state for use as SHAKE256 XOF
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
**************************************************/
void shake256_init(keccak_state *state)
{
  keccak_init(state->s);
  state->pos = 0;
}

/*************************************************
* Name:        shake256_absorb
*
* Description: Absorb step of the SHAKE256 XOF; incremental.
*
* Arguments:   - keccak_state *state: pointer to (initialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
**************************************************/
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
  state->pos = keccak_absorb(state->s, state->pos, SHA3_256_RATE, in, inlen);
}

/*************************************************
* Name:        shake256_finalize
*
* Description: Finalize absorb step of the SHAKE256 XOF.
*
* Arguments:   - keccak_state *state: pointer to Keccak state
**************************************************/
void shake256_finalize(keccak_state *state)
{
  keccak_finalize(state->s, state->pos, SHA3_256_RATE, 0x1F);
  state->pos = SHA3_256_RATE;
}

/*************************************************
* Name:        shake256_squeeze
*
* Description: Squeeze step of SHAKE256 XOF. Squeezes arbitraily many
*              bytes. Can be called multiple times to keep squeezing.
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t outlen : number of bytes to be squeezed (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state)
{
  state->pos = keccak_squeeze(out, outlen, state->s, state->pos, SHA3_256_RATE);
}

/*************************************************
 * Name:        shake256_absorb_once
 *
 * Description: Absorb step of the SHAKE256 XOF.
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
 *              - const uint8_t *input: pointer to input to be absorbed
 *                                            into s
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake256_absorb_once(keccak_state *state, const uint8_t *input, size_t inlen)
{
    keccak_absorb_once(state->s, SHA3_256_RATE, input, inlen, 0x1F);
    state->pos = SHA3_256_RATE;
}

/*************************************************
 * Name:        shake256_squeezeblocks
 *
 * Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
 *              SHA3_256_RATE bytes each. Modifies the state. Can be called
 *              multiple times to keep squeezing, i.e., is incremental.
 *
 * Arguments:   - uint8_t *output: pointer to output blocks
 *              - size_t nblocks: number of blocks to be squeezed
 *                                (written to output)
 *              - keccak_state *state: pointer to input/output Keccak state
 **************************************************/
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, keccak_state *state)
{
    keccak_squeezeblocks(output, nblocks, state->s, SHA3_256_RATE);
}

/*************************************************
* Name:        shake128
*
* Description: SHAKE128 XOF with non-incremental API
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen: length of input in bytes
**************************************************/
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
  size_t nblocks;
  keccak_state state;

  shake128_absorb_once(&state, in, inlen);
  nblocks = outlen/SHA3_128_RATE;
  shake128_squeezeblocks(&state, out, nblocks);
  outlen -= nblocks*SHA3_128_RATE;
  out += nblocks*SHA3_128_RATE;
  shake128_squeeze(&state, out, outlen);
}

/*************************************************
* Name:        shake256
*
* Description: SHAKE256 XOF with non-incremental API
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen: length of input in bytes
**************************************************/
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
  size_t nblocks;
  keccak_state state;

  shake256_absorb_once(&state, in, inlen);
  nblocks = outlen/SHA3_256_RATE;
  shake256_squeezeblocks(out, nblocks, &state);
  outlen -= nblocks*SHA3_256_RATE;
  out += nblocks*SHA3_256_RATE;
  shake256_squeeze(out, outlen, &state);
}

/*************************************************
* Name:        sha3_128
*
* Description: SHA3-128 with non-incremental API
*
* Arguments:   - uint8_t *output:      pointer to output
*              - const uint8_t *input: pointer to input
*              - size_t inlen:   length of input in bytes
**************************************************/
void sha3_128(uint8_t *output, const uint8_t *input,  size_t inlen)
{
  uint64_t s[25];
  uint8_t t[SHA3_128_RATE];
  size_t i;

  /* Absorb input */
  keccak_absorb_once(s, SHA3_128_RATE, input, inlen, 0x06);

  /* Squeeze output */
  keccak_squeezeblocks(t, 1, s, SHA3_128_RATE);

  for(i=0;i<16;i++)
      output[i] = t[i];
}

/*************************************************
* Name:        sha3_256
*
* Description: SHA3-256 with non-incremental API
*
* Arguments:   - uint8_t *output:      pointer to output
*              - const uint8_t *input: pointer to input
*              - size_t inlen:   length of input in bytes
**************************************************/
void sha3_256(uint8_t *output, const uint8_t *input,  size_t inlen)
{
  uint64_t s[25];
  uint8_t t[SHA3_256_RATE];
  size_t i;

  /* Absorb input */
  keccak_absorb_once(s, SHA3_256_RATE, input, inlen, 0x06);

  /* Squeeze output */
  keccak_squeezeblocks(t, 1, s, SHA3_256_RATE);

  for(i=0;i<32;i++)
      output[i] = t[i];
}

/*************************************************
* Name:        sha3_484
*
* Description: SHA3-384 with non-incremental API
*
* Arguments:   - uint8_t *output:      pointer to output
*              - const uint8_t *input: pointer to input
*              - size_t inlen:   length of input in bytes
**************************************************/
void sha3_384(uint8_t *output, const uint8_t *input, size_t inlen)
{
	uint64_t s[25];
	uint8_t t[SHA3_384_RATE];
	size_t i;

	/* Absorb input */
	keccak_absorb_once(s, SHA3_384_RATE, input, inlen, 0x06);

	/* Squeeze output */
	keccak_squeezeblocks(t, 1, s, SHA3_384_RATE);

	for (i = 0; i<48; i++)
		output[i] = t[i];
}

/*************************************************
* Name:        sha3_512
*
* Description: SHA3-512 with non-incremental API
*
* Arguments:   - uint8_t *output:      pointer to output
*              - const uint8_t *input: pointer to input
*              - size_t inlen:   length of input in bytes
**************************************************/
void sha3_512(uint8_t *output, const uint8_t *input,  size_t inlen)
{
  uint64_t s[25];
  uint8_t t[SHA3_512_RATE];
  size_t i;

  /* Absorb input */
  keccak_absorb_once(s, SHA3_512_RATE, input, inlen, 0x06);

  /* Squeeze output */
  keccak_squeezeblocks(t, 1, s, SHA3_512_RATE);

  for(i=0;i<64;i++)
      output[i] = t[i];
}

void sha3_1024(uint8_t *output, const uint8_t *input, size_t inlen)
{
	uint64_t s[25];
	uint8_t t[2*SHA3_512_RATE];
	size_t i;

	/* Absorb input */
	keccak_absorb_once(s, SHA3_512_RATE, input, inlen, 0x06);

	/* Squeeze output */
	keccak_squeezeblocks(t,2, s, SHA3_512_RATE);

	for (i = 0; i < 128; i++)
		output[i] = t[i];

	// free(t);
}

void shake256_inc_init(uint64_t *s_inc) {
    keccak_inc_init(s_inc);
}

void shake256_inc_absorb(uint64_t *s_inc, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(s_inc, SHA3_256_RATE, input, inlen);
}

void shake256_inc_finalize(uint64_t *s_inc) {
    keccak_inc_finalize(s_inc, SHA3_256_RATE, 0x1F);
}

void shake256_inc_squeeze(uint8_t *output, size_t outlen, uint64_t *s_inc) {
    keccak_inc_squeeze(output, outlen, s_inc, SHA3_256_RATE);
}
