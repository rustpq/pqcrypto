#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

/**
 * XOF state for the ``_absorb`` and ``_squeezeblocks`` functions.
 */
typedef struct {
  uint8_t __state[216];
} shake128ctx;

/**
 * Incremental XOF state
 */

typedef struct {
  uint8_t __state[384];
} shake128incctx;

/**
 * XOF state for the ``_absorb`` and ``_squeezeblocks`` functions.
 */
typedef struct {
  uint8_t __state[216];
} shake256ctx;

/**
 * Incremental XOF state
 */
typedef struct {
  uint8_t __state[352];
} shake256incctx;

/**
 * The state for the hash function
 */
typedef struct {
  uint8_t __state[352];
} sha3_256incctx;

/**
 * The state for the hash function
 */
typedef struct {
  void *state;
  uint8_t __state[288];
} sha3_512incctx;


/**
 * Directly obtain the digest of input
 */
void sha3_256(uint8_t *out, const uint8_t *input, size_t inlen);

/**
 * Add 64-bytes blocks to the state
 */
void sha3_256_inc_absorb(sha3_256incctx *state, const uint8_t *inblocks, size_t inlen);

/**
 * Finalize the state and obtain the hash result.
 * Consumes the state
 */
void sha3_256_inc_finalize(uint8_t *out, sha3_256incctx *state, const uint8_t *inbytes, size_t inlen);

/**
 * Initializes the incremental hashing state.
 * Allocates the state for the hash function.
 * Make sure to call the ``_inc_finalize`` variant
 * at some point to free the allocated memory.
 */
void sha3_256_inc_init(sha3_256incctx *state);

/**
 * Directly obtain the digest of input
 */
void sha3_512(uint8_t *out, const uint8_t *input, size_t inlen);

/**
 * Add 64-bytes blocks to the state
 */
void sha3_512_inc_absorb(sha3_512incctx *state, const uint8_t *inblocks, size_t inlen);

/**
 * Finalize the state and obtain the hash result.
 * Consumes the state
 */
void sha3_512_inc_finalize(uint8_t *out, sha3_512incctx *state, const uint8_t *inbytes, size_t inlen);

/**
 * Initializes the incremental hashing state.
 * Allocates the state for the hash function.
 * Make sure to call the ``_inc_finalize`` variant
 * at some point to free the allocated memory.
 */
void sha3_512_inc_init(sha3_512incctx *state);

/**
 * Extendible-Output Function
 */
void shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);

/**
 * Squeeze out output from the XOF which already absorbed things through ``_absorb``.
 */
void shake128_absorb(uint8_t *output, size_t nblocks, shake128ctx *state);

/**
 * Absorb ``input`` into the XOF state
 */
void shake128_inc_absorb(shake128incctx *state, const uint8_t *input, size_t inlen);

/**
 * Finalize the XOF state to prepare for squeezing.
 * After this you can't absorb anymore.
 */
void shake128_inc_finalize(shake128incctx *state);

/**
 * Initialize the incremental XOF state
 */
void shake128_inc_init(shake128incctx *state);

/**
 * Squeeze out ``outlen`` bytes
 */
void shake128_inc_squeeze(uint8_t *output, size_t outlen, shake128incctx *state);

/**
 * Initializes the XOF state and absorbs the input
 * After calling this function, pass to ``_squeezeblocks``
 */
void shake128_squeeze(shake128ctx *state, const uint8_t *input, size_t input_len);

/**
 * Extendible-Output Function
 */
void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);

/**
 * Squeeze out output from the XOF which already absorbed things through ``_absorb``.
 */
void shake256_absorb(uint8_t *output, size_t nblocks, shake256ctx *state);

/**
 * Absorb ``input`` into the XOF state
 */
void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen);

/**
 * Finalize the XOF state to prepare for squeezing.
 * After this you can't absorb anymore.
 */
void shake256_inc_finalize(shake256incctx *state);

/**
 * Initialize the incremental XOF state
 */
void shake256_inc_init(shake256incctx *state);

/**
 * Squeeze out ``outlen`` bytes
 */
void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state);

/**
 * Initializes the XOF state and absorbs the input
 * After calling this function, pass to ``_squeezeblocks``
 */
void shake256_squeeze(shake256ctx *state, const uint8_t *input, size_t input_len);


#endif
