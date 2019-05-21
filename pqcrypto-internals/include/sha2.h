#ifndef SHA2_H
#define SHA2_H

#include <stddef.h>
#include <stdint.h>

/* The incremental API allows hashing of individual input blocks; these blocks
    must be exactly 64 bytes each.
    Use the 'finalize' functions for any remaining bytes (possibly over 64). */

/**
 * The state for the hash function
 */
typedef struct {
  void *state;
} sha224ctx;

/**
 * The state for the hash function
 */
typedef struct {
  void *state;
} sha256ctx;

/**
 * The state for the hash function
 */
typedef struct {
  void *state;
} sha384ctx;

/**
 * The state for the hash function
 */
typedef struct {
  void *state;
} sha512ctx;



/**
 * Directly obtain the digest of input
 */
void sha224(uint8_t *out, const uint8_t *input, size_t inlen);

/**
 * Add 64-bytes blocks to the state
 */
void sha224_inc_blocks(sha224ctx *state, const uint8_t *inblocks, size_t inlen);

/**
 * Finalize the state and obtain the hash result.
 * Consumes the state
 */
void sha224_inc_finalize(uint8_t *out, sha224ctx *state, const uint8_t *inbytes, size_t inlen);

/**
 * Initializes the incremental hashing state.
 * Allocates the state for the hash function.
 * Make sure to call the ``_inc_finalize`` variant
 * at some point to free the allocated memory.
 */
void sha224_inc_init(sha224ctx *state);

/**
 * Directly obtain the digest of input
 */
void sha256(uint8_t *out, const uint8_t *input, size_t inlen);

/**
 * Add 64-bytes blocks to the state
 */
void sha256_inc_blocks(sha256ctx *state, const uint8_t *inblocks, size_t inlen);

/**
 * Finalize the state and obtain the hash result.
 * Consumes the state
 */
void sha256_inc_finalize(uint8_t *out, sha256ctx *state, const uint8_t *inbytes, size_t inlen);

/**
 * Initializes the incremental hashing state.
 * Allocates the state for the hash function.
 * Make sure to call the ``_inc_finalize`` variant
 * at some point to free the allocated memory.
 */
void sha256_inc_init(sha256ctx *state);

/**
 * Directly obtain the digest of input
 */
void sha384(uint8_t *out, const uint8_t *input, size_t inlen);

/**
 * Add 64-bytes blocks to the state
 */
void sha384_inc_blocks(sha384ctx *state, const uint8_t *inblocks, size_t inlen);

/**
 * Finalize the state and obtain the hash result.
 * Consumes the state
 */
void sha384_inc_finalize(uint8_t *out, sha384ctx *state, const uint8_t *inbytes, size_t inlen);

/**
 * Initializes the incremental hashing state.
 * Allocates the state for the hash function.
 * Make sure to call the ``_inc_finalize`` variant
 * at some point to free the allocated memory.
 */
void sha384_inc_init(sha384ctx *state);

/**
 * Directly obtain the digest of input
 */
void sha512(uint8_t *out, const uint8_t *input, size_t inlen);

/**
 * Add 64-bytes blocks to the state
 */
void sha512_inc_blocks(sha512ctx *state, const uint8_t *inblocks, size_t inlen);

/**
 * Finalize the state and obtain the hash result.
 * Consumes the state
 */
void sha512_inc_finalize(uint8_t *out, sha512ctx *state, const uint8_t *inbytes, size_t inlen);

/**
 * Initializes the incremental hashing state.
 * Allocates the state for the hash function.
 * Make sure to call the ``_inc_finalize`` variant
 * at some point to free the allocated memory.
 */
void sha512_inc_init(sha512ctx *state);


#endif
