/*
 * spake2p.h - C ABI over the spake2p Rust crate (RFC 9383 SPAKE2+,
 * P256-SHA256-HKDF-SHA256-HMAC-SHA256). Licensed under either of Apache-2.0 or MIT at your option.
 *
 * Conventions
 *  - Every function returns a spake2p_status_t: 0 (SPAKE2P_OK) is success, anything else an error.
 *    On error no output buffer is written, and an output handle is set to NULL.
 *  - Byte strings are (pointer, length). NULL is accepted only with length 0.
 *  - Output buffers are (pointer, capacity). They must be non-NULL with capacity at least the size
 *    stated below; only the leading bytes are written.
 *  - Sizes: scalar (w0, w1) 32, point (shareP, shareV, L) 65 (uncompressed SEC1), confirmation tag 32,
 *    shared key 32, PBKDF output 80.
 *  - Handles are not thread-safe: use one from one thread at a time (moving between threads is fine).
 *  - spake2p_*_finish CONSUMES its handle on success and on failure: it is freed (and zeroised) and the
 *    pointer is invalid afterwards. Do not call finish twice or free a finished handle.
 *  - No panic crosses this boundary; a caught one is SPAKE2P_ERR_PANIC.
 */
#ifndef SPAKE2P_H
#define SPAKE2P_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t spake2p_status_t;

enum {
    SPAKE2P_OK = 0,
    SPAKE2P_ERR_INVALID_LENGTH = 1,       /* a byte string had the wrong length */
    SPAKE2P_ERR_INVALID_ENCODING = 2,     /* point not uncompressed SEC1 (leading 0x04) */
    SPAKE2P_ERR_NOT_ON_CURVE = 3,         /* point not on P-256 */
    SPAKE2P_ERR_IDENTITY_POINT = 4,       /* received or computed point is the identity */
    SPAKE2P_ERR_SCALAR_OUT_OF_RANGE = 5,  /* scalar >= group order */
    SPAKE2P_ERR_ZERO_SCALAR = 6,          /* w0 or w1 is zero */
    SPAKE2P_ERR_CONFIRMATION_FAILED = 7,  /* wrong password/context/identity or tampering */
    SPAKE2P_ERR_RNG = 8,                  /* OS random number generator failed */
    SPAKE2P_ERR_UNKNOWN = 9,              /* an error this header does not know */
    SPAKE2P_ERR_NULL_POINTER = 100,       /* a required pointer was NULL */
    SPAKE2P_ERR_BUFFER_TOO_SMALL = 101,   /* output capacity smaller than the output */
    SPAKE2P_ERR_PANIC = 102               /* internal panic caught (a bug) */
};

enum {
    SPAKE2P_SCALAR_LEN = 32,
    SPAKE2P_POINT_LEN = 65,
    SPAKE2P_CONFIRM_LEN = 32,
    SPAKE2P_KEY_LEN = 32,
    SPAKE2P_PBKDF_OUTPUT_LEN = 80
};

/* Opaque handles. */
typedef struct Spake2pProver spake2p_prover_t;
typedef struct Spake2pVerifier spake2p_verifier_t;

/* Registration ------------------------------------------------------------------------------ */

/* Splits an 80-byte PBKDF output into w0 and w1 (each 32 bytes, big-endian). */
spake2p_status_t spake2p_w0w1_from_pbkdf_output(
    const uint8_t *pbkdf_output, size_t pbkdf_output_len,
    uint8_t *w0_out, size_t w0_cap,
    uint8_t *w1_out, size_t w1_cap);

/* L = w1*P (65 bytes) from w1 (32 bytes). The Verifier stores (w0, L), never w1. */
spake2p_status_t spake2p_register(
    const uint8_t *w1, size_t w1_len,
    uint8_t *l_out, size_t l_cap);

/* RFC 9383 section 3.2 PBKDF input. Required size = 24 + password_len + id_prover_len +
 * id_verifier_len; *out_len (non-NULL) receives it on success and on BUFFER_TOO_SMALL, so a caller can
 * probe with out_cap = 0 and any non-NULL out. */
spake2p_status_t spake2p_pbkdf_input(
    const uint8_t *password, size_t password_len,
    const uint8_t *id_prover, size_t id_prover_len,
    const uint8_t *id_verifier, size_t id_verifier_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

/* Prover ------------------------------------------------------------------------------------ */

/* Starts a Prover. w0, w1: 32 bytes. Writes shareP (65 bytes) and sets *out_prover (NULL on failure). */
spake2p_status_t spake2p_prover_start(
    const uint8_t *context, size_t context_len,
    const uint8_t *id_prover, size_t id_prover_len,
    const uint8_t *id_verifier, size_t id_verifier_len,
    const uint8_t *w0, size_t w0_len,
    const uint8_t *w1, size_t w1_len,
    spake2p_prover_t **out_prover,
    uint8_t *share_p_out, size_t share_p_cap);

/* Checks shareV (65) and confirmV (32); on success writes confirmP (32) and the shared key (32).
 * CONSUMES `prover` whether it succeeds or fails. NULL prover: SPAKE2P_ERR_NULL_POINTER. */
spake2p_status_t spake2p_prover_finish(
    spake2p_prover_t *prover,
    const uint8_t *share_v, size_t share_v_len,
    const uint8_t *confirm_v, size_t confirm_v_len,
    uint8_t *confirm_p_out, size_t confirm_p_cap,
    uint8_t *key_out, size_t key_cap);

/* Frees (and zeroises) a Prover that was never finished. NULL is a no-op. */
void spake2p_prover_free(spake2p_prover_t *prover);

/* Verifier ---------------------------------------------------------------------------------- */

/* Answers shareP (65). w0: 32 bytes; l: 65 bytes. Writes shareV (65) and confirmV (32) and sets
 * *out_verifier (NULL on failure). */
spake2p_status_t spake2p_verifier_respond(
    const uint8_t *context, size_t context_len,
    const uint8_t *id_prover, size_t id_prover_len,
    const uint8_t *id_verifier, size_t id_verifier_len,
    const uint8_t *w0, size_t w0_len,
    const uint8_t *l, size_t l_len,
    const uint8_t *share_p, size_t share_p_len,
    spake2p_verifier_t **out_verifier,
    uint8_t *share_v_out, size_t share_v_cap,
    uint8_t *confirm_v_out, size_t confirm_v_cap);

/* Checks confirmP (32); on success writes the shared key (32). CONSUMES `verifier` whether it succeeds
 * or fails. NULL verifier: SPAKE2P_ERR_NULL_POINTER. */
spake2p_status_t spake2p_verifier_finish(
    spake2p_verifier_t *verifier,
    const uint8_t *confirm_p, size_t confirm_p_len,
    uint8_t *key_out, size_t key_cap);

/* Frees (and zeroises) a Verifier that was never finished. NULL is a no-op. */
void spake2p_verifier_free(spake2p_verifier_t *verifier);

/* The PBKDF output length spake2p_w0w1_from_pbkdf_output requires (80). */
size_t spake2p_pbkdf_output_len(void);

#ifdef __cplusplus
}
#endif

#endif /* SPAKE2P_H */
