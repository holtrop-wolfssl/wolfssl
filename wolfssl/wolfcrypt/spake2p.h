/* spake2p.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*!
    \file wolfssl/wolfcrypt/spake2p.h

    SPAKE2+ augmented password-authenticated key exchange (RFC 9383).

    Roles:
      Prover   (client) - holds w0 and w1.
      Verifier (server) - holds the registration record (w0, L = w1*P).

    Message flow:
      Prover                                   Verifier
      shareP = x*P + w0*M          ------>
                                   <------     shareV = y*P + w0*N, confirmV
      confirmP                     ------>
      both sides: K_shared

    Call sequence (either role):
      wc_Spake2pInit()
      [wc_Spake2pSetContext()]
      [wc_Spake2pSetIdentities()]
      wc_Spake2pSetProverSecrets() or wc_Spake2pSetVerifierSecrets()
      wc_Spake2pGenerateShare()
      wc_Spake2pProcessPeerShare()
      wc_Spake2pVerifyPeerConfirm()
      wc_Spake2pGetSharedKey()
      wc_Spake2pFree()

    Calls made out of order return BAD_STATE_E. The shared key cannot be
    retrieved until the peer's confirmation MAC has been verified.
*/

#ifndef WOLFCRYPT_SPAKE2P_H
#define WOLFCRYPT_SPAKE2P_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_HAVE_SPAKE2P

#ifndef HAVE_ECC
    #error "SPAKE2+ requires ECC (HAVE_ECC)"
#endif
#ifndef HAVE_HKDF
    #error "SPAKE2+ requires HKDF (HAVE_HKDF)"
#endif
#ifdef NO_SHA256
    #error "SPAKE2+ requires SHA-256"
#endif

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Constants                                                                 */
/* ------------------------------------------------------------------------- */

/* Roles. */
enum {
    WC_SPAKE2P_PROVER   = 0,
    WC_SPAKE2P_VERIFIER = 1
};

/* RFC 9383 ciphersuites: group / hash / KDF / MAC.
 * Values are stable regardless of build configuration; a suite whose
 * primitives are not compiled in is rejected with NOT_COMPILED_IN. */
enum {
    WC_SPAKE2P_P256_SHA256_HKDF_HMAC        = 1,
    WC_SPAKE2P_P256_SHA512_HKDF_HMAC        = 2,
    WC_SPAKE2P_P384_SHA256_HKDF_HMAC        = 3,
    WC_SPAKE2P_P384_SHA512_HKDF_HMAC        = 4,
    WC_SPAKE2P_P521_SHA512_HKDF_HMAC        = 5,
    WC_SPAKE2P_P256_SHA256_HKDF_CMAC_AES128 = 6
    /* edwards25519 / edwards448 suites: reserved for future use. */
};

/* Largest scalar (w0, w1, x, y) for any enabled curve. */
#define WC_SPAKE2P_MAX_SCALAR_SZ   MAX_ECC_BYTES

/* Largest encoded point (shareP, shareV, L): SEC1 uncompressed. */
#define WC_SPAKE2P_MAX_POINT_SZ    (1 + 2 * MAX_ECC_BYTES)
#define WC_SPAKE2P_MAX_SHARE_SZ    WC_SPAKE2P_MAX_POINT_SZ
#define WC_SPAKE2P_MAX_L_SZ        WC_SPAKE2P_MAX_POINT_SZ

/* Largest hash output among supported suites. */
#ifdef WOLFSSL_SHA512
    #define WC_SPAKE2P_MAX_HASH_SZ WC_SHA512_DIGEST_SIZE
#else
    #define WC_SPAKE2P_MAX_HASH_SZ WC_SHA256_DIGEST_SIZE
#endif

/* Largest confirmation key, confirmation MAC, and shared key. */
#define WC_SPAKE2P_MAX_CONFIRM_KEY_SZ  WC_SPAKE2P_MAX_HASH_SZ
#define WC_SPAKE2P_MAX_CONFIRM_SZ      WC_SPAKE2P_MAX_HASH_SZ
#define WC_SPAKE2P_MAX_KEY_SZ          WC_SPAKE2P_MAX_HASH_SZ

/* Internal state machine values (wc_Spake2p.state). */
enum {
    WC_SPAKE2P_STATE_INIT      = 0, /* Init done; secrets not yet set.     */
    WC_SPAKE2P_STATE_SECRETS   = 1, /* Long-term secrets loaded.           */
    WC_SPAKE2P_STATE_SHARE     = 2, /* Own share generated.                */
    WC_SPAKE2P_STATE_KEYS      = 3, /* Peer share processed, keys derived. */
    WC_SPAKE2P_STATE_CONFIRMED = 4, /* Peer confirmation verified.         */
    WC_SPAKE2P_STATE_FAILED    = 5  /* Error occurred; context unusable.   */
};

/* ------------------------------------------------------------------------- */
/* Context                                                                   */
/* ------------------------------------------------------------------------- */

/* Defined here so the context can be allocated on the stack. Treat all
 * fields as private; use the API functions below. */
typedef struct wc_Spake2p {
    void*  heap;                    /* Heap hint.                            */
    int    devId;                   /* Device id for crypto callbacks.       */
    byte   suite;                   /* WC_SPAKE2P_<suite>.                   */
    byte   role;                    /* WC_SPAKE2P_PROVER or _VERIFIER.       */
    byte   state;                   /* WC_SPAKE2P_STATE_*.                   */
#ifdef WOLFSSL_SPAKE2P_TEST_HOOKS
    byte   ephSet;                  /* Ephemeral scalar fixed for testing.   */
#endif

    /* Transcript inputs (owned copies, may be NULL with size 0). */
    byte*  context;
    word32 contextSz;
    byte*  idProver;
    word32 idProverSz;
    byte*  idVerifier;
    word32 idVerifierSz;

    /* Long-term secrets. */
    byte   w0[WC_SPAKE2P_MAX_SCALAR_SZ];
    word32 w0Sz;
    union {
        byte w1[WC_SPAKE2P_MAX_SCALAR_SZ]; /* Prover.                       */
        byte L[WC_SPAKE2P_MAX_L_SZ];       /* Verifier, encoded point.      */
    } sec;
    word32 secSz;

    /* Ephemeral scalar: x (Prover) or y (Verifier). */
    byte   eph[WC_SPAKE2P_MAX_SCALAR_SZ];
    word32 ephSz;

    /* Encoded shares, kept for the transcript and confirmation MACs. */
    byte   share[WC_SPAKE2P_MAX_SHARE_SZ];
    word32 shareSz;
    byte   peerShare[WC_SPAKE2P_MAX_SHARE_SZ];
    word32 peerShareSz;

    /* Derived keys. */
    byte   kConfirmP[WC_SPAKE2P_MAX_CONFIRM_KEY_SZ];
    byte   kConfirmV[WC_SPAKE2P_MAX_CONFIRM_KEY_SZ];
    word32 kConfirmSz;
    byte   kShared[WC_SPAKE2P_MAX_KEY_SZ];
    word32 kSharedSz;
} wc_Spake2p;

/* ------------------------------------------------------------------------- */
/* Registration (offline)                                                    */
/* ------------------------------------------------------------------------- */

WOLFSSL_API int wc_Spake2pDeriveW0W1(int suite,
    const byte* w0s, word32 w0sSz, const byte* w1s, word32 w1sSz,
    byte* w0, word32* w0Sz, byte* w1, word32* w1Sz, void* heap);

WOLFSSL_API int wc_Spake2pComputeL(int suite, const byte* w1, word32 w1Sz,
    byte* L, word32* LSz, void* heap, int devId);

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                 */
/* ------------------------------------------------------------------------- */

WOLFSSL_API int wc_Spake2pInit(wc_Spake2p* ctx, int suite, int role,
    void* heap, int devId);

WOLFSSL_API void wc_Spake2pFree(wc_Spake2p* ctx);

#ifndef WC_NO_CONSTRUCTORS
WOLFSSL_API wc_Spake2p* wc_Spake2pNew(int suite, int role, void* heap,
    int devId, int* result_code);

WOLFSSL_API int wc_Spake2pDelete(wc_Spake2p* ctx, wc_Spake2p** ctx_p);
#endif

/* ------------------------------------------------------------------------- */
/* Transcript inputs (optional; call before wc_Spake2pGenerateShare)         */
/* ------------------------------------------------------------------------- */

WOLFSSL_API int wc_Spake2pSetContext(wc_Spake2p* ctx,
    const byte* context, word32 contextSz);

WOLFSSL_API int wc_Spake2pSetIdentities(wc_Spake2p* ctx,
    const byte* idProver, word32 idProverSz,
    const byte* idVerifier, word32 idVerifierSz);

/* ------------------------------------------------------------------------- */
/* Long-term secrets (exactly one call, matching the role)                   */
/* ------------------------------------------------------------------------- */

WOLFSSL_API int wc_Spake2pSetProverSecrets(wc_Spake2p* ctx,
    const byte* w0, word32 w0Sz, const byte* w1, word32 w1Sz);

WOLFSSL_API int wc_Spake2pSetVerifierSecrets(wc_Spake2p* ctx,
    const byte* w0, word32 w0Sz, const byte* L, word32 LSz);

/* ------------------------------------------------------------------------- */
/* Online exchange                                                           */
/* ------------------------------------------------------------------------- */

WOLFSSL_API int wc_Spake2pGenerateShare(wc_Spake2p* ctx, WC_RNG* rng,
    byte* share, word32* shareSz);

WOLFSSL_API int wc_Spake2pProcessPeerShare(wc_Spake2p* ctx,
    const byte* peerShare, word32 peerShareSz,
    byte* confirm, word32* confirmSz);

WOLFSSL_API int wc_Spake2pVerifyPeerConfirm(wc_Spake2p* ctx,
    const byte* peerConfirm, word32 peerConfirmSz);

WOLFSSL_API int wc_Spake2pGetSharedKey(wc_Spake2p* ctx,
    byte* key, word32* keySz);

/* ------------------------------------------------------------------------- */
/* Test hooks                                                                */
/* ------------------------------------------------------------------------- */

#ifdef WOLFSSL_SPAKE2P_TEST_HOOKS
WOLFSSL_API int wc_Spake2pSetEphemeral(wc_Spake2p* ctx,
    const byte* scalar, word32 scalarSz);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_HAVE_SPAKE2P */
#endif /* WOLFCRYPT_SPAKE2P_H */
