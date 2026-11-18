/* spake2p.c
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

/* SPAKE2+ (RFC 9383) augmented PAKE. API: wolfssl/wolfcrypt/spake2p.h
 *
 * Implemented so far: wc_Spake2pDeriveW0W1(), wc_Spake2pComputeL(),
 * wc_Spake2pInit(), wc_Spake2pFree(), wc_Spake2pNew(), wc_Spake2pDelete(),
 * wc_Spake2pSetContext(), wc_Spake2pSetIdentities(),
 * wc_Spake2pSetProverSecrets(), wc_Spake2pSetVerifierSecrets(),
 * wc_Spake2pGenerateShare(), wc_Spake2pProcessPeerShare(),
 * wc_Spake2pVerifyPeerConfirm(), wc_Spake2pGetSharedKey(),
 * wc_Spake2pSetEphemeral() (test hooks only).
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_HAVE_SPAKE2P

#include <wolfssl/wolfcrypt/spake2p.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#ifdef WOLFSSL_CMAC
    #include <wolfssl/wolfcrypt/cmac.h>
#endif
#ifdef WOLFSSL_HAVE_SP_ECC
    #include <wolfssl/wolfcrypt/sp.h>
#endif

/* Whether the ephemeral scalar was fixed with wc_Spake2pSetEphemeral(). The
 * field only exists in test-hook builds; everywhere else this is the constant
 * 0, so the fixed-ephemeral code is compiled out of production builds. */
#ifdef WOLFSSL_SPAKE2P_TEST_HOOKS
    #define SPAKE2P_EPH_FIXED(ctx)  ((ctx)->ephSet)
#else
    #define SPAKE2P_EPH_FIXED(ctx)  0
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* ------------------------------------------------------------------------- */
/* Suite parameters                                                          */
/* ------------------------------------------------------------------------- */

/* Get the ECC curve used by a ciphersuite.
 *
 * @param  [in]   suite    WC_SPAKE2P_<suite>.
 * @param  [out]  curveId  ECC curve id (ECC_SECP256R1, ...).
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when suite is not a known ciphersuite.
 */
static int spake2p_suite_curve(int suite, int* curveId)
{
    int ret = 0;

    switch (suite) {
        case WC_SPAKE2P_P256_SHA256_HKDF_HMAC:
        case WC_SPAKE2P_P256_SHA512_HKDF_HMAC:
        case WC_SPAKE2P_P256_SHA256_HKDF_CMAC_AES128:
            *curveId = ECC_SECP256R1;
            break;
        case WC_SPAKE2P_P384_SHA256_HKDF_HMAC:
        case WC_SPAKE2P_P384_SHA512_HKDF_HMAC:
            *curveId = ECC_SECP384R1;
            break;
        case WC_SPAKE2P_P521_SHA512_HKDF_HMAC:
            *curveId = ECC_SECP521R1;
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}

/* Check that a ciphersuite is known and that its curve, hash and MAC are all
 * compiled in.
 *
 * @param  [in]  suite  WC_SPAKE2P_<suite>.
 * @return  0 when the suite can be used.
 * @return  BAD_FUNC_ARG when suite is not a known ciphersuite.
 * @return  NOT_COMPILED_IN when the suite's curve, hash or MAC is not
 *          compiled in.
 */
static int spake2p_suite_supported(int suite)
{
    int ret;
    int curveId = 0;

    ret = spake2p_suite_curve(suite, &curveId);
    if ((ret == 0) && (wc_ecc_get_curve_idx(curveId) < 0)) {
        ret = NOT_COMPILED_IN;
    }
    if (ret == 0) {
        switch (suite) {
            /* HMAC is always present: spake2p.h requires it for HKDF. */
            case WC_SPAKE2P_P256_SHA256_HKDF_HMAC:
            case WC_SPAKE2P_P384_SHA256_HKDF_HMAC:
                break;
            case WC_SPAKE2P_P256_SHA512_HKDF_HMAC:
            case WC_SPAKE2P_P384_SHA512_HKDF_HMAC:
            case WC_SPAKE2P_P521_SHA512_HKDF_HMAC:
        #ifndef WOLFSSL_SHA512
                ret = NOT_COMPILED_IN;
        #endif
                break;
            case WC_SPAKE2P_P256_SHA256_HKDF_CMAC_AES128:
        #if !defined(WOLFSSL_CMAC) || defined(NO_AES) || \
            !defined(WOLFSSL_AES_128)
                ret = NOT_COMPILED_IN;
        #endif
                break;
            default:
                ret = BAD_FUNC_ARG;
                break;
        }
    }

    return ret;
}

/* Load the group order of a ciphersuite's curve.
 *
 * @param  [in]   suite    WC_SPAKE2P_<suite>.
 * @param  [out]  order    Initialized mp_int that receives the order.
 * @param  [out]  orderSz  Length of the order in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when suite is not a known ciphersuite.
 * @return  NOT_COMPILED_IN when the suite's curve is not compiled in.
 * @return  Other negative value on math error.
 */
static int spake2p_load_order(int suite, mp_int* order, word32* orderSz)
{
    int ret;
    int curveId = 0;
    int idx;
    const ecc_set_type* dp = NULL;

    ret = spake2p_suite_curve(suite, &curveId);
    if (ret == 0) {
        idx = wc_ecc_get_curve_idx(curveId);
        if (idx >= 0) {
            dp = wc_ecc_get_curve_params(idx);
        }
        if (dp == NULL) {
            ret = NOT_COMPILED_IN;
        }
    }
    if (ret == 0) {
        ret = mp_read_radix(order, dp->order, MP_RADIX_HEX);
    }
    if (ret == 0) {
        *orderSz = (word32)mp_unsigned_bin_size(order);
    }

    return ret;
}

/* ------------------------------------------------------------------------- */
/* Registration (offline)                                                    */
/* ------------------------------------------------------------------------- */

/* Reduce a big-endian byte string modulo the group order.
 *
 * out = in mod order, written big-endian and zero-padded to orderSz bytes.
 *
 * @param  [in]   in       Big-endian integer.
 * @param  [in]   inSz     Length of in in bytes.
 * @param  [in]   order    Group order.
 * @param  [in]   orderSz  Length of the order in bytes.
 * @param  [in]   t        Initialized temporary; zeroized before return.
 * @param  [out]  out      Buffer of at least orderSz bytes.
 * @return  0 on success.
 * @return  Negative value on math error.
 */
static int spake2p_reduce(const byte* in, word32 inSz, mp_int* order,
    word32 orderSz, mp_int* t, byte* out)
{
    int ret;

    ret = mp_read_unsigned_bin(t, in, inSz);
    if (ret == 0) {
        ret = mp_mod(t, order, t);
    }
    if (ret == 0) {
        ret = mp_to_unsigned_bin_len(t, out, (int)orderSz);
    }
    mp_forcezero(t);

    return ret;
}

/* Derive w0 and w1 from the two halves of a PBKDF output (RFC 9383,
 * Section 3.2):
 *   w0 = w0s mod p,  w1 = w1s mod p
 * where p is the group order of the suite's curve.
 *
 * Each input must be at least as long as the group order and at most twice
 * as long. RFC 9383 recommends (group order length + 8) bytes so the
 * reduction has negligible bias.
 *
 * @param  [in]       suite  WC_SPAKE2P_<suite>.
 * @param  [in]       w0s    First half of the PBKDF output.
 * @param  [in]       w0sSz  Length of w0s in bytes.
 * @param  [in]       w1s    Second half of the PBKDF output.
 * @param  [in]       w1sSz  Length of w1s in bytes.
 * @param  [out]      w0     Buffer that receives w0.
 * @param  [in, out]  w0Sz   On in, size of w0. On out, bytes written.
 * @param  [out]      w1     Buffer that receives w1.
 * @param  [in, out]  w1Sz   On in, size of w1. On out, bytes written.
 * @param  [in]       heap   Heap hint for temporary allocations.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a pointer is NULL, the suite is unknown, or
 *          w0sSz or w1sSz is outside [order length, 2 * order length].
 * @return  BUFFER_E when *w0Sz or *w1Sz is smaller than the order length.
 * @return  NOT_COMPILED_IN when the suite's curve is not compiled in.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative value on math error.
 */
int wc_Spake2pDeriveW0W1(int suite,
    const byte* w0s, word32 w0sSz, const byte* w1s, word32 w1sSz,
    byte* w0, word32* w0Sz, byte* w1, word32* w1Sz, void* heap)
{
    int ret = 0;
    int curveId = 0;
    int initDone = 0;
    int outWritten = 0;
    word32 orderSz = 0;
    WC_DECLARE_VAR(order, mp_int, 1, heap);
    WC_DECLARE_VAR(t, mp_int, 1, heap);

    (void)heap;

    if ((w0s == NULL) || (w1s == NULL) || (w0 == NULL) || (w0Sz == NULL) ||
            (w1 == NULL) || (w1Sz == NULL)) {
        return BAD_FUNC_ARG;
    }
    /* Reject an unknown suite before allocating. */
    ret = spake2p_suite_curve(suite, &curveId);
    if (ret != 0) {
        return ret;
    }

    WC_ALLOC_VAR_EX(order, mp_int, 1, heap, DYNAMIC_TYPE_ECC,
        ret = MEMORY_E);
    if (ret == 0) {
        WC_ALLOC_VAR_EX(t, mp_int, 1, heap, DYNAMIC_TYPE_ECC,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        ret = mp_init_multi(order, t, NULL, NULL, NULL, NULL);
        if (ret == 0) {
            initDone = 1;
        }
    }

    if (ret == 0) {
        ret = spake2p_load_order(suite, order, &orderSz);
    }
    if ((ret == 0) && ((w0sSz < orderSz) || (w0sSz > 2 * orderSz) ||
            (w1sSz < orderSz) || (w1sSz > 2 * orderSz))) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && ((*w0Sz < orderSz) || (*w1Sz < orderSz))) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        outWritten = 1;
        ret = spake2p_reduce(w0s, w0sSz, order, orderSz, t, w0);
    }
    if (ret == 0) {
        ret = spake2p_reduce(w1s, w1sSz, order, orderSz, t, w1);
    }
    if (ret == 0) {
        *w0Sz = orderSz;
        *w1Sz = orderSz;
    }
    else if (outWritten) {
        /* Don't leave a partial result in the output buffers. */
        ForceZero(w0, orderSz);
        ForceZero(w1, orderSz);
    }

    if (initDone) {
        mp_forcezero(t);
        mp_clear(order);
    }
    WC_FREE_VAR_EX(t, heap, DYNAMIC_TYPE_ECC);
    WC_FREE_VAR_EX(order, heap, DYNAMIC_TYPE_ECC);

    return ret;
}

/* Check that a scalar is a valid private value for the suite's curve: exactly
 * the group order length, and in [1, order - 1].
 *
 * @param  [in]  suite     WC_SPAKE2P_<suite>.
 * @param  [in]  scalar    Big-endian scalar.
 * @param  [in]  scalarSz  Length of scalar in bytes.
 * @param  [in]  heap      Heap hint for temporary allocations.
 * @return  0 when the scalar is valid.
 * @return  BAD_FUNC_ARG when the suite is unknown or the scalar is invalid.
 * @return  NOT_COMPILED_IN when the suite's curve is not compiled in.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative value on math error.
 */
static int spake2p_check_scalar(int suite, const byte* scalar,
    word32 scalarSz, void* heap)
{
    int ret = 0;
    int initDone = 0;
    word32 orderSz = 0;
    WC_DECLARE_VAR(order, mp_int, 1, heap);
    WC_DECLARE_VAR(t, mp_int, 1, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(order, mp_int, 1, heap, DYNAMIC_TYPE_ECC,
        ret = MEMORY_E);
    if (ret == 0) {
        WC_ALLOC_VAR_EX(t, mp_int, 1, heap, DYNAMIC_TYPE_ECC,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        ret = mp_init_multi(order, t, NULL, NULL, NULL, NULL);
        if (ret == 0) {
            initDone = 1;
        }
    }

    if (ret == 0) {
        ret = spake2p_load_order(suite, order, &orderSz);
    }
    if ((ret == 0) && (scalarSz != orderSz)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(t, scalar, scalarSz);
    }
    if ((ret == 0) && (mp_iszero(t) || (mp_cmp(t, order) != MP_LT))) {
        ret = BAD_FUNC_ARG;
    }

    if (initDone) {
        mp_forcezero(t);
        mp_clear(order);
    }
    WC_FREE_VAR_EX(t, heap, DYNAMIC_TYPE_ECC);
    WC_FREE_VAR_EX(order, heap, DYNAMIC_TYPE_ECC);

    return ret;
}

/* Compute the Verifier's registration value L = w1 * P (RFC 9383,
 * Section 3.2), where P is the generator of the suite's curve, encoded as a
 * SEC1 uncompressed point (0x04 || X || Y).
 *
 * The scalar multiplication is done by wc_ecc_make_pub(), so it uses the
 * library's timing-resistant implementation, or a crypto callback device
 * when devId is set.
 *
 * @param  [in]       suite  WC_SPAKE2P_<suite>.
 * @param  [in]       w1     w1 scalar, as output by wc_Spake2pDeriveW0W1().
 * @param  [in]       w1Sz   Length of w1 in bytes (the group order length).
 * @param  [out]      L      Buffer that receives the encoded point.
 * @param  [in, out]  LSz    On in, size of L. On out, bytes written.
 * @param  [in]       heap   Heap hint for temporary allocations.
 * @param  [in]       devId  Device id for crypto callbacks, or
 *                           INVALID_DEVID.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a pointer is NULL, the suite is unknown, or w1
 *          is not a valid scalar (wrong length, zero, or not less than the
 *          group order).
 * @return  BUFFER_E when *LSz is too small for the encoded point.
 * @return  NOT_COMPILED_IN when the suite's curve, or ECC key import/export,
 *          is not compiled in.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative value on ECC or math error.
 */
int wc_Spake2pComputeL(int suite, const byte* w1, word32 w1Sz,
    byte* L, word32* LSz, void* heap, int devId)
{
#if defined(HAVE_ECC_KEY_IMPORT) && defined(HAVE_ECC_KEY_EXPORT)
    int ret;
    int curveId = 0;
    int curveSz = 0;
    int keyInit = 0;
    WC_DECLARE_VAR(key, ecc_key, 1, heap);

    (void)heap;

    if ((w1 == NULL) || (L == NULL) || (LSz == NULL)) {
        return BAD_FUNC_ARG;
    }
    ret = spake2p_suite_curve(suite, &curveId);
    if (ret != 0) {
        return ret;
    }

    /* Check the curve is compiled in, w1 is exactly the order length, and w1
     * is in [1, order - 1]. wc_ecc_import_private_key_ex() below also range
     * checks, but returns ECC_PRIV_KEY_E rather than the documented
     * BAD_FUNC_ARG, and accepts any length (on CAAM, curve size + MAC length
     * is taken as an encrypted black key). Checking first also fails before
     * the ECC key is allocated. */
    ret = spake2p_check_scalar(suite, w1, w1Sz, heap);
    if (ret == 0) {
        curveSz = wc_ecc_get_curve_size_from_id(curveId);
        if (curveSz <= 0) {
            ret = NOT_COMPILED_IN;
        }
    }
    if ((ret == 0) && (*LSz < (word32)(1 + 2 * curveSz))) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        WC_ALLOC_VAR_EX(key, ecc_key, 1, heap, DYNAMIC_TYPE_ECC,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        ret = wc_ecc_init_ex(key, heap, devId);
        if (ret == 0) {
            keyInit = 1;
        }
    }
    if (ret == 0) {
        ret = wc_ecc_import_private_key_ex(w1, w1Sz, NULL, 0, key, curveId);
    }
    if (ret == 0) {
        /* No output point: the public part is cached in the key. */
        ret = wc_ecc_make_pub(key, NULL);
    }
    if (ret == 0) {
        ret = wc_ecc_export_x963(key, L, LSz);
    }

    if (keyInit) {
        /* Zeroizes the private scalar. */
        wc_ecc_free(key);
    }
    WC_FREE_VAR_EX(key, heap, DYNAMIC_TYPE_ECC);

    return ret;
#else
    (void)suite;
    (void)w1;
    (void)w1Sz;
    (void)L;
    (void)LSz;
    (void)heap;
    (void)devId;

    return NOT_COMPILED_IN;
#endif /* HAVE_ECC_KEY_IMPORT && HAVE_ECC_KEY_EXPORT */
}

/* ------------------------------------------------------------------------- */
/* Owned buffers                                                             */
/* ------------------------------------------------------------------------- */

/* Make an owned copy of a byte string. An empty string is stored as NULL.
 *
 * @param  [in]   heap   Heap hint.
 * @param  [in]   src    Data to copy; may be NULL when srcSz is 0.
 * @param  [in]   srcSz  Length of src in bytes.
 * @param  [out]  out    Receives the copy, or NULL when srcSz is 0.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int spake2p_dup(void* heap, const byte* src, word32 srcSz, byte** out)
{
    *out = NULL;
    if (srcSz == 0) {
        return 0;
    }
    *out = (byte*)XMALLOC(srcSz, heap, DYNAMIC_TYPE_SPAKE2P);
    if (*out == NULL) {
        return MEMORY_E;
    }
    XMEMCPY(*out, src, srcSz);
    (void)heap;

    return 0;
}

/* Zeroize and free an owned copy made by spake2p_dup(). NULL is a no-op.
 *
 * @param  [in]  heap  Heap hint used for the allocation.
 * @param  [in]  buf   Buffer to free, or NULL.
 * @param  [in]  sz    Length of buf in bytes.
 */
static void spake2p_free_buf(void* heap, byte* buf, word32 sz)
{
    if (buf != NULL) {
        ForceZero(buf, sz);
        XFREE(buf, heap, DYNAMIC_TYPE_SPAKE2P);
    }
    (void)heap;
}

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                 */
/* ------------------------------------------------------------------------- */

/* Initialize a context for one protocol run.
 *
 * Any previous contents of ctx are discarded without being freed; call
 * wc_Spake2pFree() first when reusing a context. ctx is zeroed before the
 * arguments are checked, so wc_Spake2pFree() is safe to call on it even if
 * this function fails.
 *
 * @param  [out]  ctx    Context to initialize.
 * @param  [in]   suite  WC_SPAKE2P_<suite>.
 * @param  [in]   role   WC_SPAKE2P_PROVER or WC_SPAKE2P_VERIFIER.
 * @param  [in]   heap   Heap hint for allocations made by the context.
 * @param  [in]   devId  Device id for crypto callbacks, or INVALID_DEVID.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ctx is NULL, or suite or role is unknown.
 * @return  NOT_COMPILED_IN when the suite's curve, hash or MAC is not
 *          compiled in.
 */
int wc_Spake2pInit(wc_Spake2p* ctx, int suite, int role, void* heap, int devId)
{
    int ret;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(ctx, 0, sizeof(*ctx));

    if ((role != WC_SPAKE2P_PROVER) && (role != WC_SPAKE2P_VERIFIER)) {
        return BAD_FUNC_ARG;
    }
    ret = spake2p_suite_supported(suite);
    if (ret != 0) {
        return ret;
    }

    ctx->heap  = heap;
    ctx->devId = devId;
    ctx->suite = (byte)suite;
    ctx->role  = (byte)role;
    ctx->state = WC_SPAKE2P_STATE_INIT;

    return 0;
}

/* Release resources held by a context and zeroize it.
 *
 * Frees the owned copies of the context string and identities, then
 * zeroizes the whole structure: w0, w1 or L, the ephemeral scalar, the
 * shares and all derived keys. The structure itself is not freed. Safe to
 * call with NULL, and safe to call more than once.
 *
 * @param  [in, out]  ctx  Context to free.
 */
void wc_Spake2pFree(wc_Spake2p* ctx)
{
    if (ctx == NULL) {
        return;
    }

    /* Owned copies made by wc_Spake2pSetContext() and
     * wc_Spake2pSetIdentities(). Not secret, but zeroed with everything
     * else. */
    spake2p_free_buf(ctx->heap, ctx->context, ctx->contextSz);
    spake2p_free_buf(ctx->heap, ctx->idProver, ctx->idProverSz);
    spake2p_free_buf(ctx->heap, ctx->idVerifier, ctx->idVerifierSz);

    /* Zeroizes all secrets and leaves every pointer NULL, so a second call
     * is a no-op. */
    ForceZero(ctx, sizeof(*ctx));
}

#ifndef WC_NO_CONSTRUCTORS
/* Allocate and initialize a context.
 *
 * @param  [in]   suite        WC_SPAKE2P_<suite>.
 * @param  [in]   role         WC_SPAKE2P_PROVER or WC_SPAKE2P_VERIFIER.
 * @param  [in]   heap         Heap hint for the allocation and the context.
 * @param  [in]   devId        Device id for crypto callbacks, or
 *                             INVALID_DEVID.
 * @param  [out]  result_code  Optional; receives 0 on success or the error.
 * @return  New context on success.
 * @return  NULL on failure: MEMORY_E, or an error from wc_Spake2pInit().
 */
wc_Spake2p* wc_Spake2pNew(int suite, int role, void* heap, int devId,
    int* result_code)
{
    int ret;
    wc_Spake2p* ctx;

    ctx = (wc_Spake2p*)XMALLOC(sizeof(wc_Spake2p), heap,
        DYNAMIC_TYPE_SPAKE2P);
    if (ctx == NULL) {
        ret = MEMORY_E;
    }
    else {
        ret = wc_Spake2pInit(ctx, suite, role, heap, devId);
        if (ret != 0) {
            XFREE(ctx, heap, DYNAMIC_TYPE_SPAKE2P);
            ctx = NULL;
        }
    }

    if (result_code != NULL) {
        *result_code = ret;
    }

    return ctx;
}

/* Free a context allocated with wc_Spake2pNew().
 *
 * @param  [in]   ctx    Context to free.
 * @param  [out]  ctx_p  Optional; *ctx_p is set to NULL on success.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wc_Spake2pDelete(wc_Spake2p* ctx, wc_Spake2p** ctx_p)
{
    void* heap;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    /* wc_Spake2pFree() zeroizes the heap hint along with everything else. */
    heap = ctx->heap;
    (void)heap;

    wc_Spake2pFree(ctx);
    XFREE(ctx, heap, DYNAMIC_TYPE_SPAKE2P);
    if (ctx_p != NULL) {
        *ctx_p = NULL;
    }

    return 0;
}
#endif /* !WC_NO_CONSTRUCTORS */

/* ------------------------------------------------------------------------- */
/* Transcript inputs                                                         */
/* ------------------------------------------------------------------------- */

/* Check that the transcript inputs can still be changed: only before this
 * side's share has been generated.
 *
 * @param  [in]  ctx  Context.
 * @return  1 when the context and identities may be set, 0 otherwise.
 */
static int spake2p_transcript_settable(const wc_Spake2p* ctx)
{
    return (ctx->state == WC_SPAKE2P_STATE_INIT) ||
           (ctx->state == WC_SPAKE2P_STATE_SECRETS);
}

/* Set the application context string bound into the transcript.
 *
 * The data is copied. Calling again replaces the previous value; on error
 * the previous value is left unchanged.
 *
 * @param  [in, out]  ctx        Initialized context.
 * @param  [in]       context    Context bytes; may be NULL when contextSz
 *                               is 0.
 * @param  [in]       contextSz  Length of context in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ctx is NULL, or context is NULL while contextSz
 *          is not 0.
 * @return  BAD_STATE_E when called after wc_Spake2pGenerateShare().
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int wc_Spake2pSetContext(wc_Spake2p* ctx, const byte* context,
    word32 contextSz)
{
    int ret;
    byte* copy = NULL;

    if ((ctx == NULL) || ((context == NULL) && (contextSz != 0))) {
        return BAD_FUNC_ARG;
    }
    if (!spake2p_transcript_settable(ctx)) {
        return BAD_STATE_E;
    }

    /* Copy before freeing the old value: keeps it on failure, and is safe if
     * context points into the current copy. */
    ret = spake2p_dup(ctx->heap, context, contextSz, &copy);
    if (ret == 0) {
        spake2p_free_buf(ctx->heap, ctx->context, ctx->contextSz);
        ctx->context = copy;
        ctx->contextSz = contextSz;
    }

    return ret;
}

/* Set the Prover and Verifier identities bound into the transcript.
 *
 * Both are copied. Calling again replaces both previous values; on error
 * neither previous value is changed.
 *
 * @param  [in, out]  ctx           Initialized context.
 * @param  [in]       idProver      Prover identity; may be NULL when
 *                                  idProverSz is 0.
 * @param  [in]       idProverSz    Length of idProver in bytes.
 * @param  [in]       idVerifier    Verifier identity; may be NULL when
 *                                  idVerifierSz is 0.
 * @param  [in]       idVerifierSz  Length of idVerifier in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ctx is NULL, or an identity is NULL while its
 *          size is not 0.
 * @return  BAD_STATE_E when called after wc_Spake2pGenerateShare().
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int wc_Spake2pSetIdentities(wc_Spake2p* ctx,
    const byte* idProver, word32 idProverSz,
    const byte* idVerifier, word32 idVerifierSz)
{
    int ret;
    byte* copyP = NULL;
    byte* copyV = NULL;

    if ((ctx == NULL) || ((idProver == NULL) && (idProverSz != 0)) ||
            ((idVerifier == NULL) && (idVerifierSz != 0))) {
        return BAD_FUNC_ARG;
    }
    if (!spake2p_transcript_settable(ctx)) {
        return BAD_STATE_E;
    }

    /* Make both copies before replacing either value, so a failure leaves
     * the identities exactly as they were. */
    ret = spake2p_dup(ctx->heap, idProver, idProverSz, &copyP);
    if (ret == 0) {
        ret = spake2p_dup(ctx->heap, idVerifier, idVerifierSz, &copyV);
        if (ret != 0) {
            spake2p_free_buf(ctx->heap, copyP, idProverSz);
        }
    }
    if (ret == 0) {
        spake2p_free_buf(ctx->heap, ctx->idProver, ctx->idProverSz);
        spake2p_free_buf(ctx->heap, ctx->idVerifier, ctx->idVerifierSz);
        ctx->idProver = copyP;
        ctx->idProverSz = idProverSz;
        ctx->idVerifier = copyV;
        ctx->idVerifierSz = idVerifierSz;
    }

    return ret;
}

/* ------------------------------------------------------------------------- */
/* Long-term secrets                                                         */
/* ------------------------------------------------------------------------- */

/* Load the Prover's secrets w0 and w1.
 *
 * Both must be exactly the group order length and in [1, order - 1]. They
 * are copied into the context. On error the context is unchanged and still
 * usable.
 *
 * @param  [in, out]  ctx   Context initialized as WC_SPAKE2P_PROVER.
 * @param  [in]       w0    w0 scalar.
 * @param  [in]       w0Sz  Length of w0 in bytes.
 * @param  [in]       w1    w1 scalar.
 * @param  [in]       w1Sz  Length of w1 in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a pointer is NULL, or w0 or w1 is not a valid
 *          scalar.
 * @return  BAD_STATE_E when ctx is not a Prover, or secrets are already
 *          set.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int wc_Spake2pSetProverSecrets(wc_Spake2p* ctx,
    const byte* w0, word32 w0Sz, const byte* w1, word32 w1Sz)
{
    int ret;

    if ((ctx == NULL) || (w0 == NULL) || (w1 == NULL)) {
        return BAD_FUNC_ARG;
    }
    if ((ctx->role != WC_SPAKE2P_PROVER) ||
            (ctx->state != WC_SPAKE2P_STATE_INIT)) {
        return BAD_STATE_E;
    }

    ret = spake2p_check_scalar(ctx->suite, w0, w0Sz, ctx->heap);
    if (ret == 0) {
        ret = spake2p_check_scalar(ctx->suite, w1, w1Sz, ctx->heap);
    }
    if (ret == 0) {
        /* Valid scalars are the order length, which fits these buffers. */
        XMEMCPY(ctx->w0, w0, w0Sz);
        ctx->w0Sz = w0Sz;
        XMEMCPY(ctx->sec.w1, w1, w1Sz);
        ctx->secSz = w1Sz;
        ctx->state = WC_SPAKE2P_STATE_SECRETS;
    }

    return ret;
}

#ifdef HAVE_ECC_KEY_IMPORT
/* Check that L is a SEC1 uncompressed encoding of a point on the suite's
 * curve that is not the point at infinity.
 *
 * The NIST curves used by SPAKE2+ have cofactor 1, so every point on the
 * curve other than the identity is in the prime-order group.
 *
 * @param  [in]  suite  WC_SPAKE2P_<suite>.
 * @param  [in]  L      Encoded point.
 * @param  [in]  LSz    Length of L in bytes.
 * @param  [in]  heap   Heap hint for temporary allocations.
 * @return  0 when L is valid.
 * @return  IS_POINT_E when L is malformed or not on the curve, including
 *          the SEC1 infinity encoding (single byte 0x00).
 * @return  ECC_INF_E when L is 0x04 followed by all zero bytes, the affine
 *          (0, 0) form of the point at infinity.
 * @return  BAD_FUNC_ARG when the suite is unknown.
 * @return  NOT_COMPILED_IN when the suite's curve is not compiled in.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int spake2p_check_point(int suite, const byte* L, word32 LSz,
    void* heap)
{
    int ret;
    int curveId = 0;
    int idx = -1;
    int curveSz = 0;
    ecc_point* pt = NULL;

    ret = spake2p_suite_curve(suite, &curveId);
    if (ret == 0) {
        idx = wc_ecc_get_curve_idx(curveId);
        curveSz = wc_ecc_get_curve_size_from_id(curveId);
        if ((idx < 0) || (curveSz <= 0)) {
            ret = NOT_COMPILED_IN;
        }
    }
    /* Uncompressed only: 0x04 || X || Y, each coordinate the field size. */
    if ((ret == 0) && ((LSz != (word32)(1 + 2 * curveSz)) ||
            (L[0] != ECC_POINT_UNCOMP))) {
        ret = IS_POINT_E;
    }
    if (ret == 0) {
        pt = wc_ecc_new_point_h(heap);
        if (pt == NULL) {
            ret = MEMORY_E;
        }
    }
    if ((ret == 0) && (wc_ecc_import_point_der(L, LSz, idx, pt) != 0)) {
        ret = IS_POINT_E;
    }
    /* (0, 0) is how the identity decodes; it is not on these curves, so
     * check it first to report it distinctly. */
    if ((ret == 0) && mp_iszero(pt->x) && mp_iszero(pt->y)) {
        ret = ECC_INF_E;
    }
    /* Coordinates in [0, p - 1] and the curve equation holds. */
    if ((ret == 0) && (wc_ecc_point_is_on_curve(pt, idx) != 0)) {
        ret = IS_POINT_E;
    }

    if (pt != NULL) {
        wc_ecc_del_point_h(pt, heap);
    }
    (void)heap;

    return ret;
}
#endif /* HAVE_ECC_KEY_IMPORT */

/* Load the Verifier's registration record (w0, L).
 *
 * w0 must be exactly the group order length and in [1, order - 1]. L must
 * be a SEC1 uncompressed point on the suite's curve, not the point at
 * infinity. Both are copied into the context. On error the context is
 * unchanged and still usable.
 *
 * @param  [in, out]  ctx   Context initialized as WC_SPAKE2P_VERIFIER.
 * @param  [in]       w0    w0 scalar.
 * @param  [in]       w0Sz  Length of w0 in bytes.
 * @param  [in]       L     Encoded point L = w1 * P.
 * @param  [in]       LSz   Length of L in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a pointer is NULL, or w0 is not a valid
 *          scalar.
 * @return  IS_POINT_E when L is malformed or not on the curve, including
 *          the SEC1 infinity encoding (single byte 0x00).
 * @return  ECC_INF_E when L is 0x04 followed by all zero bytes, the affine
 *          (0, 0) form of the point at infinity.
 * @return  BAD_STATE_E when ctx is not a Verifier, or secrets are already
 *          set.
 * @return  NOT_COMPILED_IN when ECC key import is not compiled in.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int wc_Spake2pSetVerifierSecrets(wc_Spake2p* ctx,
    const byte* w0, word32 w0Sz, const byte* L, word32 LSz)
{
#ifdef HAVE_ECC_KEY_IMPORT
    int ret;

    if ((ctx == NULL) || (w0 == NULL) || (L == NULL)) {
        return BAD_FUNC_ARG;
    }
    if ((ctx->role != WC_SPAKE2P_VERIFIER) ||
            (ctx->state != WC_SPAKE2P_STATE_INIT)) {
        return BAD_STATE_E;
    }

    ret = spake2p_check_scalar(ctx->suite, w0, w0Sz, ctx->heap);
    if (ret == 0) {
        ret = spake2p_check_point(ctx->suite, L, LSz, ctx->heap);
    }
    if (ret == 0) {
        /* A valid L is 1 + 2 * field size, which fits sec.L. */
        XMEMCPY(ctx->w0, w0, w0Sz);
        ctx->w0Sz = w0Sz;
        XMEMCPY(ctx->sec.L, L, LSz);
        ctx->secSz = LSz;
        ctx->state = WC_SPAKE2P_STATE_SECRETS;
    }

    return ret;
#else
    (void)ctx;
    (void)w0;
    (void)w0Sz;
    (void)L;
    (void)LSz;

    return NOT_COMPILED_IN;
#endif /* HAVE_ECC_KEY_IMPORT */
}

/* ------------------------------------------------------------------------- */
/* Online exchange                                                           */
/* ------------------------------------------------------------------------- */

/* RFC 9383, Section 4: the fixed points M and N for each curve, as affine
 * coordinates. RFC 9383 gives them as compressed SEC1 points; these are the
 * same points uncompressed, so no point decompression is needed at run time.
 *
 *   P-256 M = 02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f
 *   P-256 N = 03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49
 *   P-384 M = 030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc
 *             36f15314739074d2eb8613fceec2853
 *   P-384 N = 02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb
 *             252c5490214cf9aa3f0baab4b665c10
 *   P-521 M = 02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608
 *             cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa
 *   P-521 N = 0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b25
 *             32d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25
 */
typedef struct Spake2pFixedPoints {
    int         curveId;
    const char* mx;
    const char* my;
    const char* nx;
    const char* ny;
} Spake2pFixedPoints;

static const Spake2pFixedPoints spake2p_fixed_points[] = {
    { ECC_SECP256R1,
      "886E2F97ACE46E55BA9DD7242579F2993B64E16EF3DCAB95AFD497333D8FA12F",
      "5FF355163E43CE224E0B0E65FF02AC8E5C7BE09419C785E0CA547D55A12E2D20",
      "D8BBD6C639C62937B04D997F38C3770719C629D7014D49A24B4F98BAA1292B49",
      "07D60AA6BFADE45008A636337F5168C64D9BD36034808CD564490B1E656EDBE7" },
    { ECC_SECP384R1,
      "0FF0895AE5EBF6187080A82D82B42E2765E3B2F8749C7E05EBA366434B363D3D"
      "C36F15314739074D2EB8613FCEEC2853",
      "97592C55797CDD77C0715CB7DF2150220A0119866486AF4234F390AAD1F6ADDD"
      "E5930909ADC67A1FC0C99BA3D52DC5DD",
      "C72CF2E390853A1C1C4AD816A62FD15824F56078918F43F922CA21518F9C543B"
      "B252C5490214CF9AA3F0BAAB4B665C10",
      "C38B7D7F4E7F320317CD717315A797C7E02933AEF68B364CBF84EBC619BEDBE2"
      "1FF5C69EA0F1FED5D7E3200418073F40" },
    { ECC_SECP521R1,
      "003F06F38131B2BA2600791E82488E8D20AB889AF753A41806C5DB18D37D8560"
      "8CFAE06B82E4A72CD744C719193562A653EA1F119EEF9356907EDC9B56979962"
      "D7AA",
      "01BDD179A3D547610892E9B96DEA1EAB10BDD7AC5AE0CF75AA0F853BFD185CF7"
      "82F894301998B11D1898EDE2701DCA37A2BB50B4F519C3D89A7D054B51FB8491"
      "2192",
      "00C7924B9EC017F3094562894336A53C50167BA8C5963876880542BC669E494B"
      "2532D76C5B53DFB349FDF69154B9E0048C58A42E8ED04CEF052A3BC349D95575"
      "CD25",
      "01C62BEE650C9287A651BB75C7F39A2006873347B769840D261D17760B107E29"
      "F091D556A82A2E4CDE0C40B84B95B878DB2489EF760206424B3FE7968AA8E0B1"
      "F334" },
};

/* Load M or N for a curve into an affine point (z = 1).
 *
 * @param  [in]   curveId  ECC curve id.
 * @param  [in]   useN     0 for M, 1 for N.
 * @param  [out]  pt       Initialized point.
 * @return  0 on success.
 * @return  NOT_COMPILED_IN when the curve has no fixed points.
 * @return  Other negative value on math error.
 */
static int spake2p_load_fixed_point(int curveId, int useN, ecc_point* pt)
{
    int ret = NOT_COMPILED_IN;
    word32 i;

    for (i = 0; i < (word32)(sizeof(spake2p_fixed_points) /
            sizeof(spake2p_fixed_points[0])); i++) {
        const Spake2pFixedPoints* fp = &spake2p_fixed_points[i];
        if (fp->curveId == curveId) {
            ret = mp_read_radix(pt->x, useN ? fp->nx : fp->mx, MP_RADIX_HEX);
            if (ret == 0) {
                ret = mp_read_radix(pt->y, useN ? fp->ny : fp->my,
                    MP_RADIX_HEX);
            }
            if (ret == 0) {
                ret = mp_set(pt->z, 1);
            }
            break;
        }
    }

    return ret;
}

#if !defined(WOLFSSL_SP_MATH)
/* Curve parameters for the generic (non single-precision) point arithmetic. */
typedef struct Spake2pCurveMath {
    mp_int   a;
    mp_int   prime;
    mp_int   order;
    mp_digit mp;
    int      init;
} Spake2pCurveMath;

/* Load the generic-math parameters of a curve.
 *
 * @param  [in]   dp  Curve parameters.
 * @param  [out]  m   Receives the parameters; free with spake2p_math_free().
 * @return  0 on success.
 * @return  Negative value on math error.
 */
static int spake2p_math_load(const ecc_set_type* dp, Spake2pCurveMath* m)
{
    int ret;

    m->init = 0;
    ret = mp_init_multi(&m->a, &m->prime, &m->order, NULL, NULL, NULL);
    if (ret == 0) {
        m->init = 1;
        ret = mp_read_radix(&m->a, dp->Af, MP_RADIX_HEX);
    }
    if (ret == 0) {
        ret = mp_read_radix(&m->prime, dp->prime, MP_RADIX_HEX);
    }
    if (ret == 0) {
        ret = mp_read_radix(&m->order, dp->order, MP_RADIX_HEX);
    }
    if (ret == 0) {
        ret = mp_montgomery_setup(&m->prime, &m->mp);
    }

    return ret;
}

/* Free parameters loaded by spake2p_math_load(). The values are public. */
static void spake2p_math_free(Spake2pCurveMath* m)
{
    if (m->init) {
        mp_clear(&m->order);
        mp_clear(&m->prime);
        mp_clear(&m->a);
        m->init = 0;
    }
}

/* Convert an affine point to Montgomery-form projective coordinates, as
 * produced by wc_ecc_mulmod_ex2() with map = 0. Mirrors ecc_point_to_mont().
 *
 * @param  [in]   p     Affine point (z = 1).
 * @param  [out]  r     Initialized point; receives the converted point.
 * @param  [in]   m     Curve parameters.
 * @param  [in]   heap  Heap hint for temporary allocations.
 * @return  0 on success.
 * @return  Negative value on math error.
 */
static int spake2p_point_to_mont(ecc_point* p, ecc_point* r,
    Spake2pCurveMath* m, void* heap)
{
    int ret = 0;
    WC_DECLARE_VAR(mu, mp_int, 1, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(mu, mp_int, 1, heap, DYNAMIC_TYPE_ECC, ret = MEMORY_E);
    if (ret == 0) {
        ret = mp_init(mu);
        if (ret == 0) {
            ret = mp_montgomery_calc_normalization(mu, &m->prime);
            if ((ret == 0) && (mp_cmp_d(mu, 1) == MP_EQ)) {
                /* Montgomery form is the normal form. */
                ret = mp_copy(p->x, r->x);
                if (ret == 0) {
                    ret = mp_copy(p->y, r->y);
                }
                if (ret == 0) {
                    ret = mp_copy(p->z, r->z);
                }
            }
            else if (ret == 0) {
                ret = mp_mulmod(p->x, mu, &m->prime, r->x);
                if (ret == 0) {
                    ret = mp_mulmod(p->y, mu, &m->prime, r->y);
                }
                if (ret == 0) {
                    ret = mp_mulmod(p->z, mu, &m->prime, r->z);
                }
            }
            mp_clear(mu);
        }
    }
    WC_FREE_VAR_EX(mu, heap, DYNAMIC_TYPE_ECC);

    return ret;
}
#endif /* !WOLFSSL_SP_MATH */

/* Single-precision dispatch for the curves SPAKE2+ uses. Each evaluates to 1
 * and sets ret when the SP code for the curve is compiled in, else 0. */
#ifdef WOLFSSL_HAVE_SP_ECC
/* R = s * Q. */
static int spake2p_sp_mul(int id, mp_int* s, ecc_point* Q, ecc_point* R,
    void* heap, int* ret)
{
#ifndef WOLFSSL_SP_NO_256
    if (id == ECC_SECP256R1) {
        *ret = sp_ecc_mulmod_256(s, Q, R, 1, heap);
        return 1;
    }
#endif
#ifdef WOLFSSL_SP_384
    if (id == ECC_SECP384R1) {
        *ret = sp_ecc_mulmod_384(s, Q, R, 1, heap);
        return 1;
    }
#endif
#ifdef WOLFSSL_SP_521
    if (id == ECC_SECP521R1) {
        *ret = sp_ecc_mulmod_521(s, Q, R, 1, heap);
        return 1;
    }
#endif
    (void)id; (void)s; (void)Q; (void)R; (void)heap; (void)ret;
    return 0;
}

/* R = s * Q + A, or s * G + A when Q is NULL. A is affine. */
static int spake2p_sp_mul_add(int id, mp_int* s, ecc_point* Q, ecc_point* A,
    ecc_point* R, void* heap, int* ret)
{
#ifndef WOLFSSL_SP_NO_256
    if (id == ECC_SECP256R1) {
        *ret = (Q == NULL) ? sp_ecc_mulmod_base_add_256(s, A, 0, R, 1, heap)
                           : sp_ecc_mulmod_add_256(s, Q, A, 0, R, 1, heap);
        return 1;
    }
#endif
#ifdef WOLFSSL_SP_384
    if (id == ECC_SECP384R1) {
        *ret = (Q == NULL) ? sp_ecc_mulmod_base_add_384(s, A, 0, R, 1, heap)
                           : sp_ecc_mulmod_add_384(s, Q, A, 0, R, 1, heap);
        return 1;
    }
#endif
#ifdef WOLFSSL_SP_521
    if (id == ECC_SECP521R1) {
        *ret = (Q == NULL) ? sp_ecc_mulmod_base_add_521(s, A, 0, R, 1, heap)
                           : sp_ecc_mulmod_add_521(s, Q, A, 0, R, 1, heap);
        return 1;
    }
#endif
    (void)id; (void)s; (void)Q; (void)A; (void)R; (void)heap; (void)ret;
    return 0;
}
#endif /* WOLFSSL_HAVE_SP_ECC */

/* Compute R = k * G + s * Q, mapped to affine, where G is the curve's
 * generator. Both scalar multiplications are constant time in the scalar:
 * the single-precision code when it is compiled in for the curve, otherwise
 * wc_ecc_mulmod_ex2() (timing resistant, and blinded when rng is not NULL).
 *
 * @param  [in]   dp     Curve parameters.
 * @param  [in]   k      Scalar for G, in [1, order - 1].
 * @param  [in]   s      Scalar for Q, in [1, order - 1].
 * @param  [in]   Q      Affine point on the curve.
 * @param  [out]  R      Initialized point; receives the affine result.
 * @param  [in]   rng    RNG for blinding, or NULL.
 * @param  [in]   heap   Heap hint for temporary allocations.
 * @return  0 on success.
 * @return  ECC_INF_E when the result is the point at infinity.
 * @return  NOT_COMPILED_IN when no implementation is available for the
 *          curve.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative value on ECC or math error.
 */
static int spake2p_mul_add(const ecc_set_type* dp, mp_int* k, mp_int* s,
    ecc_point* Q, ecc_point* R, WC_RNG* rng, void* heap)
{
    int ret = NOT_COMPILED_IN;
    int done = 0;
    ecc_point* T = NULL;

    T = wc_ecc_new_point_h(heap);
    if (T == NULL) {
        return MEMORY_E;
    }

#ifdef WOLFSSL_HAVE_SP_ECC
    /* T = s * Q, then R = k * G + T, using the precomputed table for G. */
    if (spake2p_sp_mul(dp->id, s, Q, T, heap, &ret)) {
        if (ret == 0) {
            (void)spake2p_sp_mul_add(dp->id, k, NULL, T, R, heap, &ret);
        }
        done = 1;
    }
#endif

#if !defined(WOLFSSL_SP_MATH)
    if (!done) {
        /* Generic math: both products left in Montgomery projective form,
         * added with the exception-safe projective add, then mapped. */
        ecc_point* G = NULL;
        int infinity = 0;
        WC_DECLARE_VAR(m, Spake2pCurveMath, 1, heap);

        ret = 0;
        WC_ALLOC_VAR_EX(m, Spake2pCurveMath, 1, heap, DYNAMIC_TYPE_ECC,
            ret = MEMORY_E);
        if (ret == 0) {
            ret = spake2p_math_load(dp, m);
        }
        if (ret == 0) {
            G = wc_ecc_new_point_h(heap);
            if (G == NULL) {
                ret = MEMORY_E;
            }
        }
        if (ret == 0) {
            ret = mp_read_radix(G->x, dp->Gx, MP_RADIX_HEX);
        }
        if (ret == 0) {
            ret = mp_read_radix(G->y, dp->Gy, MP_RADIX_HEX);
        }
        if (ret == 0) {
            ret = mp_set(G->z, 1);
        }
        if (ret == 0) {
            ret = wc_ecc_mulmod_ex2(k, G, R, &m->a, &m->prime, &m->order,
                rng, 0, heap);
        }
        if (ret == 0) {
            ret = wc_ecc_mulmod_ex2(s, Q, T, &m->a, &m->prime, &m->order,
                rng, 0, heap);
        }
        if (ret == 0) {
            ret = ecc_projective_add_point_safe(R, T, R, &m->a, &m->prime,
                m->mp, &infinity);
            if ((ret == 0) && infinity) {
                ret = ECC_INF_E;
            }
        }
        if (ret == 0) {
            ret = ecc_map_ex(R, &m->prime, m->mp, 1);
        }

        if (G != NULL) {
            wc_ecc_del_point_h(G, heap);
        }
        if (WC_VAR_OK(m)) {
            spake2p_math_free(m);
        }
        WC_FREE_VAR_EX(m, heap, DYNAMIC_TYPE_ECC);
        done = 1;
    }
#endif /* !WOLFSSL_SP_MATH */

    /* The SP code maps the identity to (0, 0). */
    if ((ret == 0) && mp_iszero(R->x) && mp_iszero(R->y)) {
        ret = ECC_INF_E;
    }

    /* T held s * Q, which is secret. */
    wc_ecc_forcezero_point(T);
    wc_ecc_del_point_h(T, heap);
    (void)done;
    (void)rng;
    (void)heap;

    return ret;
}

/* Compute R = P + s * Q, mapped to affine, where P is a public affine point.
 * The scalar multiplication is constant time in s.
 *
 * @param  [in]   dp    Curve parameters.
 * @param  [in]   P     Affine point on the curve (z = 1).
 * @param  [in]   s     Scalar for Q, in [1, order - 1].
 * @param  [in]   Q     Affine point on the curve.
 * @param  [out]  R     Initialized point; receives the affine result.
 * @param  [in]   heap  Heap hint for temporary allocations.
 * @return  0 on success.
 * @return  ECC_INF_E when the result is the point at infinity.
 * @return  NOT_COMPILED_IN when no implementation is available for the
 *          curve.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative value on ECC or math error.
 */
static int spake2p_add_mul(const ecc_set_type* dp, ecc_point* P, mp_int* s,
    ecc_point* Q, ecc_point* R, void* heap)
{
    int ret = NOT_COMPILED_IN;
    int done = 0;

#ifdef WOLFSSL_HAVE_SP_ECC
    done = spake2p_sp_mul_add(dp->id, s, Q, P, R, heap, &ret);
#endif

#if !defined(WOLFSSL_SP_MATH)
    if (!done) {
        ecc_point* Pm = NULL;
        int infinity = 0;
        WC_DECLARE_VAR(m, Spake2pCurveMath, 1, heap);

        ret = 0;
        WC_ALLOC_VAR_EX(m, Spake2pCurveMath, 1, heap, DYNAMIC_TYPE_ECC,
            ret = MEMORY_E);
        if (ret == 0) {
            ret = spake2p_math_load(dp, m);
        }
        if (ret == 0) {
            Pm = wc_ecc_new_point_h(heap);
            if (Pm == NULL) {
                ret = MEMORY_E;
            }
        }
        if (ret == 0) {
            ret = spake2p_point_to_mont(P, Pm, m, heap);
        }
        if (ret == 0) {
            ret = wc_ecc_mulmod_ex2(s, Q, R, &m->a, &m->prime, &m->order,
                NULL, 0, heap);
        }
        if (ret == 0) {
            ret = ecc_projective_add_point_safe(R, Pm, R, &m->a, &m->prime,
                m->mp, &infinity);
            if ((ret == 0) && infinity) {
                ret = ECC_INF_E;
            }
        }
        if (ret == 0) {
            ret = ecc_map_ex(R, &m->prime, m->mp, 1);
        }

        if (Pm != NULL) {
            wc_ecc_del_point_h(Pm, heap);
        }
        if (WC_VAR_OK(m)) {
            spake2p_math_free(m);
        }
        WC_FREE_VAR_EX(m, heap, DYNAMIC_TYPE_ECC);
        done = 1;
    }
#endif /* !WOLFSSL_SP_MATH */

    if ((ret == 0) && mp_iszero(R->x) && mp_iszero(R->y)) {
        ret = ECC_INF_E;
    }
    (void)done;
    (void)heap;

    return ret;
}

/* Compute R = k * P, mapped to affine in constant time. The scalar
 * multiplication is constant time in k.
 *
 * @param  [in]   dp    Curve parameters.
 * @param  [in]   k     Scalar, in [1, order - 1].
 * @param  [in]   P     Affine point on the curve.
 * @param  [out]  R     Initialized point; receives the affine result.
 * @param  [in]   heap  Heap hint for temporary allocations.
 * @return  0 on success.
 * @return  ECC_INF_E when the result is the point at infinity.
 * @return  NOT_COMPILED_IN when no implementation is available for the
 *          curve.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative value on ECC or math error.
 */
static int spake2p_mul(const ecc_set_type* dp, mp_int* k, ecc_point* P,
    ecc_point* R, void* heap)
{
    int ret = NOT_COMPILED_IN;
    int done = 0;

#ifdef WOLFSSL_HAVE_SP_ECC
    done = spake2p_sp_mul(dp->id, k, P, R, heap, &ret);
#endif

#if !defined(WOLFSSL_SP_MATH)
    if (!done) {
        WC_DECLARE_VAR(m, Spake2pCurveMath, 1, heap);

        ret = 0;
        WC_ALLOC_VAR_EX(m, Spake2pCurveMath, 1, heap, DYNAMIC_TYPE_ECC,
            ret = MEMORY_E);
        if (ret == 0) {
            ret = spake2p_math_load(dp, m);
        }
        /* Leave projective, then map with the constant-time inversion. */
        if (ret == 0) {
            ret = wc_ecc_mulmod_ex2(k, P, R, &m->a, &m->prime, &m->order,
                NULL, 0, heap);
        }
        if (ret == 0) {
            ret = ecc_map_ex(R, &m->prime, m->mp, 1);
        }

        if (WC_VAR_OK(m)) {
            spake2p_math_free(m);
        }
        WC_FREE_VAR_EX(m, heap, DYNAMIC_TYPE_ECC);
        done = 1;
    }
#endif /* !WOLFSSL_SP_MATH */

    if ((ret == 0) && mp_iszero(R->x) && mp_iszero(R->y)) {
        ret = ECC_INF_E;
    }
    (void)done;
    (void)heap;

    return ret;
}

/* Encode an affine point as SEC1 uncompressed: 0x04 || X || Y.
 *
 * @param  [in]   pt   Affine point.
 * @param  [in]   fs   Field size in bytes.
 * @param  [out]  out  Buffer of at least 1 + 2 * fs bytes.
 * @return  0 on success.
 * @return  Negative value on math error.
 */
static int spake2p_encode_point(ecc_point* pt, word32 fs, byte* out)
{
    int ret;

    out[0] = ECC_POINT_UNCOMP;
    ret = mp_to_unsigned_bin_len(pt->x, out + 1, (int)fs);
    if (ret == 0) {
        ret = mp_to_unsigned_bin_len(pt->y, out + 1 + fs, (int)fs);
    }

    return ret;
}

/* Decode a SEC1 uncompressed point already validated by
 * spake2p_check_point() (or produced by this library).
 *
 * @param  [in]   in  Encoded point, 1 + 2 * fs bytes.
 * @param  [in]   fs  Field size in bytes.
 * @param  [out]  pt  Initialized point; receives the affine point (z = 1).
 * @return  0 on success.
 * @return  Negative value on math error.
 */
static int spake2p_decode_point(const byte* in, word32 fs, ecc_point* pt)
{
    int ret;

    ret = mp_read_unsigned_bin(pt->x, in + 1, fs);
    if (ret == 0) {
        ret = mp_read_unsigned_bin(pt->y, in + 1 + fs, fs);
    }
    if (ret == 0) {
        ret = mp_set(pt->z, 1);
    }

    return ret;
}

/* Generate this side's ephemeral scalar and public share (RFC 9383,
 * Section 3.3):
 *   Prover:   x random in [1, p - 1], shareP = x * P + w0 * M
 *   Verifier: y random in [1, p - 1], shareV = y * P + w0 * N
 * The share is written as a SEC1 uncompressed point.
 *
 * On error the context is left with its secrets loaded and no share, so the
 * call can be retried; a randomly generated ephemeral is zeroized.
 *
 * @param  [in, out]  ctx      Context with secrets loaded.
 * @param  [in]       rng      Initialized RNG. Not used for the ephemeral
 *                             when one was fixed for testing, but still used
 *                             for blinding when not NULL.
 * @param  [out]      share    Buffer that receives the encoded share.
 * @param  [in, out]  shareSz  On in, size of share. On out, bytes written.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ctx, share or shareSz is NULL, or rng is NULL
 *          and no ephemeral was fixed.
 * @return  BAD_STATE_E when the secrets are not loaded, or a share was
 *          already generated.
 * @return  BUFFER_E when *shareSz is too small.
 * @return  ECC_INF_E when the share is the point at infinity (negligible
 *          probability with a random ephemeral).
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative value on RNG, ECC or math error.
 */
int wc_Spake2pGenerateShare(wc_Spake2p* ctx, WC_RNG* rng, byte* share,
    word32* shareSz)
{
    int ret;
    int curveId = 0;
    int idx;
    int initDone = 0;
    word32 fs = 0;
    word32 orderSz = 0;
    const ecc_set_type* dp = NULL;
    ecc_point* Q = NULL;
    ecc_point* R = NULL;
    void* heap;
    WC_DECLARE_VAR(order, mp_int, 1, NULL);
    WC_DECLARE_VAR(k, mp_int, 1, NULL);
    WC_DECLARE_VAR(w0, mp_int, 1, NULL);

    if ((ctx == NULL) || (share == NULL) || (shareSz == NULL) ||
            ((rng == NULL) && !SPAKE2P_EPH_FIXED(ctx))) {
        return BAD_FUNC_ARG;
    }
    if (ctx->state != WC_SPAKE2P_STATE_SECRETS) {
        return BAD_STATE_E;
    }
    heap = ctx->heap;

    ret = spake2p_suite_curve(ctx->suite, &curveId);
    if (ret == 0) {
        idx = wc_ecc_get_curve_idx(curveId);
        if (idx >= 0) {
            dp = wc_ecc_get_curve_params(idx);
        }
        if (dp == NULL) {
            ret = NOT_COMPILED_IN;
        }
    }
    if (ret == 0) {
        fs = (word32)dp->size;
        if (*shareSz < 1 + 2 * fs) {
            ret = BUFFER_E;
        }
    }
    if (ret != 0) {
        return ret;
    }

    WC_ALLOC_VAR_EX(order, mp_int, 1, heap, DYNAMIC_TYPE_ECC,
        ret = MEMORY_E);
    if (ret == 0) {
        WC_ALLOC_VAR_EX(k, mp_int, 1, heap, DYNAMIC_TYPE_ECC,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        WC_ALLOC_VAR_EX(w0, mp_int, 1, heap, DYNAMIC_TYPE_ECC,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        ret = mp_init_multi(order, k, w0, NULL, NULL, NULL);
        if (ret == 0) {
            initDone = 1;
        }
    }
    if (ret == 0) {
        Q = wc_ecc_new_point_h(heap);
        R = wc_ecc_new_point_h(heap);
        if ((Q == NULL) || (R == NULL)) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        ret = spake2p_load_order(ctx->suite, order, &orderSz);
    }
    if (ret == 0) {
        if (SPAKE2P_EPH_FIXED(ctx)) {
            /* Fixed for testing; validated when it was set. */
            ret = mp_read_unsigned_bin(k, ctx->eph, ctx->ephSz);
        }
        else {
            /* Uniform in [1, order - 1]. */
            ret = wc_ecc_gen_k(rng, (int)fs, k, order);
        }
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(w0, ctx->w0, ctx->w0Sz);
    }
    if (ret == 0) {
        ret = spake2p_load_fixed_point(curveId,
            ctx->role == WC_SPAKE2P_VERIFIER, Q);
    }
    if (ret == 0) {
        ret = spake2p_mul_add(dp, k, w0, Q, R, rng, heap);
    }

    if (ret == 0) {
        ctx->share[0] = ECC_POINT_UNCOMP;
        ret = mp_to_unsigned_bin_len(R->x, ctx->share + 1, (int)fs);
    }
    if (ret == 0) {
        ret = mp_to_unsigned_bin_len(R->y, ctx->share + 1 + fs, (int)fs);
    }
    if ((ret == 0) && !SPAKE2P_EPH_FIXED(ctx)) {
        ret = mp_to_unsigned_bin_len(k, ctx->eph, (int)orderSz);
        ctx->ephSz = orderSz;
    }

    if (ret == 0) {
        ctx->shareSz = 1 + 2 * fs;
        XMEMCPY(share, ctx->share, ctx->shareSz);
        *shareSz = ctx->shareSz;
        ctx->state = WC_SPAKE2P_STATE_SHARE;
    }
    else {
        ForceZero(ctx->share, sizeof(ctx->share));
        ctx->shareSz = 0;
        if (!SPAKE2P_EPH_FIXED(ctx)) {
            ForceZero(ctx->eph, sizeof(ctx->eph));
            ctx->ephSz = 0;
        }
    }

    if (R != NULL) {
        wc_ecc_del_point_h(R, heap);
    }
    if (Q != NULL) {
        wc_ecc_del_point_h(Q, heap);
    }
    if (initDone) {
        mp_forcezero(w0);
        mp_forcezero(k);
        mp_clear(order);
    }
    WC_FREE_VAR_EX(w0, heap, DYNAMIC_TYPE_ECC);
    WC_FREE_VAR_EX(k, heap, DYNAMIC_TYPE_ECC);
    WC_FREE_VAR_EX(order, heap, DYNAMIC_TYPE_ECC);
    (void)heap;

    return ret;
}

/* ------------------------------------------------------------------------- */
/* Key schedule and confirmation                                             */
/* ------------------------------------------------------------------------- */

#define SPAKE2P_MAC_HMAC  0
#define SPAKE2P_MAC_CMAC  1

/* Length of the AES key and tag for the CMAC-AES-128 suites. */
#define SPAKE2P_CMAC_SZ   16

/* Hash, KDF and MAC parameters of a ciphersuite (RFC 9383, Section 4). */
typedef struct Spake2pSuiteInfo {
    enum wc_HashType hashType;  /* Hash, and HKDF/HMAC hash.             */
    int              macType;   /* SPAKE2P_MAC_HMAC or SPAKE2P_MAC_CMAC. */
    word32           hashSz;    /* K_main and K_shared length.           */
    word32           keySz;     /* Length of each confirmation key.      */
    word32           tagSz;     /* Confirmation MAC length.              */
} Spake2pSuiteInfo;

/* Get the hash, KDF and MAC parameters of a ciphersuite. The suite has been
 * checked by wc_Spake2pInit().
 *
 * @param  [in]   suite  WC_SPAKE2P_<suite>.
 * @param  [out]  info   Receives the parameters.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when suite is not a known ciphersuite.
 */
static int spake2p_suite_info(int suite, Spake2pSuiteInfo* info)
{
    int ret = 0;

    switch (suite) {
        case WC_SPAKE2P_P256_SHA256_HKDF_HMAC:
        case WC_SPAKE2P_P384_SHA256_HKDF_HMAC:
            info->hashType = WC_HASH_TYPE_SHA256;
            info->macType = SPAKE2P_MAC_HMAC;
            break;
        case WC_SPAKE2P_P256_SHA512_HKDF_HMAC:
        case WC_SPAKE2P_P384_SHA512_HKDF_HMAC:
        case WC_SPAKE2P_P521_SHA512_HKDF_HMAC:
            info->hashType = WC_HASH_TYPE_SHA512;
            info->macType = SPAKE2P_MAC_HMAC;
            break;
        case WC_SPAKE2P_P256_SHA256_HKDF_CMAC_AES128:
            info->hashType = WC_HASH_TYPE_SHA256;
            info->macType = SPAKE2P_MAC_CMAC;
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
    }
    if (ret == 0) {
        ret = wc_HashGetDigestSize(info->hashType);
        if (ret > 0) {
            info->hashSz = (word32)ret;
            ret = 0;
        }
        else if (ret == 0) {
            ret = NOT_COMPILED_IN;
        }
    }
    if (ret == 0) {
        /* RFC 9383, Section 3.4: HMAC keys are the digest length; CMAC-AES
         * keys are the AES key length. */
        if (info->macType == SPAKE2P_MAC_HMAC) {
            info->keySz = info->hashSz;
            info->tagSz = info->hashSz;
        }
        else {
            info->keySz = SPAKE2P_CMAC_SZ;
            info->tagSz = SPAKE2P_CMAC_SZ;
        }
    }

    return ret;
}

/* Compute the confirmation MAC of msg under key for the suite.
 *
 * @param  [in]   ctx    Context (heap hint and device id).
 * @param  [in]   info   Suite parameters.
 * @param  [in]   key    Confirmation key, info->keySz bytes.
 * @param  [in]   msg    Message (a share).
 * @param  [in]   msgSz  Length of msg in bytes.
 * @param  [out]  out    Buffer of at least info->tagSz bytes.
 * @return  0 on success.
 * @return  NOT_COMPILED_IN when the MAC is not compiled in.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative value on MAC error.
 */
static int spake2p_mac(const wc_Spake2p* ctx, const Spake2pSuiteInfo* info,
    const byte* key, const byte* msg, word32 msgSz, byte* out)
{
    int ret = NOT_COMPILED_IN;

    if (info->macType == SPAKE2P_MAC_HMAC) {
        WC_DECLARE_VAR(hmac, Hmac, 1, ctx->heap);

        ret = 0;
        WC_ALLOC_VAR_EX(hmac, Hmac, 1, ctx->heap, DYNAMIC_TYPE_HMAC,
            ret = MEMORY_E);
        if (ret == 0) {
            ret = wc_HmacInit(hmac, ctx->heap, ctx->devId);
            if (ret == 0) {
                ret = wc_HmacSetKey(hmac, (int)info->hashType, key,
                    info->keySz);
                if (ret == 0) {
                    ret = wc_HmacUpdate(hmac, msg, msgSz);
                }
                if (ret == 0) {
                    ret = wc_HmacFinal(hmac, out);
                }
                wc_HmacFree(hmac);
            }
        }
        WC_FREE_VAR_EX(hmac, ctx->heap, DYNAMIC_TYPE_HMAC);
    }
    else {
#ifdef WOLFSSL_CMAC
        word32 outSz = SPAKE2P_CMAC_SZ;
        WC_DECLARE_VAR(cmac, Cmac, 1, ctx->heap);

        ret = 0;
        WC_ALLOC_VAR_EX(cmac, Cmac, 1, ctx->heap, DYNAMIC_TYPE_CMAC,
            ret = MEMORY_E);
        if (ret == 0) {
            ret = wc_AesCmacGenerate_ex(cmac, out, &outSz, msg, msgSz, key,
                info->keySz, ctx->heap, ctx->devId);
            ForceZero(cmac, sizeof(*cmac));
        }
        WC_FREE_VAR_EX(cmac, ctx->heap, DYNAMIC_TYPE_CMAC);
#endif
    }
    (void)ctx;
    (void)key;
    (void)msg;
    (void)msgSz;
    (void)out;

    return ret;
}

/* Add len(data) || data to the transcript hash, where len() is an eight-byte
 * little-endian byte count (RFC 9383, Section 3).
 *
 * @param  [in, out]  hash    Hash in progress.
 * @param  [in]       type    Hash type.
 * @param  [in]       data    Data; may be NULL when sz is 0.
 * @param  [in]       sz      Length of data in bytes.
 * @return  0 on success.
 * @return  Negative value on hash error.
 */
static int spake2p_tt_add(wc_HashAlg* hash, enum wc_HashType type,
    const byte* data, word32 sz)
{
    int ret;
    byte len[8];

    /* word32 lengths: the upper four bytes are always zero. */
    len[0] = (byte)(sz);
    len[1] = (byte)(sz >> 8);
    len[2] = (byte)(sz >> 16);
    len[3] = (byte)(sz >> 24);
    len[4] = 0;
    len[5] = 0;
    len[6] = 0;
    len[7] = 0;

    ret = wc_HashUpdate(hash, type, len, sizeof(len));
    if ((ret == 0) && (sz > 0)) {
        ret = wc_HashUpdate(hash, type, data, sz);
    }

    return ret;
}

/* Compute the transcript hash K_main = Hash(TT) (RFC 9383, Section 3.3):
 *
 *   TT = len(Context) || Context || len(idProver) || idProver
 *     || len(idVerifier) || idVerifier || len(M) || M || len(N) || N
 *     || len(shareP) || shareP || len(shareV) || shareV
 *     || len(Z) || Z || len(V) || V || len(w0) || w0
 *
 * The context is always included, as a zero length when it is empty.
 *
 * @param  [in]   ctx     Context with transcript inputs and shares.
 * @param  [in]   info    Suite parameters.
 * @param  [in]   curveId ECC curve id.
 * @param  [in]   fs      Field size in bytes.
 * @param  [in]   Z       Encoded Z, 1 + 2 * fs bytes.
 * @param  [in]   V       Encoded V, 1 + 2 * fs bytes.
 * @param  [out]  kMain   Buffer of at least info->hashSz bytes.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative value on hash or math error.
 */
static int spake2p_transcript_hash(const wc_Spake2p* ctx,
    const Spake2pSuiteInfo* info, int curveId, word32 fs, const byte* Z,
    const byte* V, byte* kMain)
{
    int ret = 0;
    int hashInit = 0;
    word32 ptSz = 1 + 2 * fs;
    const byte* shareP;
    const byte* shareV;
    byte mn[WC_SPAKE2P_MAX_POINT_SZ];
    ecc_point* pt = NULL;
    WC_DECLARE_VAR(hash, wc_HashAlg, 1, ctx->heap);

    if (ctx->role == WC_SPAKE2P_PROVER) {
        shareP = ctx->share;
        shareV = ctx->peerShare;
    }
    else {
        shareP = ctx->peerShare;
        shareV = ctx->share;
    }

    WC_ALLOC_VAR_EX(hash, wc_HashAlg, 1, ctx->heap, DYNAMIC_TYPE_HASHES,
        ret = MEMORY_E);
    if (ret == 0) {
        pt = wc_ecc_new_point_h(ctx->heap);
        if (pt == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        ret = wc_HashInit_ex(hash, info->hashType, ctx->heap, ctx->devId);
        if (ret == 0) {
            hashInit = 1;
        }
    }

    if (ret == 0) {
        ret = spake2p_tt_add(hash, info->hashType, ctx->context,
            ctx->contextSz);
    }
    if (ret == 0) {
        ret = spake2p_tt_add(hash, info->hashType, ctx->idProver,
            ctx->idProverSz);
    }
    if (ret == 0) {
        ret = spake2p_tt_add(hash, info->hashType, ctx->idVerifier,
            ctx->idVerifierSz);
    }
    /* M then N, uncompressed. */
    if (ret == 0) {
        ret = spake2p_load_fixed_point(curveId, 0, pt);
    }
    if (ret == 0) {
        ret = spake2p_encode_point(pt, fs, mn);
    }
    if (ret == 0) {
        ret = spake2p_tt_add(hash, info->hashType, mn, ptSz);
    }
    if (ret == 0) {
        ret = spake2p_load_fixed_point(curveId, 1, pt);
    }
    if (ret == 0) {
        ret = spake2p_encode_point(pt, fs, mn);
    }
    if (ret == 0) {
        ret = spake2p_tt_add(hash, info->hashType, mn, ptSz);
    }
    if (ret == 0) {
        ret = spake2p_tt_add(hash, info->hashType, shareP, ptSz);
    }
    if (ret == 0) {
        ret = spake2p_tt_add(hash, info->hashType, shareV, ptSz);
    }
    if (ret == 0) {
        ret = spake2p_tt_add(hash, info->hashType, Z, ptSz);
    }
    if (ret == 0) {
        ret = spake2p_tt_add(hash, info->hashType, V, ptSz);
    }
    if (ret == 0) {
        ret = spake2p_tt_add(hash, info->hashType, ctx->w0, ctx->w0Sz);
    }
    if (ret == 0) {
        ret = wc_HashFinal(hash, info->hashType, kMain);
    }

    if (hashInit) {
        /* The hash state has absorbed Z, V and w0. */
        (void)wc_HashFree(hash, info->hashType);
        ForceZero(hash, sizeof(*hash));
    }
    WC_FREE_VAR_EX(hash, ctx->heap, DYNAMIC_TYPE_HASHES);
    if (pt != NULL) {
        wc_ecc_del_point_h(pt, ctx->heap);
    }

    return ret;
}

/* Derive the confirmation keys and K_shared from K_main (RFC 9383,
 * Section 3.4), storing them in the context:
 *
 *   K_confirmP || K_confirmV = KDF(nil, K_main, "ConfirmationKeys")
 *   K_shared = KDF(nil, K_main, "SharedKey")
 *
 * @param  [in, out]  ctx    Context.
 * @param  [in]       info   Suite parameters.
 * @param  [in]       kMain  K_main, info->hashSz bytes.
 * @return  0 on success.
 * @return  Negative value on HKDF error.
 */
static int spake2p_key_schedule(wc_Spake2p* ctx, const Spake2pSuiteInfo* info,
    const byte* kMain)
{
    static const byte confLabel[] = "ConfirmationKeys";
    static const byte sharedLabel[] = "SharedKey";
    int ret;
    byte keys[2 * WC_SPAKE2P_MAX_CONFIRM_KEY_SZ];

    ret = wc_HKDF_ex((int)info->hashType, kMain, info->hashSz, NULL, 0,
        confLabel, (word32)sizeof(confLabel) - 1, keys, 2 * info->keySz,
        ctx->heap, ctx->devId);
    if (ret == 0) {
        XMEMCPY(ctx->kConfirmP, keys, info->keySz);
        XMEMCPY(ctx->kConfirmV, keys + info->keySz, info->keySz);
        ctx->kConfirmSz = info->keySz;
        ret = wc_HKDF_ex((int)info->hashType, kMain, info->hashSz, NULL, 0,
            sharedLabel, (word32)sizeof(sharedLabel) - 1, ctx->kShared,
            info->hashSz, ctx->heap, ctx->devId);
    }
    if (ret == 0) {
        ctx->kSharedSz = info->hashSz;
    }
    ForceZero(keys, sizeof(keys));

    return ret;
}

/* Compute the shared points Z and V (RFC 9383, Section 3.3). The cofactor h
 * is 1 for the supported curves.
 *
 *   Prover:   T = shareV - w0 * N,  Z = x * T,  V = w1 * T
 *   Verifier: T = shareP - w0 * M,  Z = y * T,  V = y * L
 *
 * T is computed as peerShare + (order - w0) * N (or M).
 *
 * @param  [in]   ctx      Context with secrets, ephemeral and peer share.
 * @param  [in]   dp       Curve parameters.
 * @param  [in]   fs       Field size in bytes.
 * @param  [out]  Zenc     Receives Z, 1 + 2 * fs bytes.
 * @param  [out]  Venc     Receives V, 1 + 2 * fs bytes.
 * @return  0 on success.
 * @return  ECC_INF_E when T, Z or V is the point at infinity.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative value on ECC or math error.
 */
static int spake2p_compute_zv(const wc_Spake2p* ctx, const ecc_set_type* dp,
    word32 fs, byte* Zenc, byte* Venc)
{
    int ret = 0;
    int initDone = 0;
    word32 orderSz = 0;
    void* heap = ctx->heap;
    ecc_point* peer = NULL;
    ecc_point* Q = NULL;
    ecc_point* T = NULL;
    ecc_point* R = NULL;
    WC_DECLARE_VAR(order, mp_int, 1, heap);
    WC_DECLARE_VAR(k, mp_int, 1, heap);
    WC_DECLARE_VAR(nw0, mp_int, 1, heap);
    WC_DECLARE_VAR(w1, mp_int, 1, heap);

    WC_ALLOC_VAR_EX(order, mp_int, 1, heap, DYNAMIC_TYPE_ECC,
        ret = MEMORY_E);
    if (ret == 0) {
        WC_ALLOC_VAR_EX(k, mp_int, 1, heap, DYNAMIC_TYPE_ECC,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        WC_ALLOC_VAR_EX(nw0, mp_int, 1, heap, DYNAMIC_TYPE_ECC,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        WC_ALLOC_VAR_EX(w1, mp_int, 1, heap, DYNAMIC_TYPE_ECC,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        ret = mp_init_multi(order, k, nw0, w1, NULL, NULL);
        if (ret == 0) {
            initDone = 1;
        }
    }
    if (ret == 0) {
        peer = wc_ecc_new_point_h(heap);
        Q = wc_ecc_new_point_h(heap);
        T = wc_ecc_new_point_h(heap);
        R = wc_ecc_new_point_h(heap);
        if ((peer == NULL) || (Q == NULL) || (T == NULL) || (R == NULL)) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        ret = spake2p_load_order(ctx->suite, order, &orderSz);
    }
    /* nw0 = order - w0, so nw0 * Q = -(w0 * Q). w0 is in [1, order - 1]. */
    if (ret == 0) {
        ret = mp_read_unsigned_bin(nw0, ctx->w0, ctx->w0Sz);
    }
    if (ret == 0) {
        ret = mp_sub(order, nw0, nw0);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(k, ctx->eph, ctx->ephSz);
    }
    if (ret == 0) {
        ret = spake2p_decode_point(ctx->peerShare, fs, peer);
    }
    /* Prover removes w0 * N from shareV; Verifier removes w0 * M from
     * shareP. */
    if (ret == 0) {
        ret = spake2p_load_fixed_point(dp->id,
            ctx->role == WC_SPAKE2P_PROVER, Q);
    }
    if (ret == 0) {
        ret = spake2p_add_mul(dp, peer, nw0, Q, T, heap);
    }

    /* Z = eph * T */
    if (ret == 0) {
        ret = spake2p_mul(dp, k, T, R, heap);
    }
    if (ret == 0) {
        ret = spake2p_encode_point(R, fs, Zenc);
    }

    /* V = w1 * T (Prover) or y * L (Verifier). */
    if (ret == 0) {
        if (ctx->role == WC_SPAKE2P_PROVER) {
            ret = mp_read_unsigned_bin(w1, ctx->sec.w1, ctx->secSz);
            if (ret == 0) {
                ret = spake2p_mul(dp, w1, T, R, heap);
            }
        }
        else {
            ret = spake2p_decode_point(ctx->sec.L, fs, Q);
            if (ret == 0) {
                ret = spake2p_mul(dp, k, Q, R, heap);
            }
        }
    }
    if (ret == 0) {
        ret = spake2p_encode_point(R, fs, Venc);
    }

    /* T reveals w0 * N (or M) given the public share, and R held Z and V. */
    if (T != NULL) {
        wc_ecc_forcezero_point(T);
        wc_ecc_del_point_h(T, heap);
    }
    if (R != NULL) {
        wc_ecc_forcezero_point(R);
        wc_ecc_del_point_h(R, heap);
    }
    if (Q != NULL) {
        wc_ecc_del_point_h(Q, heap);
    }
    if (peer != NULL) {
        wc_ecc_del_point_h(peer, heap);
    }
    if (initDone) {
        mp_forcezero(w1);
        mp_forcezero(nw0);
        mp_forcezero(k);
        mp_clear(order);
    }
    WC_FREE_VAR_EX(w1, heap, DYNAMIC_TYPE_ECC);
    WC_FREE_VAR_EX(nw0, heap, DYNAMIC_TYPE_ECC);
    WC_FREE_VAR_EX(k, heap, DYNAMIC_TYPE_ECC);
    WC_FREE_VAR_EX(order, heap, DYNAMIC_TYPE_ECC);
    (void)heap;

    return ret;
}

/* Process the peer's share and produce this side's confirmation MAC
 * (RFC 9383, Sections 3.3 and 3.4).
 *
 * Validates the peer share, computes Z and V, hashes the transcript to
 * K_main, derives K_confirmP, K_confirmV and K_shared, and outputs
 *   Prover:   confirmP = MAC(K_confirmP, shareV)
 *   Verifier: confirmV = MAC(K_confirmV, shareP)
 *
 * Argument, state and buffer-size errors leave the context unchanged. Any
 * later error puts it in the failed state: every further call except
 * wc_Spake2pFree() returns BAD_STATE_E.
 *
 * @param  [in, out]  ctx          Context after wc_Spake2pGenerateShare().
 * @param  [in]       peerShare    Peer's share, SEC1 uncompressed.
 * @param  [in]       peerShareSz  Length of peerShare in bytes.
 * @param  [out]      confirm      Buffer that receives this side's MAC.
 * @param  [in, out]  confirmSz    On in, size of confirm. On out, bytes
 *                                 written.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a pointer is NULL.
 * @return  BAD_STATE_E when no share has been generated, or the peer share
 *          was already processed.
 * @return  BUFFER_E when *confirmSz is too small.
 * @return  IS_POINT_E when the peer share is malformed or not on the curve.
 * @return  ECC_INF_E when the peer share or a computed point is the point at
 *          infinity.
 * @return  NOT_COMPILED_IN when ECC key import is not compiled in.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative value on ECC, hash or MAC error.
 */
int wc_Spake2pProcessPeerShare(wc_Spake2p* ctx, const byte* peerShare,
    word32 peerShareSz, byte* confirm, word32* confirmSz)
{
    int ret;
    int curveId = 0;
    int idx;
    word32 fs = 0;
    const ecc_set_type* dp = NULL;
    Spake2pSuiteInfo info;
    byte Z[WC_SPAKE2P_MAX_POINT_SZ];
    byte V[WC_SPAKE2P_MAX_POINT_SZ];
    byte kMain[WC_SPAKE2P_MAX_HASH_SZ];

    if ((ctx == NULL) || (peerShare == NULL) || (confirm == NULL) ||
            (confirmSz == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (ctx->state != WC_SPAKE2P_STATE_SHARE) {
        return BAD_STATE_E;
    }
    ret = spake2p_suite_info(ctx->suite, &info);
    if ((ret == 0) && (*confirmSz < info.tagSz)) {
        ret = BUFFER_E;
    }
    if (ret != 0) {
        return ret;
    }

    /* From here on, any failure is fatal to the context. */
    ret = spake2p_suite_curve(ctx->suite, &curveId);
    if (ret == 0) {
        idx = wc_ecc_get_curve_idx(curveId);
        if (idx >= 0) {
            dp = wc_ecc_get_curve_params(idx);
        }
        if (dp == NULL) {
            ret = NOT_COMPILED_IN;
        }
    }
    /* RFC 9383, Section 6: abort unless the peer share is in the
     * prime-order group. With cofactor 1 that is: on the curve and not the
     * identity. */
    if (ret == 0) {
        fs = (word32)dp->size;
#ifdef HAVE_ECC_KEY_IMPORT
        ret = spake2p_check_point(ctx->suite, peerShare, peerShareSz,
            ctx->heap);
#else
        ret = NOT_COMPILED_IN;
#endif
    }
    if (ret == 0) {
        XMEMCPY(ctx->peerShare, peerShare, peerShareSz);
        ctx->peerShareSz = peerShareSz;
        ret = spake2p_compute_zv(ctx, dp, fs, Z, V);
    }
    if (ret == 0) {
        ret = spake2p_transcript_hash(ctx, &info, curveId, fs, Z, V, kMain);
    }
    if (ret == 0) {
        ret = spake2p_key_schedule(ctx, &info, kMain);
    }
    if (ret == 0) {
        /* This side's MAC is over the peer's share. */
        ret = spake2p_mac(ctx, &info,
            (ctx->role == WC_SPAKE2P_PROVER) ? ctx->kConfirmP :
                                               ctx->kConfirmV,
            ctx->peerShare, ctx->peerShareSz, confirm);
    }

    if (ret == 0) {
        *confirmSz = info.tagSz;
        ctx->state = WC_SPAKE2P_STATE_KEYS;
    }
    else {
        ForceZero(ctx->kConfirmP, sizeof(ctx->kConfirmP));
        ForceZero(ctx->kConfirmV, sizeof(ctx->kConfirmV));
        ForceZero(ctx->kShared, sizeof(ctx->kShared));
        ctx->kConfirmSz = 0;
        ctx->kSharedSz = 0;
        ctx->state = WC_SPAKE2P_STATE_FAILED;
    }
    /* The ephemeral scalar is not needed once Z and V are computed; a leaked
     * ephemeral reveals w0 from the share. */
    ForceZero(ctx->eph, sizeof(ctx->eph));
    ctx->ephSz = 0;

    /* K_main must be discarded (RFC 9383, Section 3.4); Z and V are
     * secret. */
    ForceZero(kMain, sizeof(kMain));
    ForceZero(Z, sizeof(Z));
    ForceZero(V, sizeof(V));

    return ret;
}

/* Verify the peer's confirmation MAC (RFC 9383, Section 3.4), comparing in
 * constant time:
 *   Prover:   expects confirmV = MAC(K_confirmV, shareP)
 *   Verifier: expects confirmP = MAC(K_confirmP, shareV)
 * i.e. the MAC of this side's own share under the peer's confirmation key.
 *
 * On success the context is confirmed and K_shared becomes available. The
 * confirmation keys are discarded either way (RFC 9383, Section 3.4).
 * Argument and state errors leave the context unchanged; any other failure,
 * including a mismatch, puts it in the failed state.
 *
 * @param  [in, out]  ctx            Context after
 *                                   wc_Spake2pProcessPeerShare().
 * @param  [in]       peerConfirm    Peer's confirmation MAC as received.
 * @param  [in]       peerConfirmSz  Length of peerConfirm in bytes.
 * @return  0 when the confirmation is valid.
 * @return  MAC_CMP_FAILED_E when it is invalid or has the wrong length.
 * @return  BAD_FUNC_ARG when ctx or peerConfirm is NULL.
 * @return  BAD_STATE_E when the peer share has not been processed, or the
 *          context is confirmed or failed.
 * @return  Other negative value on MAC error.
 */
int wc_Spake2pVerifyPeerConfirm(wc_Spake2p* ctx, const byte* peerConfirm,
    word32 peerConfirmSz)
{
    int ret;
    Spake2pSuiteInfo info;
    byte expected[WC_SPAKE2P_MAX_CONFIRM_SZ];

    if ((ctx == NULL) || (peerConfirm == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (ctx->state != WC_SPAKE2P_STATE_KEYS) {
        return BAD_STATE_E;
    }

    ret = spake2p_suite_info(ctx->suite, &info);
    if (ret == 0) {
        /* The peer MACs this side's share under the peer's key. */
        ret = spake2p_mac(ctx, &info,
            (ctx->role == WC_SPAKE2P_PROVER) ? ctx->kConfirmV :
                                               ctx->kConfirmP,
            ctx->share, ctx->shareSz, expected);
    }
    if (ret == 0) {
        /* The length is public; the comparison of the bytes is not. */
        if ((peerConfirmSz != info.tagSz) ||
                (ConstantCompare(expected, peerConfirm,
                    (int)info.tagSz) != 0)) {
            ret = MAC_CMP_FAILED_E;
        }
    }

    /* Confirmation keys are not needed after this, whatever the outcome. */
    ForceZero(ctx->kConfirmP, sizeof(ctx->kConfirmP));
    ForceZero(ctx->kConfirmV, sizeof(ctx->kConfirmV));
    ctx->kConfirmSz = 0;
    ForceZero(expected, sizeof(expected));

    if (ret == 0) {
        ctx->state = WC_SPAKE2P_STATE_CONFIRMED;
    }
    else {
        ForceZero(ctx->kShared, sizeof(ctx->kShared));
        ctx->kSharedSz = 0;
        ctx->state = WC_SPAKE2P_STATE_FAILED;
    }

    return ret;
}

/* Retrieve K_shared (RFC 9383, Section 3.4). Only available once the peer's
 * confirmation has been verified, so an unconfirmed key is never released.
 * May be called more than once; nothing changes in the context.
 *
 * @param  [in]       ctx    Confirmed context.
 * @param  [out]      key    Buffer that receives K_shared.
 * @param  [in, out]  keySz  On in, size of key. On out, bytes written.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a pointer is NULL.
 * @return  BAD_STATE_E when the peer's confirmation has not been verified.
 * @return  BUFFER_E when *keySz is too small.
 */
int wc_Spake2pGetSharedKey(wc_Spake2p* ctx, byte* key, word32* keySz)
{
    if ((ctx == NULL) || (key == NULL) || (keySz == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (ctx->state != WC_SPAKE2P_STATE_CONFIRMED) {
        return BAD_STATE_E;
    }
    if (*keySz < ctx->kSharedSz) {
        return BUFFER_E;
    }

    XMEMCPY(key, ctx->kShared, ctx->kSharedSz);
    *keySz = ctx->kSharedSz;

    return 0;
}

/* ------------------------------------------------------------------------- */
/* Test hooks                                                                */
/* ------------------------------------------------------------------------- */

#ifdef WOLFSSL_SPAKE2P_TEST_HOOKS
/* Fix the ephemeral scalar (x for the Prover, y for the Verifier) used by
 * wc_Spake2pGenerateShare(), for known-answer tests only.
 *
 * The scalar must be exactly the group order length and in
 * [1, order - 1]. It is copied into the context and zeroized by
 * wc_Spake2pFree(). Calling again replaces it; on error the context is
 * unchanged.
 *
 * @param  [in, out]  ctx       Initialized context.
 * @param  [in]       scalar    Ephemeral scalar, big-endian.
 * @param  [in]       scalarSz  Length of scalar in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ctx or scalar is NULL, or the scalar is not
 *          valid for the suite.
 * @return  BAD_STATE_E when called after wc_Spake2pGenerateShare().
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int wc_Spake2pSetEphemeral(wc_Spake2p* ctx, const byte* scalar,
    word32 scalarSz)
{
    int ret;

    if ((ctx == NULL) || (scalar == NULL)) {
        return BAD_FUNC_ARG;
    }
    /* Same window as the transcript inputs: before the share exists. */
    if (!spake2p_transcript_settable(ctx)) {
        return BAD_STATE_E;
    }

    ret = spake2p_check_scalar(ctx->suite, scalar, scalarSz, ctx->heap);
    if (ret == 0) {
        /* A valid scalar is the order length, which fits eph. */
        XMEMCPY(ctx->eph, scalar, scalarSz);
        ctx->ephSz = scalarSz;
        ctx->ephSet = 1;
    }

    return ret;
}
#endif /* WOLFSSL_SPAKE2P_TEST_HOOKS */

#endif /* WOLFSSL_HAVE_SPAKE2P */
