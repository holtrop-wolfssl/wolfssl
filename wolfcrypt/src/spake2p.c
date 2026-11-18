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
 * wc_Spake2pSetContext(), wc_Spake2pSetIdentities().
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_HAVE_SPAKE2P

#include <wolfssl/wolfcrypt/spake2p.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/wolfcrypt/ecc.h>

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
            case WC_SPAKE2P_P256_SHA256_HKDF_HMAC:
            case WC_SPAKE2P_P384_SHA256_HKDF_HMAC:
        #ifdef NO_HMAC
                ret = NOT_COMPILED_IN;
        #endif
                break;
            case WC_SPAKE2P_P256_SHA512_HKDF_HMAC:
            case WC_SPAKE2P_P384_SHA512_HKDF_HMAC:
            case WC_SPAKE2P_P521_SHA512_HKDF_HMAC:
        #if defined(NO_HMAC) || !defined(WOLFSSL_SHA512)
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

#if defined(HAVE_ECC_KEY_IMPORT) && defined(HAVE_ECC_KEY_EXPORT)
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
#endif /* HAVE_ECC_KEY_IMPORT && HAVE_ECC_KEY_EXPORT */

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

#endif /* WOLFSSL_HAVE_SPAKE2P */
