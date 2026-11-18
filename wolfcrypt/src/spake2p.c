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
 * Implemented so far: wc_Spake2pDeriveW0W1().
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_HAVE_SPAKE2P

#include <wolfssl/wolfcrypt/spake2p.h>
#include <wolfssl/wolfcrypt/wolfmath.h>

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

#endif /* WOLFSSL_HAVE_SPAKE2P */
