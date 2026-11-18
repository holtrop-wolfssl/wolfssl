/* test_spake2p.h
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

#ifndef WOLFCRYPT_TEST_SPAKE2P_H
#define WOLFCRYPT_TEST_SPAKE2P_H

#include <tests/api/api_decl.h>

int test_wc_Spake2pDeriveW0W1(void);
int test_wc_Spake2pComputeL(void);
int test_wc_Spake2pInitFree(void);
int test_wc_Spake2pTranscriptInputs(void);
int test_wc_Spake2pSetSecrets(void);
int test_wc_Spake2pExchange(void);
int test_wc_Spake2pExchangeErrors(void);
int test_wc_Spake2pRfcVectors(void);

#define TEST_SPAKE2P_DECLS                                              \
    TEST_DECL_GROUP("spake2p", test_wc_Spake2pDeriveW0W1),              \
    TEST_DECL_GROUP("spake2p", test_wc_Spake2pComputeL),                \
    TEST_DECL_GROUP("spake2p", test_wc_Spake2pInitFree),                \
    TEST_DECL_GROUP("spake2p", test_wc_Spake2pTranscriptInputs),        \
    TEST_DECL_GROUP("spake2p", test_wc_Spake2pSetSecrets),              \
    TEST_DECL_GROUP("spake2p", test_wc_Spake2pExchange),                \
    TEST_DECL_GROUP("spake2p", test_wc_Spake2pExchangeErrors),          \
    TEST_DECL_GROUP("spake2p", test_wc_Spake2pRfcVectors)

#endif /* WOLFCRYPT_TEST_SPAKE2P_H */
