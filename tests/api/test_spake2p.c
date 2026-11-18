/* test_spake2p.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/spake2p.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <tests/api/api.h>
#include <tests/api/test_spake2p.h>

#ifdef WOLFSSL_HAVE_SPAKE2P

/* RFC 9383 Appendix C test vectors, one per supported ciphersuite. (The
 * RFC's P256-SHA512-HKDF-SHA512-CMAC-AES-128 suite is not implemented.)
 * The full exchange needs a fixed ephemeral scalar, so x, y, the shares,
 * MACs and K_shared are only checked with WOLFSSL_SPAKE2P_TEST_HOOKS; w0,
 * w1 and L are checked in every build. */
typedef struct Spake2pRfcVector {
    int         suite;
    const char* context;
    const char* idProver;
    const char* idVerifier;
    const char* w0;
    const char* w1;
    const char* L;
    const char* x;
    const char* shareP;
    const char* y;
    const char* shareV;
    const char* confirmP;   /* MAC(K_confirmP, shareV) */
    const char* confirmV;   /* MAC(K_confirmV, shareP) */
    const char* kShared;
} Spake2pRfcVector;

static const Spake2pRfcVector spake2pRfcVectors[] = {
    {
        WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
        "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors",
        "client", "server",
        /* w0 */
        "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3",
        /* w1 */
        "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba",
        /* L */
        "04eb7c9db3d9a9eb1f8adab81b5794c1f13ae3e225efbe91ea487425854c7fc0"
        "0f00bfedcbd09b2400142d40a14f2064ef31dfaa903b91d1faea7093d835966e"
        "fd",
        /* x */
        "d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539",
        /* shareP */
        "04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0"
        "c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e3417"
        "27",
        /* y */
        "717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3",
        /* shareV */
        "04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810"
        "fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b0"
        "48",
        /* macP */
        "926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527",
        /* macV */
        "9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68",
        /* K_shared */
        "0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7"
    },
    {
        WC_SPAKE2P_P256_SHA512_HKDF_HMAC,
        "SPAKE2+-P256-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors",
        "client", "server",
        /* w0 */
        "1cc5207d6e34b8f7828206fb64b86aa9c712bc952abf251bb9f5856b24d8c8cc",
        /* w1 */
        "4279649e62532b01dc27d2ed39100ba350518fb969672061a01edce752d0e672",
        /* L */
        "043a348ad475d2200d46df876f1eb2e136056da31dafff52cc7762bf3be84de0"
        "097c4e69b0b9321326af1f0af4a14561a9c7b640cb5afd6822d14cb34830fc45"
        "11",
        /* x */
        "b586ab83f175c1a2b56b6a1b6a283523f88a9befcf11e22efb48e2ee1fe69a23",
        /* shareP */
        "04a7928c4b47f6b8657a5b8ebcb6f1bd266192e152fb9745a4180c94657a2f32"
        "3b4d50d536c0325cdb0ec42c9bd8db8d7af3ff6dc85edb4b5365375c62e09def"
        "4a",
        /* y */
        "ac1fb828f041782d452ea9cc00c3fa34a55fa8f7f98c04be45a3d607b092d441",
        /* shareV */
        "04498c29e37dbd53ebf8db76679901d90c6be3af57f46ac3025b32420839f048"
        "9c6c3b6bf5ddc8ecbc3d7c83d0891ad814a00ad23eba13197c9d96a5b10275e3"
        "5d",
        /* macP */
        "6b2469b56cf8ac3f94a8d0b533380ea6b3d0f46b3e12ee82550d49e129c24127"
        "28c9437a64ee5f80c8cdc5e8a30faa0a6deb8a5251346ba81bb6fc955b2304fc",
        /* macV */
        "154174fc278a935e290b3352ba877e179fa9281c0a76928faea703c72d383b26"
        "7511a5cf084cb07147efece94e3cfd91944e7baab856858fbebc087167b0f409",
        /* K_shared */
        "11887659d9e002f34fa6cc270d33570f001b2a3fc0522b643c07327d09a4a9f4"
        "7aab85813d13c585b53adf5ac9de5707114848f3dc31a4045f69a2cc1972b098"
    },
    {
        WC_SPAKE2P_P384_SHA256_HKDF_HMAC,
        "SPAKE2+-P384-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors",
        "client", "server",
        /* w0 */
        "097a61cbb1cee72bb654be96d80f46e0e3531151003903b572fc193f233772c2"
        "3c22228884a0d5447d0ab49a656ce1d2",
        /* w1 */
        "18772816140e6c3c3938a693c600b2191118a34c7956e1f1cd5b0d519b56ea58"
        "58060966cfaf27679c9182129949e74f",
        /* L */
        "04f27dd5384d6b9beb4c5022c94b1978d632779e1d3abe458611e734a529d004"
        "e25053398e5dc9eeaa4ffa59743ca7ddbc0e7ce69155295cb2b846da83ee6a44"
        "490dd8e96bb0b0f6645281bfd978dd5f6836561ea0d8b2c045ff04cef2e5873d"
        "2c",
        /* x */
        "2f1bdbeda162ff2beba0293d3cd3ae95f663c53663378c7e18ee8f56a4a48b00"
        "d31ce0ef43606548da485058f12e8e73",
        /* shareP */
        "049fb0404ca7ce71fb85d3aaa8fd05fa054affac996135bc245149be09571e43"
        "e2bf76e00d6d52ac452b8224f6b9da31420a4f5e214b377546daad4d61da5ca0"
        "cfdea59a5a92ebdb6b42da5d14663b8d1f9eb97050139ab89788e0ada27b048f"
        "cf",
        /* y */
        "bbcaf02404a16ed4fa73b183f703a8d969386f3d34f5e98b3a904e760512f117"
        "57f07dfcf87a2ada8fc6d028445bd53e",
        /* shareV */
        "0493b1c1f6a30eac4ac4a15711e44640bae3576787627ee25411042981e94b2e"
        "9604b9374f66bb247bc431759212ef3fa0a20c087863b89efb32219e1337ce94"
        "be2175f8cb9fd50cf0b84772717fd063c52b69de1229a01ab840b55993287f32"
        "ed",
        /* macP */
        "7ae825e242a5a1f86ad7db172c2c12fcb458b6a2b1ddfc96b2b7cfd2eed5f7ab",
        /* macV */
        "1581062167d6a3d14493447cd170d408f6fdc58e31225438db86214167426a7a",
        /* K_shared */
        "99758e838ae1a856589689fb55b6befe4e2382e6ebbeca1a6232a68f9dc04c1a"
    },
    {
        WC_SPAKE2P_P384_SHA512_HKDF_HMAC,
        "SPAKE2+-P384-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors",
        "client", "server",
        /* w0 */
        "b8d44a0982b88abe19b724d4bdafba8c90dc93130e0bf4f8062810992326da12"
        "6fd01db53e40250ca33a3ff302044cb0",
        /* w1 */
        "2373e2071c3bb2a6d53ece57830d56f8080189816803c22375d6a4a514f9d161"
        "b64d0f05b97735b98b348f9b33cc2e30",
        /* L */
        "049ca7217ff6456bb2e2bcf71b31d9b1e5ed6e0c9700936ae617e990cee87ee1"
        "ce3a03629dd5532948c39b89f38b39f13c7f513c5b1ada00f6533a4a8b02b9cd"
        "04e1b2a5db1f24ec5fe959198a19666037e04b768cc02e75ac9da0048736db6e"
        "5b",
        /* x */
        "5a835d52714f30d2ef539268b89df9558628400063dfa0e41eb979066f4caf40"
        "9bbf7aab3ddddea13f1b070a1827d3d4",
        /* shareP */
        "042f382eef464a2c9aecfdf4b81d25c4de2de113ba67405ce336c762c69217ae"
        "7e27bda875144140d7536c4cc08b9b4dace5f872a6a2ed57f34042688ad3c5d4"
        "46c187dc0caf9cea812df3a4dd6fdbc64b9d7d7d7ff4bf6965abb06eeb108d55"
        "ee",
        /* y */
        "c883ee5b08cf7ba122038c279459ab1a730f85f2d624a02732d519faab56a498"
        "e773a8dec6c447ed02d5c00303a18bc4",
        /* shareV */
        "04d72e11eee332305062454c0a058b8103a3304785d445510cd8d101e9cb44cf"
        "b159cb7b72123abaf719ab1c42e0558c84c14b0886e8b446e4c880bff2f4b291"
        "fafafc748cb4115824e66732bdeba7fae176388e228ab9d7546255994ca3fb5a"
        "52",
        /* macP */
        "7f806ae56ea3e49a8b16ffee528086489418913641f529d50ff92aa456ad4648"
        "e522f9540b403bff6bd94ee1adc95c7d1b2666f7ba6f9c10748bc7bfb4181d27",
        /* macV */
        "8daa262decb79cceda4421f4f8dacf22ec027c08e036f071beea563c8e00813a"
        "29807963ff9d7d6bbff48dd5bdcdd9ca9fd7ffc272b162258d981913f7253dcb",
        /* K_shared */
        "31e0075a823b9269af5769d71ef3b2f5001cbfe044584fe8551124a217dad078"
        "415630bf3eda16b5a38341d418a6d72b3960f818a0926f0de88784b59d6a694b"
    },
    {
        WC_SPAKE2P_P521_SHA512_HKDF_HMAC,
        "SPAKE2+-P521-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors",
        "client", "server",
        /* w0 */
        "009c79bcd7656716314fca5a6e2c5cda7ef86131399438e012a043051e863f60"
        "b5aeb3c101731e1505e721580f48535a9b0456b231b9266ae6fff49ee90d25f7"
        "2f5f",
        /* w1 */
        "01632c15f51fcd916cd79e19075f8a69b72b0099922ad62ff8d540b469569f0a"
        "a027047aed2b3f242ea0ac4288b4e4db6a4e5946d8ad32b42192c5aa66d9ef8e"
        "1b33",
        /* L */
        "040135072d0fa36f9e80031294cef5c3c35b882a0efa2c66570d64a49f8bec6c"
        "66435bf65bb7c7b2a3e7dece491e02b4d567e7087dbc32fe0fae8af417dcb50b"
        "e6d704012a194588b690e6d3db492656f72ddea01fc1c7fcec0f5d34a5af0102"
        "939f6fdeae39c20cff74fcdb7f09855f0fc9520d20b0520b0b096b8d42c7c3d6"
        "8b4a66f751",
        /* x */
        "00b69e3bb15df82c9fa0057461334e2c66ab92fc9b8d3662eec81216ef5ddc4a"
        "43f19e90dedaa2d72502f69673a115984ffcf88e03a9364b07102114c5602cd9"
        "3c69",
        /* shareP */
        "0400a14431edf6852ff5fe868f8683e16e9e0a45d9e27f9a96442285ac6b161f"
        "c0bf267362a5ffb06f9cbd14b7a37e492146d77cae4c77812df00a91dbae09e2"
        "7e1fac00ae019317ef9768548325bca35ce258e6206fe03c6338b2eb889d09d9"
        "f11400a36cf6328a7e1f81c6c7a2af7ff1d9b5210768318f27e57b75b39b9fbf"
        "c7b37a60ab",
        /* y */
        "0056d01c5246fbde964c0493934b7ece89eafd943eb27d357880a2a22022499e"
        "249528c5707b1afe8794c8a1d60ceedaeed96dd0dd904ea075f096c9fec5da7d"
        "e496",
        /* shareV */
        "0401aa5af0f3027f63b7170572db5ff06dd1f3d6ea8ea771b26b434fbbc6c9de"
        "7d80975131c9c2e94d30c0ed2d62449c4c1b7e95037a85ed7598e415a2591263"
        "65e89500d0f2156b551b70416d719944736990f346f6f9ba4fbaf2f63e098736"
        "90bcf730582e0a7b03ffede50f5787b631d5021a94287f0a29a081b62b9f5a3b"
        "f393b001b3",
        /* macP */
        "f0f5c903dfa42fe367659656a26058cd984b76a8e91ae4d0fa4c13db149008e2"
        "ae57713fb230a627761174fefd263b9c10e9a4b6a3746cde59c5943040c17133",
        /* macV */
        "a8f7ab43f3a800171d3a3fb26d742e1ed236c2d5804ecd328f220a7d245cd2e3"
        "bfb6c0526983bff9229c94f70fe64ba9bb5a4d0dc10afcda64a4c96d4c3d81ad",
        /* K_shared */
        "d1c170e4e55efacb9db8abad286293ebd1dcf24f13973427b9632bbc323e42e4"
        "47afca2aa7f74f2af3fb5f51684ec543db854b7002cde6799c330b032ba8820a"
    },
    {
        WC_SPAKE2P_P256_SHA256_HKDF_CMAC_AES128,
        "SPAKE2+-P256-SHA256-HKDF-SHA256-CMAC-AES-128 Test Vectors",
        "client", "server",
        /* w0 */
        "9aad90c603cf16cec4ee40d81acd7a865130b28cc6d0664ae2e0f406aa47ed61",
        /* w1 */
        "872be859cec1e78d191882bd9c2f032af018a25016813788fe8954bfffc58c8e",
        /* L */
        "04d79a53698c5dd79e14b426e73b4a7f1b42469815fe24e8f53ce01579e902eb"
        "198d59f05bc451c41826b88e3db5476a69e197fdf474c75b387f6d40361c3fda"
        "35",
        /* x */
        "9d39a3511a007a7d3fe6af5555cf60301bcda503f2bf6634b2caf9e4fd0743a1",
        /* shareP */
        "04788218027ba4b17f7279ef0aef47a8733cf88b5bf65d6127ecadc78b8a0f65"
        "b9001f7e54719fb63c072ddd1e1a4adfb376dde37ba1aa2082362b6c2ca14a8e"
        "53",
        /* y */
        "9c3219841626325c68d89c22fb6c55611e3136442daa8b9b784db7242afff3ed",
        /* shareV */
        "04c05953ea9d1cd6248b8c61becd7d55e46237526d8b1e23495ea7566b7f6bc2"
        "4b3da1cfb2e88a975fcfb5dc4e72b5cbea509b1cfdd1ef8f8195fa8bf2bd5ca1"
        "e5",
        /* macP */
        "d340bc94a03feafd14491e316514ca5f",
        /* macV */
        "2b42d0fe76bcf9ccc208d06d60082f96",
        /* K_shared */
        "e832094adfc028bf288e49ab902fc208b7eeff084f259da7613c0479869d4fc9"
    },
};

#ifndef WC_NO_RNG
/* w0 * N on P-256 for the RFC 9383 P-256 vector's w0, computed
 * independently. As the peer share it makes shareV - w0*N the identity. */
static const char spake2pW0TimesN[] =
    "048b58955995f4f1a52bb5340107501a94844fc53c4b9fab949c74a3d320144e"
    "bae45beca1d2b0a7785a5737dc1779bbd5c5619788e05284f4eaa2174f6eec15"
    "43";
#endif /* !WC_NO_RNG */

/* wc_Spake2pDeriveW0W1() answers, computed independently:
 *   P-256: w0s = 01 02 .. 28, w1s = 29 2a .. 50 (40 bytes each)
 *   P-521: w0s = ff * 74, w1s = 80 00 * 73 (74 bytes each) */
static const char spake2pDerive256W0[] =
    "0e101214070605041155b315cb1c6f28abec21cff529b6e3d3e045e760833d5c";
static const char spake2pDerive256W1[] =
    "5e606263dedddcdc44044a821fd15c25abc36f002c137cb00cd3caf4b4b66c34";
static const char spake2pDerive521W0[] =
    "00000000000000000000000000000000000000000000000002d73cbc3e206834"
    "ca4019ff5b847b2d17e2251b23bb31dc28a2482470b763cdfb7fffffffffffff"
    "ffff";
static const char spake2pDerive521W1[] =
    "000000000000000000000000000000000000000000000000016b9e5e1f10341a"
    "65200cffadc23d968bf1128d91dd98ee14512412385bb1e6fdc0000000000000"
    "0000";

#define SPAKE2P_RFC_VECTOR_CNT \
    ((int)(sizeof(spake2pRfcVectors) / sizeof(spake2pRfcVectors[0])))

/* Whether the suite's curve, hash and MAC are compiled in. */
static int spake2p_suite_available(int suite)
{
    wc_Spake2p ctx;
    int ret = wc_Spake2pInit(&ctx, suite, WC_SPAKE2P_PROVER, NULL,
        INVALID_DEVID);
    wc_Spake2pFree(&ctx);
    return ret == 0;
}

static int spake2p_hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return c - 'A' + 10;
}

/* Decode a hex string into out; returns the number of bytes written. */
static word32 spake2p_unhex(const char* hex, byte* out, word32 outSz)
{
    word32 n = 0;

    while ((hex[0] != '\0') && (hex[1] != '\0') && (n < outSz)) {
        out[n++] = (byte)((spake2p_hexval(hex[0]) << 4) |
                          spake2p_hexval(hex[1]));
        hex += 2;
    }
    return n;
}

static int spake2p_all_zero(const byte* b, word32 sz)
{
    word32 i;

    for (i = 0; i < sz; i++) {
        if (b[i] != 0)
            return 0;
    }
    return 1;
}

#ifndef WC_NO_RNG
/* Order (scalar) size for a suite. */
static word32 spake2p_order_sz(int suite)
{
    switch (suite) {
        case WC_SPAKE2P_P384_SHA256_HKDF_HMAC:
        case WC_SPAKE2P_P384_SHA512_HKDF_HMAC:
            return 48;
        case WC_SPAKE2P_P521_SHA512_HKDF_HMAC:
            return 66;
        default:
            return 32;
    }
}

/* K_shared (hash) length for a suite. */
static word32 spake2p_hash_sz(int suite)
{
    switch (suite) {
        case WC_SPAKE2P_P256_SHA512_HKDF_HMAC:
        case WC_SPAKE2P_P384_SHA512_HKDF_HMAC:
        case WC_SPAKE2P_P521_SHA512_HKDF_HMAC:
            return 64;
        default:
            return 32;
    }
}

/* A registration record made the way an application would. */
typedef struct Spake2pRecord {
    byte   w0[WC_SPAKE2P_MAX_SCALAR_SZ];
    byte   w1[WC_SPAKE2P_MAX_SCALAR_SZ];
    byte   L[WC_SPAKE2P_MAX_L_SZ];
    word32 sz;
    word32 LSz;
} Spake2pRecord;

static int spake2p_make_record(WC_RNG* rng, int suite, Spake2pRecord* rec)
{
    int ret;
    byte ws[2 * (WC_SPAKE2P_MAX_SCALAR_SZ + 8)];
    word32 half = spake2p_order_sz(suite) + 8;
    word32 w0Sz = sizeof(rec->w0);
    word32 w1Sz = sizeof(rec->w1);

    rec->LSz = sizeof(rec->L);
    ret = wc_RNG_GenerateBlock(rng, ws, 2 * half);
    if (ret == 0) {
        ret = wc_Spake2pDeriveW0W1(suite, ws, half, ws + half, half,
            rec->w0, &w0Sz, rec->w1, &w1Sz, NULL);
    }
    if (ret == 0) {
        rec->sz = w0Sz;
        ret = wc_Spake2pComputeL(suite, rec->w1, w1Sz, rec->L, &rec->LSz,
            NULL, INVALID_DEVID);
    }
    return ret;
}

/* Run the protocol to the point where both sides have processed the peer's
 * share. On success *p and *v must be freed by the caller. */
static int spake2p_exchange(WC_RNG* rng, int suite, wc_Spake2p* p,
    wc_Spake2p* v, const Spake2pRecord* recP, const Spake2pRecord* recV,
    const char* ctxP, const char* ctxV, const char* idP, const char* idV,
    byte* confP, word32* confPSz, byte* confV, word32* confVSz)
{
    int ret;
    byte shareP[WC_SPAKE2P_MAX_SHARE_SZ];
    byte shareV[WC_SPAKE2P_MAX_SHARE_SZ];
    word32 sharePSz = sizeof(shareP);
    word32 shareVSz = sizeof(shareV);

    ret = wc_Spake2pInit(p, suite, WC_SPAKE2P_PROVER, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_Spake2pInit(v, suite, WC_SPAKE2P_VERIFIER, NULL,
            INVALID_DEVID);
    if (ret == 0)
        ret = wc_Spake2pSetContext(p, (const byte*)ctxP,
            (word32)XSTRLEN(ctxP));
    if (ret == 0)
        ret = wc_Spake2pSetContext(v, (const byte*)ctxV,
            (word32)XSTRLEN(ctxV));
    if (ret == 0)
        ret = wc_Spake2pSetIdentities(p, (const byte*)idP,
            (word32)XSTRLEN(idP), (const byte*)"server", 6);
    if (ret == 0)
        ret = wc_Spake2pSetIdentities(v, (const byte*)idV,
            (word32)XSTRLEN(idV), (const byte*)"server", 6);
    if (ret == 0)
        ret = wc_Spake2pSetProverSecrets(p, recP->w0, recP->sz, recP->w1,
            recP->sz);
    if (ret == 0)
        ret = wc_Spake2pSetVerifierSecrets(v, recV->w0, recV->sz, recV->L,
            recV->LSz);
    if (ret == 0)
        ret = wc_Spake2pGenerateShare(p, rng, shareP, &sharePSz);
    if (ret == 0)
        ret = wc_Spake2pGenerateShare(v, rng, shareV, &shareVSz);
    if (ret == 0)
        ret = wc_Spake2pProcessPeerShare(v, shareP, sharePSz, confV,
            confVSz);
    if (ret == 0)
        ret = wc_Spake2pProcessPeerShare(p, shareV, shareVSz, confP,
            confPSz);
    return ret;
}
#endif /* !WC_NO_RNG */

#endif /* WOLFSSL_HAVE_SPAKE2P */

/*
 * wc_Spake2pDeriveW0W1(): reduction of the PBKDF output halves modulo the
 * group order, padding to the order length, length bounds and errors.
 */
int test_wc_Spake2pDeriveW0W1(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HAVE_SPAKE2P
    byte in0[2 * 66 + 1];
    byte in1[2 * 66 + 1];
    byte w0[WC_SPAKE2P_MAX_SCALAR_SZ + 4];
    byte w1[WC_SPAKE2P_MAX_SCALAR_SZ + 4];
    byte exp[WC_SPAKE2P_MAX_SCALAR_SZ];
    word32 w0Sz;
    word32 w1Sz;
    word32 i;
    const int s = WC_SPAKE2P_P256_SHA256_HKDF_HMAC;

    /* P-256 known answer (recommended 40-byte halves). */
    for (i = 0; i < 40; i++) {
        in0[i] = (byte)(i + 1);
        in1[i] = (byte)(i + 41);
    }
    w0Sz = w1Sz = sizeof(w0);
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 40, in1, 40, w0, &w0Sz, w1,
        &w1Sz, NULL), 0);
    ExpectIntEQ(w0Sz, 32);
    ExpectIntEQ(w1Sz, 32);
    ExpectIntEQ(spake2p_unhex(spake2pDerive256W0, exp, sizeof(exp)), 32);
    ExpectBufEQ(w0, exp, 32);
    ExpectIntEQ(spake2p_unhex(spake2pDerive256W1, exp, sizeof(exp)), 32);
    ExpectBufEQ(w1, exp, 32);

    /* P-521 known answer: results with leading zero bytes are padded to the
     * 66-byte order length. */
    if (spake2p_suite_available(WC_SPAKE2P_P521_SHA512_HKDF_HMAC)) {
        XMEMSET(in0, 0xFF, 74);
        XMEMSET(in1, 0x00, 74);
        in1[0] = 0x80;
        w0Sz = w1Sz = sizeof(w0);
        ExpectIntEQ(wc_Spake2pDeriveW0W1(WC_SPAKE2P_P521_SHA512_HKDF_HMAC,
            in0, 74, in1, 74, w0, &w0Sz, w1, &w1Sz, NULL), 0);
        ExpectIntEQ(w0Sz, 66);
        ExpectIntEQ(spake2p_unhex(spake2pDerive521W0, exp, sizeof(exp)), 66);
        ExpectBufEQ(w0, exp, 66);
        ExpectIntEQ(spake2p_unhex(spake2pDerive521W1, exp, sizeof(exp)), 66);
        ExpectBufEQ(w1, exp, 66);
    }

    /* Input equal to the order reduces to zero; order - 1 is unchanged. */
    ExpectIntEQ(spake2p_unhex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        in0, sizeof(in0)), 32);
    XMEMCPY(in1, in0, 32);
    in1[31]--;
    w0Sz = w1Sz = 32;
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 32, in1, 32, w0, &w0Sz, w1,
        &w1Sz, NULL), 0);
    ExpectTrue(spake2p_all_zero(w0, 32));
    ExpectBufEQ(w1, in1, 32);

    /* Larger output buffers: only the order length is written. */
    XMEMSET(w0, 0xAA, sizeof(w0));
    w0Sz = w1Sz = sizeof(w0);
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in1, 32, in1, 32, w0, &w0Sz, w1,
        &w1Sz, NULL), 0);
    ExpectIntEQ(w0Sz, 32);
    ExpectIntEQ(w0[32], 0xAA);

    /* Input lengths: [order length, 2 * order length]. */
    w0Sz = w1Sz = 32;
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 31, in1, 40, w0, &w0Sz, w1,
        &w1Sz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 40, in1, 31, w0, &w0Sz, w1,
        &w1Sz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 65, in1, 40, w0, &w0Sz, w1,
        &w1Sz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 40, in1, 65, w0, &w0Sz, w1,
        &w1Sz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 64, in1, 64, w0, &w0Sz, w1,
        &w1Sz, NULL), 0);

    /* Output too small: BUFFER_E, nothing written, sizes unchanged. */
    XMEMSET(w0, 0xAA, sizeof(w0));
    w0Sz = 31;
    w1Sz = 32;
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 40, in1, 40, w0, &w0Sz, w1,
        &w1Sz, NULL), WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(w0Sz, 31);
    ExpectIntEQ(w0[0], 0xAA);
    w0Sz = 32;
    w1Sz = 31;
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 40, in1, 40, w0, &w0Sz, w1,
        &w1Sz, NULL), WC_NO_ERR_TRACE(BUFFER_E));

    /* NULL pointers and unknown suites. */
    w0Sz = w1Sz = 32;
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, NULL, 40, in1, 40, w0, &w0Sz, w1,
        &w1Sz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 40, NULL, 40, w0, &w0Sz, w1,
        &w1Sz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 40, in1, 40, NULL, &w0Sz, w1,
        &w1Sz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 40, in1, 40, w0, NULL, w1,
        &w1Sz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 40, in1, 40, w0, &w0Sz, NULL,
        &w1Sz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pDeriveW0W1(s, in0, 40, in1, 40, w0, &w0Sz, w1,
        NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pDeriveW0W1(0, in0, 40, in1, 40, w0, &w0Sz, w1,
        &w1Sz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pDeriveW0W1(7, in0, 40, in1, 40, w0, &w0Sz, w1,
        &w1Sz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif /* WOLFSSL_HAVE_SPAKE2P */
    return EXPECT_RESULT();
}

/*
 * wc_Spake2pComputeL(): L = w1 * P against every RFC 9383 vector, scalar
 * validation, buffer sizing and errors.
 */
int test_wc_Spake2pComputeL(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HAVE_SPAKE2P
    byte w1[WC_SPAKE2P_MAX_SCALAR_SZ + 1];
    byte L[WC_SPAKE2P_MAX_L_SZ + 1];
    byte exp[WC_SPAKE2P_MAX_L_SZ];
    word32 w1Sz;
    word32 LSz;
    word32 expSz;
    int i;
    const int s = WC_SPAKE2P_P256_SHA256_HKDF_HMAC;

    for (i = 0; i < SPAKE2P_RFC_VECTOR_CNT; i++) {
        const Spake2pRfcVector* v = &spake2pRfcVectors[i];
        if (!spake2p_suite_available(v->suite))
            continue;
        w1Sz = spake2p_unhex(v->w1, w1, sizeof(w1));
        expSz = spake2p_unhex(v->L, exp, sizeof(exp));
        LSz = sizeof(L);
        ExpectIntEQ(wc_Spake2pComputeL(v->suite, w1, w1Sz, L, &LSz, NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(LSz, expSz);
        ExpectBufEQ(L, exp, expSz);
    }

    /* Invalid scalars: zero, the order, all ones, wrong length. */
    XMEMSET(w1, 0, sizeof(w1));
    LSz = sizeof(L);
    ExpectIntEQ(wc_Spake2pComputeL(s, w1, 32, L, &LSz, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(spake2p_unhex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        w1, sizeof(w1)), 32);
    ExpectIntEQ(wc_Spake2pComputeL(s, w1, 32, L, &LSz, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(w1, 0xFF, sizeof(w1));
    ExpectIntEQ(wc_Spake2pComputeL(s, w1, 32, L, &LSz, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(w1, 0, sizeof(w1));
    w1[32] = 1;
    ExpectIntEQ(wc_Spake2pComputeL(s, w1, 33, L, &LSz, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pComputeL(s, w1 + 2, 31, L, &LSz, NULL,
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* w1 = 1 gives the generator; buffer exactly, one short, larger. */
    XMEMSET(w1, 0, 32);
    w1[31] = 1;
    LSz = 65;
    ExpectIntEQ(wc_Spake2pComputeL(s, w1, 32, L, &LSz, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(LSz, 65);
    ExpectIntEQ(spake2p_unhex(
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        exp, sizeof(exp)), 65);
    ExpectBufEQ(L, exp, 65);
    XMEMSET(L, 0xAA, sizeof(L));
    LSz = 64;
    ExpectIntEQ(wc_Spake2pComputeL(s, w1, 32, L, &LSz, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(LSz, 64);
    ExpectIntEQ(L[0], 0xAA);
    LSz = sizeof(L);
    ExpectIntEQ(wc_Spake2pComputeL(s, w1, 32, L, &LSz, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(LSz, 65);
    ExpectIntEQ(L[65], 0xAA);

    /* NULL pointers and unknown suites. */
    ExpectIntEQ(wc_Spake2pComputeL(s, NULL, 32, L, &LSz, NULL,
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pComputeL(s, w1, 32, NULL, &LSz, NULL,
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pComputeL(s, w1, 32, L, NULL, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pComputeL(0, w1, 32, L, &LSz, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pComputeL(7, w1, 32, L, &LSz, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif /* WOLFSSL_HAVE_SPAKE2P */
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_HAVE_SPAKE2P) && !defined(WC_NO_CONSTRUCTORS) && \
    defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY)
#define SPAKE2P_OOM_TEST
/* Allocator that fails the next allocation when armed, and otherwise calls
 * through to the allocators in place before the test. */
static wolfSSL_Malloc_cb  spake2p_oom_mf;
static wolfSSL_Free_cb    spake2p_oom_ff;
static wolfSSL_Realloc_cb spake2p_oom_rf;
static int                spake2p_oom_fail;

static void* spake2p_oom_malloc(size_t n)
{
    if (spake2p_oom_fail) {
        spake2p_oom_fail = 0;
        return NULL;
    }
    return (spake2p_oom_mf != NULL) ? spake2p_oom_mf(n) : malloc(n);
}

static void spake2p_oom_free(void* p)
{
    if (spake2p_oom_ff != NULL)
        spake2p_oom_ff(p);
    else
        free(p);
}

static void* spake2p_oom_realloc(void* p, size_t n)
{
    return (spake2p_oom_rf != NULL) ? spake2p_oom_rf(p, n) : realloc(p, n);
}
#endif

/*
 * wc_Spake2pInit(), wc_Spake2pFree(), wc_Spake2pNew(), wc_Spake2pDelete().
 */
int test_wc_Spake2pInitFree(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HAVE_SPAKE2P
    wc_Spake2p ctx;
    int suite;
    int role;
#ifndef WC_NO_CONSTRUCTORS
    wc_Spake2p* p = NULL;
    int rc;
#endif

    /* Every suite and role; suites not compiled in are NOT_COMPILED_IN. */
    for (suite = WC_SPAKE2P_P256_SHA256_HKDF_HMAC;
            suite <= WC_SPAKE2P_P256_SHA256_HKDF_CMAC_AES128; suite++) {
        for (role = WC_SPAKE2P_PROVER; role <= WC_SPAKE2P_VERIFIER; role++) {
            int ret;
            XMEMSET(&ctx, 0xA5, sizeof(ctx));
            ret = wc_Spake2pInit(&ctx, suite, role, NULL, 7);
            if (ret == 0) {
                ExpectIntEQ(ctx.suite, suite);
                ExpectIntEQ(ctx.role, role);
                ExpectIntEQ(ctx.state, WC_SPAKE2P_STATE_INIT);
                ExpectIntEQ(ctx.devId, 7);
                ExpectNull(ctx.heap);
                ExpectNull(ctx.context);
                ExpectNull(ctx.idProver);
                ExpectNull(ctx.idVerifier);
                ExpectTrue(spake2p_all_zero(ctx.w0, sizeof(ctx.w0)));
            }
            else {
                ExpectIntEQ(ret, WC_NO_ERR_TRACE(NOT_COMPILED_IN));
                ExpectTrue(spake2p_all_zero((const byte*)&ctx,
                    sizeof(ctx)));
            }
            wc_Spake2pFree(&ctx);
        }
    }

    /* Errors: ctx zeroed before the check, so Free is always safe. */
    ExpectIntEQ(wc_Spake2pInit(NULL, WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
        WC_SPAKE2P_PROVER, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(&ctx, 0xA5, sizeof(ctx));
    ExpectIntEQ(wc_Spake2pInit(&ctx, 0, WC_SPAKE2P_PROVER, NULL,
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectTrue(spake2p_all_zero((const byte*)&ctx, sizeof(ctx)));
    wc_Spake2pFree(&ctx);
    ExpectIntEQ(wc_Spake2pInit(&ctx, 7, WC_SPAKE2P_PROVER, NULL,
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(&ctx, 0xA5, sizeof(ctx));
    ExpectIntEQ(wc_Spake2pInit(&ctx, WC_SPAKE2P_P256_SHA256_HKDF_HMAC, 2,
        NULL, INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectTrue(spake2p_all_zero((const byte*)&ctx, sizeof(ctx)));
    wc_Spake2pFree(&ctx);
    ExpectIntEQ(wc_Spake2pInit(&ctx, WC_SPAKE2P_P256_SHA256_HKDF_HMAC, -1,
        NULL, INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_Spake2pFree(&ctx);

    /* Free: NULL is a no-op; owned strings released; everything zeroed;
     * a second Free is a no-op; Init again afterwards. */
    wc_Spake2pFree(NULL);
    ExpectIntEQ(wc_Spake2pInit(&ctx, WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
        WC_SPAKE2P_PROVER, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Spake2pSetContext(&ctx, (const byte*)"ctx", 3), 0);
    ExpectIntEQ(wc_Spake2pSetIdentities(&ctx, (const byte*)"alice", 5,
        (const byte*)"server", 6), 0);
    wc_Spake2pFree(&ctx);
    ExpectTrue(spake2p_all_zero((const byte*)&ctx, sizeof(ctx)));
    wc_Spake2pFree(&ctx);
    ExpectIntEQ(wc_Spake2pInit(&ctx, WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
        WC_SPAKE2P_VERIFIER, NULL, INVALID_DEVID), 0);
    wc_Spake2pFree(&ctx);

#ifndef WC_NO_CONSTRUCTORS
    /* New/Delete. */
    rc = 12345;
    ExpectNotNull(p = wc_Spake2pNew(WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
        WC_SPAKE2P_VERIFIER, NULL, INVALID_DEVID, &rc));
    ExpectIntEQ(rc, 0);
    if (p != NULL) {
        ExpectIntEQ(wc_Spake2pSetContext(p, (const byte*)"ctx", 3), 0);
    }
    ExpectIntEQ(wc_Spake2pDelete(p, &p), 0);
    ExpectNull(p);
    ExpectNotNull(p = wc_Spake2pNew(WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
        WC_SPAKE2P_PROVER, NULL, INVALID_DEVID, NULL));
    ExpectIntEQ(wc_Spake2pDelete(p, NULL), 0);
    p = NULL;

    ExpectNull(wc_Spake2pNew(0, WC_SPAKE2P_PROVER, NULL, INVALID_DEVID,
        &rc));
    ExpectIntEQ(rc, WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectNull(wc_Spake2pNew(WC_SPAKE2P_P256_SHA256_HKDF_HMAC, 9, NULL,
        INVALID_DEVID, &rc));
    ExpectIntEQ(rc, WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectNull(wc_Spake2pNew(0, 0, NULL, INVALID_DEVID, NULL));
    ExpectIntEQ(wc_Spake2pDelete(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pDelete(NULL, &p), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#if defined(SPAKE2P_OOM_TEST) && defined(USE_WOLFSSL_MEMORY)
    /* Allocation failure in New. */
    ExpectIntEQ(wolfSSL_GetAllocators(&spake2p_oom_mf, &spake2p_oom_ff,
        &spake2p_oom_rf), 0);
    ExpectIntEQ(wolfSSL_SetAllocators(spake2p_oom_malloc, spake2p_oom_free,
        spake2p_oom_realloc), 0);
    spake2p_oom_fail = 1;
    rc = 0;
    ExpectNull(wc_Spake2pNew(WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
        WC_SPAKE2P_PROVER, NULL, INVALID_DEVID, &rc));
    ExpectIntEQ(rc, WC_NO_ERR_TRACE(MEMORY_E));
    spake2p_oom_fail = 0;
    (void)wolfSSL_SetAllocators(spake2p_oom_mf, spake2p_oom_ff,
        spake2p_oom_rf);
#endif
#endif /* !WC_NO_CONSTRUCTORS */
#endif /* WOLFSSL_HAVE_SPAKE2P */
    return EXPECT_RESULT();
}

/*
 * wc_Spake2pSetContext() and wc_Spake2pSetIdentities(): copies, replacement,
 * empty values, aliasing, argument and state errors.
 */
int test_wc_Spake2pTranscriptInputs(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HAVE_SPAKE2P
    wc_Spake2p ctx;
    byte buf[32];
    int st;

    XMEMSET(&ctx, 0, sizeof(ctx));
    ExpectIntEQ(wc_Spake2pInit(&ctx, WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
        WC_SPAKE2P_PROVER, NULL, INVALID_DEVID), 0);

    /* Copied: the caller's buffer may be reused. */
    XMEMCPY(buf, "MyApp SPAKE2+ v1", 16);
    ExpectIntEQ(wc_Spake2pSetContext(&ctx, buf, 16), 0);
    XMEMSET(buf, 'X', sizeof(buf));
    ExpectIntEQ(ctx.contextSz, 16);
    ExpectBufEQ(ctx.context, "MyApp SPAKE2+ v1", 16);
    /* Replace (shorter, longer), then pass the current copy back in. */
    ExpectIntEQ(wc_Spake2pSetContext(&ctx, (const byte*)"v2", 2), 0);
    ExpectIntEQ(ctx.contextSz, 2);
    ExpectIntEQ(wc_Spake2pSetContext(&ctx,
        (const byte*)"a much longer context", 21), 0);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wc_Spake2pSetContext(&ctx, ctx.context + 2, 4), 0);
    }
    ExpectIntEQ(ctx.contextSz, 4);
    ExpectBufEQ(ctx.context, "much", 4);
    /* Empty: NULL/0 and non-NULL/0. */
    ExpectIntEQ(wc_Spake2pSetContext(&ctx, NULL, 0), 0);
    ExpectNull(ctx.context);
    ExpectIntEQ(ctx.contextSz, 0);
    ExpectIntEQ(wc_Spake2pSetContext(&ctx, buf, 0), 0);
    ExpectNull(ctx.context);
    /* Errors leave the value unchanged. */
    ExpectIntEQ(wc_Spake2pSetContext(&ctx, (const byte*)"keep", 4), 0);
    ExpectIntEQ(wc_Spake2pSetContext(NULL, buf, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetContext(&ctx, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(ctx.contextSz, 4);
    ExpectBufEQ(ctx.context, "keep", 4);

    /* Identities. */
    ExpectIntEQ(wc_Spake2pSetIdentities(&ctx, (const byte*)"alice", 5,
        (const byte*)"server", 6), 0);
    ExpectIntEQ(ctx.idProverSz, 5);
    ExpectBufEQ(ctx.idProver, "alice", 5);
    ExpectIntEQ(ctx.idVerifierSz, 6);
    ExpectBufEQ(ctx.idVerifier, "server", 6);
    ExpectIntEQ(wc_Spake2pSetIdentities(&ctx, (const byte*)"bob", 3, NULL,
        0), 0);
    ExpectIntEQ(ctx.idProverSz, 3);
    ExpectNull(ctx.idVerifier);
    ExpectIntEQ(wc_Spake2pSetIdentities(&ctx, NULL, 0, NULL, 0), 0);
    ExpectNull(ctx.idProver);
    ExpectNull(ctx.idVerifier);
    /* Swap the two identities through the current copies. */
    ExpectIntEQ(wc_Spake2pSetIdentities(&ctx, (const byte*)"alice", 5,
        (const byte*)"server", 6), 0);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wc_Spake2pSetIdentities(&ctx, ctx.idVerifier,
            ctx.idVerifierSz, ctx.idProver, ctx.idProverSz), 0);
    }
    ExpectBufEQ(ctx.idProver, "server", 6);
    ExpectBufEQ(ctx.idVerifier, "alice", 5);
    ExpectIntEQ(wc_Spake2pSetIdentities(NULL, buf, 1, buf, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetIdentities(&ctx, NULL, 1, buf, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetIdentities(&ctx, buf, 1, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectBufEQ(ctx.idProver, "server", 6);

    /* Allowed until the share is generated. */
    ctx.state = WC_SPAKE2P_STATE_SECRETS;
    ExpectIntEQ(wc_Spake2pSetContext(&ctx, (const byte*)"sec", 3), 0);
    ExpectIntEQ(wc_Spake2pSetIdentities(&ctx, (const byte*)"p", 1,
        (const byte*)"v", 1), 0);
    for (st = WC_SPAKE2P_STATE_SHARE; st <= WC_SPAKE2P_STATE_FAILED; st++) {
        ctx.state = (byte)st;
        ExpectIntEQ(wc_Spake2pSetContext(&ctx, (const byte*)"late", 4),
            WC_NO_ERR_TRACE(BAD_STATE_E));
        ExpectIntEQ(wc_Spake2pSetIdentities(&ctx, (const byte*)"x", 1,
            (const byte*)"y", 1), WC_NO_ERR_TRACE(BAD_STATE_E));
    }
    ExpectBufEQ(ctx.context, "sec", 3);
    ExpectBufEQ(ctx.idProver, "p", 1);

    wc_Spake2pFree(&ctx);
#endif /* WOLFSSL_HAVE_SPAKE2P */
    return EXPECT_RESULT();
}

/*
 * wc_Spake2pSetProverSecrets() and wc_Spake2pSetVerifierSecrets(): RFC 9383
 * records, scalar and point validation, role and state errors.
 */
int test_wc_Spake2pSetSecrets(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HAVE_SPAKE2P
    wc_Spake2p ctx;
    byte w0[WC_SPAKE2P_MAX_SCALAR_SZ];
    byte w1[WC_SPAKE2P_MAX_SCALAR_SZ];
    byte L[WC_SPAKE2P_MAX_L_SZ];
    byte bad[WC_SPAKE2P_MAX_L_SZ + 1];
    word32 w0Sz;
    word32 w1Sz;
    word32 LSz;
    int i;
    int st;
    const int s = WC_SPAKE2P_P256_SHA256_HKDF_HMAC;
    static const byte tags[] = { 0x00, 0x02, 0x03, 0x05, 0x06, 0x07 };

    XMEMSET(&ctx, 0, sizeof(ctx));

    /* RFC 9383 registration records load for both roles. */
    for (i = 0; i < SPAKE2P_RFC_VECTOR_CNT; i++) {
        const Spake2pRfcVector* v = &spake2pRfcVectors[i];
        if (!spake2p_suite_available(v->suite))
            continue;
        w0Sz = spake2p_unhex(v->w0, w0, sizeof(w0));
        w1Sz = spake2p_unhex(v->w1, w1, sizeof(w1));
        LSz = spake2p_unhex(v->L, L, sizeof(L));
        ExpectIntEQ(wc_Spake2pInit(&ctx, v->suite, WC_SPAKE2P_PROVER, NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, w0, w0Sz, w1, w1Sz), 0);
        ExpectIntEQ(ctx.state, WC_SPAKE2P_STATE_SECRETS);
        wc_Spake2pFree(&ctx);
        ExpectIntEQ(wc_Spake2pInit(&ctx, v->suite, WC_SPAKE2P_VERIFIER,
            NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, w0Sz, L, LSz), 0);
        ExpectIntEQ(ctx.state, WC_SPAKE2P_STATE_SECRETS);
        wc_Spake2pFree(&ctx);
    }

    /* P-256 record from the first vector. */
    w0Sz = spake2p_unhex(spake2pRfcVectors[0].w0, w0, sizeof(w0));
    w1Sz = spake2p_unhex(spake2pRfcVectors[0].w1, w1, sizeof(w1));
    LSz = spake2p_unhex(spake2pRfcVectors[0].L, L, sizeof(L));

    /* Prover: errors leave the context in INIT and usable. */
    ExpectIntEQ(wc_Spake2pInit(&ctx, s, WC_SPAKE2P_PROVER, NULL,
        INVALID_DEVID), 0);
    ExpectIntEQ(wc_Spake2pSetProverSecrets(NULL, w0, 32, w1, 32),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, NULL, 32, w1, 32),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, w0, 32, NULL, 32),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, w0, 31, w1, 32),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, w0, 32, w1, 33),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(bad, 0, sizeof(bad));
    ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, bad, 32, w1, 32),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, w0, 32, bad, 32),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(bad, 0xFF, sizeof(bad));
    ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, bad, 32, w1, 32),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, 32, L, LSz),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectIntEQ(ctx.state, WC_SPAKE2P_STATE_INIT);
    ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, w0, w0Sz, w1, w1Sz), 0);
    ExpectBufEQ(ctx.w0, w0, 32);
    ExpectBufEQ(ctx.sec.w1, w1, 32);
    ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, w1, 32, w0, 32),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectBufEQ(ctx.w0, w0, 32);
    wc_Spake2pFree(&ctx);
    ExpectTrue(spake2p_all_zero(ctx.w0, sizeof(ctx.w0)));

    /* Verifier: point validation. */
    ExpectIntEQ(wc_Spake2pInit(&ctx, s, WC_SPAKE2P_VERIFIER, NULL,
        INVALID_DEVID), 0);
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(NULL, w0, 32, L, LSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, NULL, 32, L, LSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, 32, NULL, LSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, 31, L, LSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, w0, 32, w1, 32),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, 32, L, 64),
        WC_NO_ERR_TRACE(IS_POINT_E));
    XMEMCPY(bad, L, 65);
    bad[65] = 0;
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, 32, bad, 66),
        WC_NO_ERR_TRACE(IS_POINT_E));
    /* Compressed form of a valid point. */
    bad[0] = (byte)(0x02 | (L[64] & 1));
    XMEMCPY(bad + 1, L + 1, 32);
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, 32, bad, 33),
        WC_NO_ERR_TRACE(IS_POINT_E));
    for (i = 0; i < (int)sizeof(tags); i++) {
        XMEMCPY(bad, L, 65);
        bad[0] = tags[i];
        ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, 32, bad, 65),
            WC_NO_ERR_TRACE(IS_POINT_E));
    }
    /* SEC1 infinity (single 0x00) and the uncompressed all-zero form. */
    bad[0] = 0x00;
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, 32, bad, 1),
        WC_NO_ERR_TRACE(IS_POINT_E));
    XMEMSET(bad, 0, 65);
    bad[0] = 0x04;
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, 32, bad, 65),
        WC_NO_ERR_TRACE(ECC_INF_E));
    /* Off the curve, and X out of the field range (X = p). */
    XMEMCPY(bad, L, 65);
    bad[64] ^= 0x01;
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, 32, bad, 65),
        WC_NO_ERR_TRACE(IS_POINT_E));
    XMEMCPY(bad, L, 65);
    ExpectIntEQ(spake2p_unhex(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        bad + 1, 32), 32);
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, 32, bad, 65),
        WC_NO_ERR_TRACE(IS_POINT_E));
    ExpectIntEQ(ctx.state, WC_SPAKE2P_STATE_INIT);
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, w0Sz, L, LSz), 0);
    ExpectBufEQ(ctx.sec.L, L, LSz);
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, w0Sz, L, LSz),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    wc_Spake2pFree(&ctx);

    /* Later states refuse. */
    ExpectIntEQ(wc_Spake2pInit(&ctx, s, WC_SPAKE2P_PROVER, NULL,
        INVALID_DEVID), 0);
    for (st = WC_SPAKE2P_STATE_SHARE; st <= WC_SPAKE2P_STATE_FAILED; st++) {
        ctx.state = (byte)st;
        ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, w0, 32, w1, 32),
            WC_NO_ERR_TRACE(BAD_STATE_E));
    }
    wc_Spake2pFree(&ctx);
#endif /* WOLFSSL_HAVE_SPAKE2P */
    return EXPECT_RESULT();
}

/*
 * Full exchanges through the public API in RFC 9383 message order, every
 * available suite: both sides confirm and agree on K_shared; a mismatched
 * password, context, identity or hash means no agreement.
 */
int test_wc_Spake2pExchange(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SPAKE2P) && !defined(WC_NO_RNG)
    WC_RNG rng;
    wc_Spake2p p;
    wc_Spake2p v;
    Spake2pRecord rec1;
    Spake2pRecord rec2;
    byte confP[WC_SPAKE2P_MAX_CONFIRM_SZ];
    byte confV[WC_SPAKE2P_MAX_CONFIRM_SZ];
    byte keyP[WC_SPAKE2P_MAX_KEY_SZ];
    byte keyV[WC_SPAKE2P_MAX_KEY_SZ];
    byte prev[WC_SPAKE2P_MAX_KEY_SZ];
    word32 confPSz;
    word32 confVSz;
    word32 keyPSz;
    word32 keyVSz;
    int suite;
    int i;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&p, 0, sizeof(p));
    XMEMSET(&v, 0, sizeof(v));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    for (suite = WC_SPAKE2P_P256_SHA256_HKDF_HMAC;
            suite <= WC_SPAKE2P_P256_SHA256_HKDF_CMAC_AES128; suite++) {
        if (!spake2p_suite_available(suite))
            continue;
        XMEMSET(prev, 0, sizeof(prev));
        ExpectIntEQ(spake2p_make_record(&rng, suite, &rec1), 0);
        ExpectIntEQ(spake2p_make_record(&rng, suite, &rec2), 0);
        for (i = 0; i < 3; i++) {
            /* Honest run. */
            confPSz = confVSz = WC_SPAKE2P_MAX_CONFIRM_SZ;
            ExpectIntEQ(spake2p_exchange(&rng, suite, &p, &v, &rec1, &rec1,
                "app v1", "app v1", "alice", "alice", confP, &confPSz,
                confV, &confVSz), 0);
            keyPSz = sizeof(keyP);
            ExpectIntEQ(wc_Spake2pGetSharedKey(&p, keyP, &keyPSz),
                WC_NO_ERR_TRACE(BAD_STATE_E));
            /* The Prover checks confirmV before releasing confirmP. */
            ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&p, confV, confVSz), 0);
            ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&v, confP, confPSz), 0);
            keyPSz = sizeof(keyP);
            keyVSz = sizeof(keyV);
            ExpectIntEQ(wc_Spake2pGetSharedKey(&p, keyP, &keyPSz), 0);
            ExpectIntEQ(wc_Spake2pGetSharedKey(&v, keyV, &keyVSz), 0);
            ExpectIntEQ(keyPSz, spake2p_hash_sz(suite));
            ExpectIntEQ(keyVSz, keyPSz);
            ExpectBufEQ(keyP, keyV, keyPSz);
            /* A new run with the same password gives a new key. */
            ExpectBufNE(keyP, prev, keyPSz);
            XMEMCPY(prev, keyP, keyPSz);
            wc_Spake2pFree(&p);
            wc_Spake2pFree(&v);

            /* Wrong password: both sides reject. */
            confPSz = confVSz = WC_SPAKE2P_MAX_CONFIRM_SZ;
            ExpectIntEQ(spake2p_exchange(&rng, suite, &p, &v, &rec1, &rec2,
                "app v1", "app v1", "alice", "alice", confP, &confPSz,
                confV, &confVSz), 0);
            ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&p, confV, confVSz),
                WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
            ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&v, confP, confPSz),
                WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
            keyPSz = sizeof(keyP);
            ExpectIntEQ(wc_Spake2pGetSharedKey(&p, keyP, &keyPSz),
                WC_NO_ERR_TRACE(BAD_STATE_E));
            wc_Spake2pFree(&p);
            wc_Spake2pFree(&v);

            /* Different contexts. */
            confPSz = confVSz = WC_SPAKE2P_MAX_CONFIRM_SZ;
            ExpectIntEQ(spake2p_exchange(&rng, suite, &p, &v, &rec1, &rec1,
                "app v1", "app v2", "alice", "alice", confP, &confPSz,
                confV, &confVSz), 0);
            ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&p, confV, confVSz),
                WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
            wc_Spake2pFree(&p);
            wc_Spake2pFree(&v);

            /* Different Prover identities. */
            confPSz = confVSz = WC_SPAKE2P_MAX_CONFIRM_SZ;
            ExpectIntEQ(spake2p_exchange(&rng, suite, &p, &v, &rec1, &rec1,
                "app v1", "app v1", "alice", "bob", confP, &confPSz, confV,
                &confVSz), 0);
            ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&v, confP, confPSz),
                WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
            wc_Spake2pFree(&p);
            wc_Spake2pFree(&v);

            /* Empty context and identities agree too. */
            confPSz = confVSz = WC_SPAKE2P_MAX_CONFIRM_SZ;
            ExpectIntEQ(spake2p_exchange(&rng, suite, &p, &v, &rec1, &rec1,
                "", "", "", "", confP, &confPSz, confV, &confVSz), 0);
            ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&p, confV, confVSz), 0);
            ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&v, confP, confPSz), 0);
            wc_Spake2pFree(&p);
            wc_Spake2pFree(&v);
        }
    }

    /* Same curve, different hash: no agreement. */
    if (spake2p_suite_available(WC_SPAKE2P_P256_SHA512_HKDF_HMAC)) {
        byte shareP[WC_SPAKE2P_MAX_SHARE_SZ];
        byte shareV[WC_SPAKE2P_MAX_SHARE_SZ];
        word32 sharePSz = sizeof(shareP);
        word32 shareVSz = sizeof(shareV);
        ExpectIntEQ(spake2p_make_record(&rng,
            WC_SPAKE2P_P256_SHA256_HKDF_HMAC, &rec1), 0);
        ExpectIntEQ(wc_Spake2pInit(&p, WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
            WC_SPAKE2P_PROVER, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_Spake2pInit(&v, WC_SPAKE2P_P256_SHA512_HKDF_HMAC,
            WC_SPAKE2P_VERIFIER, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_Spake2pSetProverSecrets(&p, rec1.w0, 32, rec1.w1, 32),
            0);
        ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&v, rec1.w0, 32, rec1.L,
            rec1.LSz), 0);
        ExpectIntEQ(wc_Spake2pGenerateShare(&p, &rng, shareP, &sharePSz), 0);
        ExpectIntEQ(wc_Spake2pGenerateShare(&v, &rng, shareV, &shareVSz), 0);
        confPSz = confVSz = WC_SPAKE2P_MAX_CONFIRM_SZ;
        ExpectIntEQ(wc_Spake2pProcessPeerShare(&v, shareP, sharePSz, confV,
            &confVSz), 0);
        ExpectIntEQ(wc_Spake2pProcessPeerShare(&p, shareV, shareVSz, confP,
            &confPSz), 0);
        ExpectIntNE(confPSz, confVSz);
        ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&p, confV, confVSz),
            WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
        wc_Spake2pFree(&p);
        wc_Spake2pFree(&v);
    }

    wc_FreeRng(&rng);
#endif /* WOLFSSL_HAVE_SPAKE2P && !WC_NO_RNG */
    return EXPECT_RESULT();
}

/*
 * Errors and state handling of wc_Spake2pGenerateShare(),
 * wc_Spake2pProcessPeerShare(), wc_Spake2pVerifyPeerConfirm() and
 * wc_Spake2pGetSharedKey() on P-256.
 */
int test_wc_Spake2pExchangeErrors(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SPAKE2P) && !defined(WC_NO_RNG)
    WC_RNG rng;
    wc_Spake2p p;
    wc_Spake2p v;
    Spake2pRecord rec;
    byte share[WC_SPAKE2P_MAX_SHARE_SZ + 1];
    byte peer[WC_SPAKE2P_MAX_SHARE_SZ + 1];
    byte confP[WC_SPAKE2P_MAX_CONFIRM_SZ + 1];
    byte confV[WC_SPAKE2P_MAX_CONFIRM_SZ + 1];
    byte key[WC_SPAKE2P_MAX_KEY_SZ + 1];
    word32 shareSz;
    word32 confPSz;
    word32 confVSz;
    word32 keySz;
    int i;
    int st;
    const int s = WC_SPAKE2P_P256_SHA256_HKDF_HMAC;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&p, 0, sizeof(p));
    XMEMSET(&v, 0, sizeof(v));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(spake2p_make_record(&rng, s, &rec), 0);

    /* --- GenerateShare --- */
    ExpectIntEQ(wc_Spake2pInit(&p, s, WC_SPAKE2P_PROVER, NULL,
        INVALID_DEVID), 0);
    shareSz = sizeof(share);
    ExpectIntEQ(wc_Spake2pGenerateShare(&p, &rng, share, &shareSz),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectIntEQ(wc_Spake2pSetProverSecrets(&p, rec.w0, 32, rec.w1, 32), 0);
    ExpectIntEQ(wc_Spake2pGenerateShare(NULL, &rng, share, &shareSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pGenerateShare(&p, &rng, NULL, &shareSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pGenerateShare(&p, &rng, share, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pGenerateShare(&p, NULL, share, &shareSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(share, 0xAA, sizeof(share));
    shareSz = 64;
    ExpectIntEQ(wc_Spake2pGenerateShare(&p, &rng, share, &shareSz),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(shareSz, 64);
    ExpectIntEQ(share[0], 0xAA);
    ExpectIntEQ(p.state, WC_SPAKE2P_STATE_SECRETS);
    shareSz = sizeof(share);
    ExpectIntEQ(wc_Spake2pGenerateShare(&p, &rng, share, &shareSz), 0);
    ExpectIntEQ(shareSz, 65);
    ExpectIntEQ(share[0], 0x04);
    ExpectIntEQ(share[65], 0xAA);
    ExpectIntEQ(wc_Spake2pGenerateShare(&p, &rng, share, &shareSz),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* --- ProcessPeerShare: arguments, state, buffer --- */
    ExpectIntEQ(wc_Spake2pInit(&v, s, WC_SPAKE2P_VERIFIER, NULL,
        INVALID_DEVID), 0);
    ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&v, rec.w0, 32, rec.L,
        rec.LSz), 0);
    confVSz = sizeof(confV);
    ExpectIntEQ(wc_Spake2pProcessPeerShare(&v, share, 65, confV, &confVSz),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    shareSz = sizeof(peer);
    ExpectIntEQ(wc_Spake2pGenerateShare(&v, &rng, peer, &shareSz), 0);
    ExpectIntEQ(wc_Spake2pProcessPeerShare(NULL, share, 65, confV,
        &confVSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pProcessPeerShare(&v, NULL, 65, confV, &confVSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pProcessPeerShare(&v, share, 65, NULL, &confVSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pProcessPeerShare(&v, share, 65, confV, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(confV, 0xAA, sizeof(confV));
    confVSz = 31;
    ExpectIntEQ(wc_Spake2pProcessPeerShare(&v, share, 65, confV, &confVSz),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(confVSz, 31);
    ExpectIntEQ(confV[0], 0xAA);
    ExpectIntEQ(v.state, WC_SPAKE2P_STATE_SHARE);
    confVSz = sizeof(confV);
    ExpectIntEQ(wc_Spake2pProcessPeerShare(&v, share, 65, confV, &confVSz),
        0);
    ExpectIntEQ(confVSz, 32);
    ExpectIntEQ(confV[32], 0xAA);
    ExpectIntEQ(v.ephSz, 0);
    ExpectIntEQ(wc_Spake2pProcessPeerShare(&v, share, 65, confV, &confVSz),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    confPSz = sizeof(confP);
    ExpectIntEQ(wc_Spake2pProcessPeerShare(&p, peer, 65, confP, &confPSz),
        0);

    /* --- VerifyPeerConfirm and GetSharedKey --- */
    ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(NULL, confV, confVSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&p, NULL, confVSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Reflection: the Prover's own MAC is not accepted. */
    ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&p, confP, confPSz),
        WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
    ExpectIntEQ(p.state, WC_SPAKE2P_STATE_FAILED);
    ExpectIntEQ(p.kSharedSz, 0);
    ExpectTrue(spake2p_all_zero(p.kShared, sizeof(p.kShared)));
    ExpectTrue(spake2p_all_zero(p.kConfirmP, sizeof(p.kConfirmP)));
    ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&p, confV, confVSz),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    /* The Verifier is unaffected and confirms. */
    ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&v, confP, confPSz), 0);
    ExpectIntEQ(v.state, WC_SPAKE2P_STATE_CONFIRMED);
    ExpectTrue(spake2p_all_zero(v.kConfirmP, sizeof(v.kConfirmP)));
    ExpectTrue(spake2p_all_zero(v.kConfirmV, sizeof(v.kConfirmV)));
    ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&v, confP, confPSz),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    keySz = sizeof(key);
    ExpectIntEQ(wc_Spake2pGetSharedKey(NULL, key, &keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pGetSharedKey(&v, NULL, &keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pGetSharedKey(&v, key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(key, 0xAA, sizeof(key));
    keySz = 31;
    ExpectIntEQ(wc_Spake2pGetSharedKey(&v, key, &keySz),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(keySz, 31);
    ExpectIntEQ(key[0], 0xAA);
    keySz = sizeof(key);
    ExpectIntEQ(wc_Spake2pGetSharedKey(&v, key, &keySz), 0);
    ExpectIntEQ(keySz, 32);
    ExpectIntEQ(key[32], 0xAA);
    keySz = 32;
    ExpectIntEQ(wc_Spake2pGetSharedKey(&v, key, &keySz), 0);
    keySz = sizeof(key);
    ExpectIntEQ(wc_Spake2pGetSharedKey(&p, key, &keySz),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    wc_Spake2pFree(&p);
    wc_Spake2pFree(&v);
    keySz = sizeof(key);
    ExpectIntEQ(wc_Spake2pGetSharedKey(&v, key, &keySz),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* Tampered confirmations: flipped byte at each end and the middle,
     * truncated, extended with the correct prefix, empty. */
    for (i = 0; i < 6; i++) {
        byte m[WC_SPAKE2P_MAX_CONFIRM_SZ + 1];
        word32 mSz = 32;
        confPSz = confVSz = WC_SPAKE2P_MAX_CONFIRM_SZ;
        ExpectIntEQ(spake2p_exchange(&rng, s, &p, &v, &rec, &rec, "c", "c",
            "a", "a", confP, &confPSz, confV, &confVSz), 0);
        XMEMCPY(m, confV, 32);
        if (i == 0) m[0] ^= 1;
        if (i == 1) m[16] ^= 1;
        if (i == 2) m[31] ^= 1;
        if (i == 3) mSz = 31;
        if (i == 4) { m[32] = 0; mSz = 33; }
        if (i == 5) mSz = 0;
        ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&p, m, mSz),
            WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
        ExpectIntEQ(p.state, WC_SPAKE2P_STATE_FAILED);
        wc_Spake2pFree(&p);
        wc_Spake2pFree(&v);
    }

    /* Invalid peer shares: each is fatal to the context. A peer share of
     * w0 * N makes shareV - w0 * N the identity. */
    for (i = 0; i < 7; i++) {
        word32 len = 65;
        int expect = WC_NO_ERR_TRACE(IS_POINT_E);
        ExpectIntEQ(wc_Spake2pInit(&p, s, WC_SPAKE2P_PROVER, NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_Spake2pSetProverSecrets(&p, rec.w0, 32, rec.w1, 32),
            0);
        shareSz = sizeof(share);
        ExpectIntEQ(wc_Spake2pGenerateShare(&p, &rng, share, &shareSz), 0);
        XMEMCPY(peer, share, 65);   /* a valid point to corrupt */
        if (i == 0) len = 64;
        if (i == 1) { peer[0] = (byte)(0x02 | (share[64] & 1)); len = 33; }
        if (i == 2) peer[0] = 0x06;
        if (i == 3) peer[64] ^= 1;
        if (i == 4) { XMEMSET(peer, 0, 65); peer[0] = 0x04;
                      expect = WC_NO_ERR_TRACE(ECC_INF_E); }
        if (i == 5) { peer[0] = 0x00; len = 1; }
        if (i == 6) {
            /* Uses the RFC P-256 vector's w0 with that record. */
            byte w0[32];
            byte w1[32];
            wc_Spake2pFree(&p);
            ExpectIntEQ(spake2p_unhex(spake2pRfcVectors[0].w0, w0, 32), 32);
            ExpectIntEQ(spake2p_unhex(spake2pRfcVectors[0].w1, w1, 32), 32);
            ExpectIntEQ(wc_Spake2pInit(&p, s, WC_SPAKE2P_PROVER, NULL,
                INVALID_DEVID), 0);
            ExpectIntEQ(wc_Spake2pSetProverSecrets(&p, w0, 32, w1, 32), 0);
            shareSz = sizeof(share);
            ExpectIntEQ(wc_Spake2pGenerateShare(&p, &rng, share, &shareSz),
                0);
            ExpectIntEQ(spake2p_unhex(spake2pW0TimesN, peer, sizeof(peer)),
                65);
            expect = WC_NO_ERR_TRACE(ECC_INF_E);
        }
        confPSz = sizeof(confP);
        ExpectIntEQ(wc_Spake2pProcessPeerShare(&p, peer, len, confP,
            &confPSz), expect);
        ExpectIntEQ(p.state, WC_SPAKE2P_STATE_FAILED);
        ExpectIntEQ(p.ephSz, 0);
        ExpectIntEQ(wc_Spake2pProcessPeerShare(&p, share, 65, confP,
            &confPSz), WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_Spake2pFree(&p);
    }

    /* Each step refuses the states it does not accept. */
    ExpectIntEQ(wc_Spake2pInit(&v, s, WC_SPAKE2P_VERIFIER, NULL,
        INVALID_DEVID), 0);
    for (st = WC_SPAKE2P_STATE_INIT; st <= WC_SPAKE2P_STATE_FAILED; st++) {
        v.state = (byte)st;
        if (st != WC_SPAKE2P_STATE_SECRETS) {
            shareSz = sizeof(share);
            ExpectIntEQ(wc_Spake2pGenerateShare(&v, &rng, share, &shareSz),
                WC_NO_ERR_TRACE(BAD_STATE_E));
        }
        if (st != WC_SPAKE2P_STATE_SHARE) {
            confVSz = sizeof(confV);
            ExpectIntEQ(wc_Spake2pProcessPeerShare(&v, share, 65, confV,
                &confVSz), WC_NO_ERR_TRACE(BAD_STATE_E));
        }
        if (st != WC_SPAKE2P_STATE_KEYS) {
            ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&v, confV, 32),
                WC_NO_ERR_TRACE(BAD_STATE_E));
        }
        if (st != WC_SPAKE2P_STATE_CONFIRMED) {
            keySz = sizeof(key);
            ExpectIntEQ(wc_Spake2pGetSharedKey(&v, key, &keySz),
                WC_NO_ERR_TRACE(BAD_STATE_E));
        }
    }
    wc_Spake2pFree(&v);

    wc_FreeRng(&rng);
#endif /* WOLFSSL_HAVE_SPAKE2P && !WC_NO_RNG */
    return EXPECT_RESULT();
}

/*
 * RFC 9383 Appendix C known answers for the whole exchange, both roles of
 * every available suite, and wc_Spake2pSetEphemeral(). Needs
 * WOLFSSL_SPAKE2P_TEST_HOOKS to fix the ephemeral scalars; skipped
 * otherwise.
 */
int test_wc_Spake2pRfcVectors(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SPAKE2P) && defined(WOLFSSL_SPAKE2P_TEST_HOOKS)
    wc_Spake2p ctx;
    byte w0[WC_SPAKE2P_MAX_SCALAR_SZ];
    byte w1[WC_SPAKE2P_MAX_SCALAR_SZ];
    byte L[WC_SPAKE2P_MAX_L_SZ];
    byte eph[WC_SPAKE2P_MAX_SCALAR_SZ];
    byte exp[WC_SPAKE2P_MAX_SHARE_SZ];
    byte peer[WC_SPAKE2P_MAX_SHARE_SZ];
    byte share[WC_SPAKE2P_MAX_SHARE_SZ];
    byte conf[WC_SPAKE2P_MAX_CONFIRM_SZ];
    byte peerConf[WC_SPAKE2P_MAX_CONFIRM_SZ];
    byte key[WC_SPAKE2P_MAX_KEY_SZ];
    word32 w0Sz, w1Sz, LSz, ephSz, expSz, peerSz, shareSz, confSz;
    word32 peerConfSz, keySz;
    int i;
    int role;
    int st;

    XMEMSET(&ctx, 0, sizeof(ctx));

    for (i = 0; i < SPAKE2P_RFC_VECTOR_CNT; i++) {
        const Spake2pRfcVector* v = &spake2pRfcVectors[i];
        if (!spake2p_suite_available(v->suite))
            continue;
        w0Sz = spake2p_unhex(v->w0, w0, sizeof(w0));
        w1Sz = spake2p_unhex(v->w1, w1, sizeof(w1));
        LSz = spake2p_unhex(v->L, L, sizeof(L));
        for (role = WC_SPAKE2P_PROVER; role <= WC_SPAKE2P_VERIFIER; role++) {
            int prover = (role == WC_SPAKE2P_PROVER);
            ExpectIntEQ(wc_Spake2pInit(&ctx, v->suite, role, NULL,
                INVALID_DEVID), 0);
            ExpectIntEQ(wc_Spake2pSetContext(&ctx, (const byte*)v->context,
                (word32)XSTRLEN(v->context)), 0);
            ExpectIntEQ(wc_Spake2pSetIdentities(&ctx,
                (const byte*)v->idProver, (word32)XSTRLEN(v->idProver),
                (const byte*)v->idVerifier, (word32)XSTRLEN(v->idVerifier)),
                0);
            if (prover) {
                ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, w0, w0Sz, w1,
                    w1Sz), 0);
            }
            else {
                ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, w0Sz, L,
                    LSz), 0);
            }
            ephSz = spake2p_unhex(prover ? v->x : v->y, eph, sizeof(eph));
            ExpectIntEQ(wc_Spake2pSetEphemeral(&ctx, eph, ephSz), 0);

            /* No RNG needed with a fixed ephemeral. */
            shareSz = sizeof(share);
            ExpectIntEQ(wc_Spake2pGenerateShare(&ctx, NULL, share, &shareSz),
                0);
            expSz = spake2p_unhex(prover ? v->shareP : v->shareV, exp,
                sizeof(exp));
            ExpectIntEQ(shareSz, expSz);
            ExpectBufEQ(share, exp, expSz);

            peerSz = spake2p_unhex(prover ? v->shareV : v->shareP, peer,
                sizeof(peer));
            confSz = sizeof(conf);
            ExpectIntEQ(wc_Spake2pProcessPeerShare(&ctx, peer, peerSz, conf,
                &confSz), 0);
            expSz = spake2p_unhex(prover ? v->confirmP : v->confirmV, exp,
                sizeof(exp));
            ExpectIntEQ(confSz, expSz);
            ExpectBufEQ(conf, exp, expSz);

            peerConfSz = spake2p_unhex(prover ? v->confirmV : v->confirmP,
                peerConf, sizeof(peerConf));
            ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&ctx, peerConf,
                peerConfSz), 0);
            keySz = sizeof(key);
            ExpectIntEQ(wc_Spake2pGetSharedKey(&ctx, key, &keySz), 0);
            expSz = spake2p_unhex(v->kShared, exp, sizeof(exp));
            ExpectIntEQ(keySz, expSz);
            ExpectBufEQ(key, exp, expSz);
            wc_Spake2pFree(&ctx);

            /* A tampered RFC confirmation is rejected. */
            ExpectIntEQ(wc_Spake2pInit(&ctx, v->suite, role, NULL,
                INVALID_DEVID), 0);
            ExpectIntEQ(wc_Spake2pSetContext(&ctx, (const byte*)v->context,
                (word32)XSTRLEN(v->context)), 0);
            ExpectIntEQ(wc_Spake2pSetIdentities(&ctx,
                (const byte*)v->idProver, (word32)XSTRLEN(v->idProver),
                (const byte*)v->idVerifier, (word32)XSTRLEN(v->idVerifier)),
                0);
            if (prover) {
                ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, w0, w0Sz, w1,
                    w1Sz), 0);
            }
            else {
                ExpectIntEQ(wc_Spake2pSetVerifierSecrets(&ctx, w0, w0Sz, L,
                    LSz), 0);
            }
            ExpectIntEQ(wc_Spake2pSetEphemeral(&ctx, eph, ephSz), 0);
            shareSz = sizeof(share);
            ExpectIntEQ(wc_Spake2pGenerateShare(&ctx, NULL, share, &shareSz),
                0);
            confSz = sizeof(conf);
            ExpectIntEQ(wc_Spake2pProcessPeerShare(&ctx, peer, peerSz, conf,
                &confSz), 0);
            peerConf[peerConfSz / 2] ^= 0x80;
            ExpectIntEQ(wc_Spake2pVerifyPeerConfirm(&ctx, peerConf,
                peerConfSz), WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
            wc_Spake2pFree(&ctx);
        }
    }

    /* wc_Spake2pSetEphemeral() errors, using the P-256 vector. */
    w0Sz = spake2p_unhex(spake2pRfcVectors[0].w0, w0, sizeof(w0));
    w1Sz = spake2p_unhex(spake2pRfcVectors[0].w1, w1, sizeof(w1));
    ephSz = spake2p_unhex(spake2pRfcVectors[0].x, eph, sizeof(eph));
    ExpectIntEQ(wc_Spake2pInit(&ctx, WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
        WC_SPAKE2P_PROVER, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Spake2pSetEphemeral(NULL, eph, ephSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetEphemeral(&ctx, NULL, ephSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Spake2pSetEphemeral(&ctx, eph, 31),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(exp, 0, 32);
    ExpectIntEQ(wc_Spake2pSetEphemeral(&ctx, exp, 32),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(exp, 0xFF, 32);
    ExpectIntEQ(wc_Spake2pSetEphemeral(&ctx, exp, 32),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(ctx.ephSet, 0);
    /* Before secrets, replaced; a rejected replacement keeps the last. */
    XMEMSET(exp, 0, 32);
    exp[31] = 7;
    ExpectIntEQ(wc_Spake2pSetEphemeral(&ctx, exp, 32), 0);
    ExpectIntEQ(wc_Spake2pSetEphemeral(&ctx, eph, ephSz), 0);
    exp[31] = 0;
    ExpectIntEQ(wc_Spake2pSetEphemeral(&ctx, exp, 32),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectBufEQ(ctx.eph, eph, ephSz);
    ExpectIntEQ(wc_Spake2pSetProverSecrets(&ctx, w0, w0Sz, w1, w1Sz), 0);
    shareSz = sizeof(share);
    ExpectIntEQ(wc_Spake2pGenerateShare(&ctx, NULL, share, &shareSz), 0);
    expSz = spake2p_unhex(spake2pRfcVectors[0].shareP, exp, sizeof(exp));
    ExpectBufEQ(share, exp, expSz);
    ExpectIntEQ(wc_Spake2pSetEphemeral(&ctx, eph, ephSz),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    for (st = WC_SPAKE2P_STATE_KEYS; st <= WC_SPAKE2P_STATE_FAILED; st++) {
        ctx.state = (byte)st;
        ExpectIntEQ(wc_Spake2pSetEphemeral(&ctx, eph, ephSz),
            WC_NO_ERR_TRACE(BAD_STATE_E));
    }
    wc_Spake2pFree(&ctx);
    ExpectIntEQ(ctx.ephSet, 0);
    ExpectTrue(spake2p_all_zero(ctx.eph, sizeof(ctx.eph)));
#endif /* WOLFSSL_HAVE_SPAKE2P && WOLFSSL_SPAKE2P_TEST_HOOKS */
    return EXPECT_RESULT();
}
