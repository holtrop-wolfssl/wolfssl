/*!
    \addtogroup SPAKE2P

    SPAKE2+ is an augmented password-authenticated key exchange (PAKE)
    specified in RFC 9383. Two parties that share knowledge of a password
    establish a shared secret key over an untrusted channel, and each side
    proves to the other that it derived the same key. An eavesdropper learns
    nothing that allows an offline guess of the password, and an active
    attacker gets at most one online password guess per protocol run.

    The protocol is augmented (asymmetric): only the client needs the
    password, or values derived from it. The server stores a registration
    record from which the password cannot be recovered without an offline
    dictionary attack, and which cannot be used directly to impersonate the
    client.

    \section spake2p_roles Roles and Secrets

    RFC 9383 names the two roles Prover and Verifier:

    - <b>Prover</b> (typically the client or device being commissioned):
      knows the password, or holds the two scalars w0 and w1 derived from
      it. Selected with WC_SPAKE2P_PROVER.
    - <b>Verifier</b> (typically the server or commissioner): holds only
      the registration record (w0, L), where L = w1*P is an encoded curve
      point. The Verifier never sees the password or w1. Selected with
      WC_SPAKE2P_VERIFIER.

    Secrecy of each value:

    | Value | Held by | Sensitivity |
    | ----- | ------- | ----------- |
    | password | Prover | Secret |
    | w0, w1 | Prover | Secret; password-equivalent, protect like the password |
    | w0, L | Verifier | Secret; disclosure enables an offline dictionary attack on the password |
    | salt, PBKDF parameters | both | Public, but per-user unique salt is required |
    | shareP, shareV, confirmP, confirmV | on the wire | Public |
    | K_shared | both, after the exchange | Secret session key |

    \section spake2p_build Enabling SPAKE2+

    - Autotools: ./configure --enable-spake2p
    - CMake: -DWOLFSSL_SPAKE2P=yes
    - user_settings.h: define WOLFSSL_HAVE_SPAKE2P

    SPAKE2+ requires ECC (HAVE_ECC), HKDF (HAVE_HKDF) and SHA-256.
    ECC and HKDF are on by default (HKDF is enabled by TLS 1.3); if either
    has been disabled, configuration fails with an error.
    Without TLS 1.3, add --enable-hkdf (Autotools) or
    -DWOLFSSL_HKDF=yes (CMake). The API is declared in
    <wolfssl/wolfcrypt/spake2p.h>.

    Additional requirements per ciphersuite:
    - SHA-512 suites require WOLFSSL_SHA512.
    - P-384 and P-521 suites require those curves to be compiled in (with
      ECC_USER_CURVES, define HAVE_ECC384 / HAVE_ECC521).
    - The CMAC suite requires WOLFSSL_CMAC (--enable-cmac) and AES-128.

    A suite that is not compiled in is rejected at runtime with
    NOT_COMPILED_IN. The suite identifiers themselves are always defined.

    \section spake2p_suites Ciphersuites and Sizes

    Both sides must use the same ciphersuite; it is not negotiated by this
    API. Choose it as part of the application protocol. Points (shares and
    L) are encoded as SEC1 uncompressed points (0x04 || X || Y). Scalars
    (w0, w1) are big-endian and the length of the group order.

    | Suite | w0, w1 | w0s, w1s (each) | shareP, shareV, L | confirmP, confirmV | K_shared |
    | ----- | ------ | --------------- | ----------------- | ------------------ | -------- |
    | WC_SPAKE2P_P256_SHA256_HKDF_HMAC        | 32 | 40 | 65  | 32 | 32 |
    | WC_SPAKE2P_P256_SHA512_HKDF_HMAC        | 32 | 40 | 65  | 64 | 64 |
    | WC_SPAKE2P_P384_SHA256_HKDF_HMAC        | 48 | 56 | 97  | 32 | 32 |
    | WC_SPAKE2P_P384_SHA512_HKDF_HMAC        | 48 | 56 | 97  | 64 | 64 |
    | WC_SPAKE2P_P521_SHA512_HKDF_HMAC        | 66 | 74 | 133 | 64 | 64 |
    | WC_SPAKE2P_P256_SHA256_HKDF_CMAC_AES128 | 32 | 40 | 65  | 16 | 32 |

    All sizes are in bytes. Rather than hard-coding them, size buffers with
    the compile-time maximums and use the length each function returns:
    - WC_SPAKE2P_MAX_SCALAR_SZ - w0, w1
    - WC_SPAKE2P_MAX_SHARE_SZ - shareP, shareV
    - WC_SPAKE2P_MAX_L_SZ - L
    - WC_SPAKE2P_MAX_CONFIRM_SZ - confirmP, confirmV
    - WC_SPAKE2P_MAX_KEY_SZ - K_shared

    WC_SPAKE2P_P256_SHA256_HKDF_HMAC is the most widely deployed suite and
    a good default.

    \section spake2p_registration Registration (Offline)

    Registration turns the password into the Prover's secrets (w0, w1) and
    the Verifier's record (w0, L). It runs once per user or device, for
    example at account creation or at manufacturing time, and is not part
    of the online exchange.

    RFC 9383 (Section 3.2) derives w0 and w1 from the password and both
    identities:

    \verbatim
    w0s || w1s = PBKDF(len(pw) || pw ||
                       len(idProver) || idProver ||
                       len(idVerifier) || idVerifier)
    w0 = w0s mod p
    w1 = w1s mod p
    \endverbatim

    where p is the group order, || is concatenation, and len(S) is the
    length of S in bytes encoded as an <b>eight-byte little-endian</b>
    integer. An identity that is not known at registration time is encoded
    as len = 0 followed by nothing. Each of w0s and w1s must be at least
    ceil(log2(p))/8 + 8 bytes (see the w0s, w1s column of the table above),
    so the PBKDF output is 80 bytes for P-256, 112 for P-384, and 148 for
    P-521.

    Steps:
    -# Build the PBKDF input exactly as above from the password, idProver,
       and idVerifier. Use the same identity byte strings that will later
       be passed to wc_Spake2pSetIdentities().
    -# Generate a random, per-user salt (at least 16 bytes). RFC 9383 leaves
       the salt to the PBKDF; it is not part of the encoded input.
    -# Run a password hash over the encoded input and salt to produce
       2 * (w0s length) bytes. Prefer a memory-hard function: RFC 9383
       recommends scrypt with (N, r, p) = (32768, 8, 1) (wc_scrypt() with
       cost 15; requires --enable-scrypt), or Argon2id with the parameters
       in RFC 9106 Section 4. wc_PBKDF2() resists hardware-accelerated
       guessing less well, but may be required by an application protocol
       (for example Matter), by FIPS compliance, or by the memory limits of
       the Prover. Whichever function is used, set its cost parameters
       (for PBKDF2, the iteration count) as high as the slowest Prover can
       tolerate.
    -# Split the output into two equal halves, w0s and w1s.
    -# Call wc_Spake2pDeriveW0W1() to reduce them to the scalars w0 and w1.
    -# Call wc_Spake2pComputeL() to compute L from w1.
    -# Give the Verifier (w0, L), plus the salt and PBKDF parameters if the
       Prover will recompute w0 and w1 from the password. Store them keyed
       by the Prover's identity.
    -# Zeroize the password, the encoded PBKDF input, the PBKDF output, and
       w1 wherever they are not needed. The Verifier must never store w1.

    Because the identities are part of the PBKDF input, w0 and w1 are bound
    to that pair of identities: changing either identity requires
    re-registration.

    The Prover can either store w0 and w1 directly (common for devices
    provisioned at manufacturing time) or store nothing and recompute them
    from the password, identities, salt, and PBKDF parameters at each login
    (common for human users). In the second case the application protocol
    must deliver the salt and PBKDF parameters from the Verifier to the
    Prover before the exchange; this API does not carry them.

    \section spake2p_exchange Online Exchange

    The exchange is three messages. This API produces and consumes the
    message contents only; the application frames and transports them.

    \verbatim
    Prover                                       Verifier
      shareP                         ------>
                                     <------     shareV, confirmV
      confirmP                       ------>
    K_shared                                     K_shared
    \endverbatim

    Both roles call the API in the same order. Each wc_Spake2p context
    handles exactly one protocol run.

    -# wc_Spake2pInit() with the suite and role.
    -# Optional: wc_Spake2pSetContext() and wc_Spake2pSetIdentities().
    -# wc_Spake2pSetProverSecrets() (Prover) or
       wc_Spake2pSetVerifierSecrets() (Verifier).
    -# wc_Spake2pGenerateShare() - produces shareP or shareV.
    -# wc_Spake2pProcessPeerShare() - consumes the peer's share, produces
       confirmP or confirmV.
    -# wc_Spake2pVerifyPeerConfirm() - checks the peer's confirmation.
    -# wc_Spake2pGetSharedKey() - returns K_shared.
    -# wc_Spake2pFree().

    Prover, step by step:
    -# Initialize, set the context and identities, and load w0 and w1.
    -# Generate shareP and send it.
    -# Receive shareV and confirmV.
    -# Process shareV, producing confirmP. Do not send confirmP yet.
    -# Verify confirmV. On failure, abort without sending confirmP.
    -# Send confirmP.
    -# Retrieve K_shared.

    Verifier, step by step:
    -# Receive shareP and the Prover's identity (application framing).
    -# Look up the registration record (w0, L) for that identity.
    -# Initialize, set the context and identities, and load w0 and L.
    -# Generate shareV.
    -# Process shareP, producing confirmV.
    -# Send shareV and confirmV.
    -# Receive confirmP and verify it. On failure, abort.
    -# Retrieve K_shared.

    The Verifier may generate shareV before shareP arrives; the only
    requirement is that wc_Spake2pGenerateShare() is called before
    wc_Spake2pProcessPeerShare().

    \section spake2p_transcript Context and Identities

    The context string and both identities are hashed into the protocol
    transcript. If the two sides use different values, the exchange fails at
    confirmation (MAC_CMP_FAILED_E), which is indistinguishable from a wrong
    password.

    - <b>Context</b> (wc_Spake2pSetContext()): an application-defined byte
      string that binds the exchange to a specific protocol and version,
      for example "MyApp SPAKE2+ v1". It may also include a hash of any
      earlier messages in the application protocol (such as the message
      carrying the salt and PBKDF parameters) so that tampering with them
      is detected. RFC 9383 makes the context optional; this documentation
      recommends always setting one.
    - <b>Identities</b> (wc_Spake2pSetIdentities()): idProver and
      idVerifier, for example a user name and a server name. RFC 9383 says
      both SHOULD be non-empty unless the identities are already implicit
      in the application (for example, a device commissioned over a
      dedicated point-to-point link); leaving them empty otherwise risks
      unknown key-share attacks. An empty identity is still included in
      the transcript, as a zero length.

    Both are optional and default to empty. They must be set before
    wc_Spake2pGenerateShare().

    \section spake2p_security Security Requirements

    - <b>Use K_shared only after confirmation.</b>
      wc_Spake2pGetSharedKey() returns BAD_STATE_E until
      wc_Spake2pVerifyPeerConfirm() has succeeded.
    - <b>Prover: verify before you confirm.</b> Verify confirmV before
      sending confirmP, so that confirmP is never released to a party that
      has not proven knowledge of the registration record.
    - <b>Abort on any error.</b> After any failure the context is in a
      failed state and every further call returns BAD_STATE_E. Free it and,
      if the application allows a retry, start a new run with a fresh
      context.
    - <b>Never reuse a context.</b> Each run must use a fresh ephemeral
      scalar, which wc_Spake2pGenerateShare() draws from the RNG. Free the
      context after each run and initialize a new one for the next.
    - <b>Rate-limit the Verifier.</b> Every failed confirmation is one
      online password guess by the peer. Limit attempts per identity and
      per source, and possibly lock out or delay after repeated failures.
    - <b>Avoid user enumeration.</b> If the Verifier receives an unknown
      identity, it should run the exchange with a fake record that is
      deterministic for that identity (for example, derived from an HMAC of
      the identity under a server secret), so that the failure happens at
      confirmation exactly as for a wrong password.
    - <b>Protect the registration record.</b> A stolen (w0, L) allows an
      offline dictionary attack on the password, slowed only by the PBKDF
      cost. Store it with the same care as password hashes.
    - <b>Derive application keys from K_shared.</b> Use K_shared as input
      keying material, for example to wc_HKDF() with labels unique to each
      purpose and direction, rather than using it directly as more than one
      key.
    - <b>Zeroize.</b> wc_Spake2pFree() zeroizes all secrets held in the
      context. The application is responsible for the password, w0, w1, L
      and K_shared buffers it owns.

    \section spake2p_errors Errors

    All functions return 0 on success and a negative wolfCrypt error code on
    failure. The codes specific to this API's behavior are:

    | Code | Meaning |
    | ---- | ------- |
    | BAD_FUNC_ARG | NULL pointer, unknown suite or role, or malformed length |
    | BAD_STATE_E | Function called out of order, wrong role, or context in failed state |
    | BUFFER_E | Output buffer too small; the required size is not written |
    | NOT_COMPILED_IN | Suite's curve, hash, or MAC not compiled in |
    | IS_POINT_E | Peer share or L is not a valid point on the curve |
    | ECC_INF_E | L, the peer share, or a computed point is the point at infinity (an encoded point reports this only for the uncompressed all-zero form; other encodings of infinity give IS_POINT_E) |
    | MAC_CMP_FAILED_E | Peer confirmation did not verify: wrong password, mismatched context or identities, or an attack |

    From the network's point of view, all failures should be reported to the
    peer identically (or not at all), so that an attacker cannot learn why
    an attempt failed.

    \section spake2p_interop Interoperability

    This implementation follows RFC 9383. Protocols that adopted earlier
    drafts of SPAKE2+ (for example Matter) may derive keys or build the
    transcript differently; verify interoperability against that
    protocol's test vectors before relying on it.

    Such protocols may also define their own PBKDF input in place of the
    RFC 9383 encoding described under Registration. Matter, for example,
    runs PBKDF2 over the setup passcode alone, without identities or
    length prefixes. wc_Spake2pDeriveW0W1() accepts w0s and w1s from any
    PBKDF, so follow the protocol's own definition in that case.

    \section spake2p_example_reg Example: Registration

    \code
    #include <wolfssl/options.h>
    #include <wolfssl/wolfcrypt/spake2p.h>
    #include <wolfssl/wolfcrypt/pwdbased.h>
    #include <wolfssl/wolfcrypt/random.h>
    #include <string.h>

    #define SUITE         WC_SPAKE2P_P256_SHA256_HKDF_HMAC
    #define W_HALF_SZ     40      // P-256: 32 + 8, see table
    #define MAX_PW_SZ     128
    #define MAX_ID_SZ     64
    #define SCRYPT_COST   15      // N = 2^15 = 32768 (RFC 9383)
    #define SCRYPT_R      8
    #define SCRYPT_P      1

    // Append len(data) as 8-byte little-endian, then data.
    static word32 put_len_data(byte* out, const byte* data, word32 sz)
    {
        word32 i;
        for (i = 0; i < 8; i++)
            out[i] = (i < 4) ? (byte)(sz >> (8 * i)) : 0;
        if (sz > 0)
            memcpy(out + 8, data, sz);
        return 8 + sz;
    }

    // RFC 9383 PBKDF input:
    // len(pw) || pw || len(idProver) || idProver || len(idVerifier) ||
    // idVerifier. Pass NULL, 0 for an identity that is not known.
    static word32 build_pbkdf_input(byte* out,
                                    const byte* pw, word32 pwSz,
                                    const byte* idP, word32 idPSz,
                                    const byte* idV, word32 idVSz)
    {
        word32 n = 0;
        n += put_len_data(out + n, pw, pwSz);
        n += put_len_data(out + n, idP, idPSz);
        n += put_len_data(out + n, idV, idVSz);
        return n;
    }

    int register_user(WC_RNG* rng, const byte* pw, word32 pwSz,
                      const byte* idP, word32 idPSz,
                      const byte* idV, word32 idVSz,
                      byte* salt, word32 saltSz,
                      byte* w0, word32* w0Sz,
                      byte* w1, word32* w1Sz,
                      byte* L, word32* LSz)
    {
        byte   in[3 * 8 + MAX_PW_SZ + 2 * MAX_ID_SZ];
        word32 inSz;
        byte   ws[2 * W_HALF_SZ];   // w0s || w1s
        int    ret;

        if (pwSz > MAX_PW_SZ || idPSz > MAX_ID_SZ || idVSz > MAX_ID_SZ)
            return BAD_FUNC_ARG;
        inSz = build_pbkdf_input(in, pw, pwSz, idP, idPSz, idV, idVSz);

        ret = wc_RNG_GenerateBlock(rng, salt, saltSz);
        if (ret == 0) {
            ret = wc_scrypt(ws, in, (int)inSz, salt, (int)saltSz,
                            SCRYPT_COST, SCRYPT_R, SCRYPT_P,
                            (int)sizeof(ws));
        }
        if (ret == 0) {
            ret = wc_Spake2pDeriveW0W1(SUITE, ws, W_HALF_SZ,
                                       ws + W_HALF_SZ, W_HALF_SZ,
                                       w0, w0Sz, w1, w1Sz, NULL);
        }
        if (ret == 0) {
            ret = wc_Spake2pComputeL(SUITE, w1, *w1Sz, L, LSz,
                                     NULL, INVALID_DEVID);
        }
        wc_ForceZero(in, sizeof(in));
        wc_ForceZero(ws, sizeof(ws));
        // Prover keeps (w0, w1), or keeps nothing and recomputes them
        // from the password, identities, salt, and scrypt parameters at
        // login. Verifier stores (w0, L, salt, scrypt parameters) for
        // this user.
        return ret;
    }
    \endcode

    \section spake2p_example_prover Example: Prover

    app_send() and app_recv() stand for the application's transport.

    \code
    static const byte appContext[] = "MyApp SPAKE2+ v1";

    int prover_run(WC_RNG* rng,
                   const byte* idP, word32 idPSz,
                   const byte* idV, word32 idVSz,
                   const byte* w0, word32 w0Sz,
                   const byte* w1, word32 w1Sz,
                   byte* key, word32* keySz)
    {
        wc_Spake2p ctx;
        byte   shareP[WC_SPAKE2P_MAX_SHARE_SZ];
        byte   shareV[WC_SPAKE2P_MAX_SHARE_SZ];
        byte   confirmP[WC_SPAKE2P_MAX_CONFIRM_SZ];
        byte   confirmV[WC_SPAKE2P_MAX_CONFIRM_SZ];
        word32 sharePSz = sizeof(shareP);
        word32 shareVSz = sizeof(shareV);
        word32 confirmPSz = sizeof(confirmP);
        word32 confirmVSz = sizeof(confirmV);
        int ret;

        ret = wc_Spake2pInit(&ctx, WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
                             WC_SPAKE2P_PROVER, NULL, INVALID_DEVID);
        if (ret != 0)
            return ret;

        ret = wc_Spake2pSetContext(&ctx, appContext,
                                   sizeof(appContext) - 1);
        if (ret == 0)
            ret = wc_Spake2pSetIdentities(&ctx, idP, idPSz, idV, idVSz);
        if (ret == 0)
            ret = wc_Spake2pSetProverSecrets(&ctx, w0, w0Sz, w1, w1Sz);

        // Message 1: Prover -> Verifier
        if (ret == 0)
            ret = wc_Spake2pGenerateShare(&ctx, rng, shareP, &sharePSz);
        if (ret == 0)
            ret = app_send(shareP, sharePSz);

        // Message 2: Verifier -> Prover
        if (ret == 0)
            ret = app_recv(shareV, &shareVSz);
        if (ret == 0)
            ret = app_recv(confirmV, &confirmVSz);
        if (ret == 0) {
            ret = wc_Spake2pProcessPeerShare(&ctx, shareV, shareVSz,
                                             confirmP, &confirmPSz);
        }
        // Verify the Verifier BEFORE releasing confirmP.
        if (ret == 0)
            ret = wc_Spake2pVerifyPeerConfirm(&ctx, confirmV, confirmVSz);

        // Message 3: Prover -> Verifier
        if (ret == 0)
            ret = app_send(confirmP, confirmPSz);

        if (ret == 0)
            ret = wc_Spake2pGetSharedKey(&ctx, key, keySz);

        wc_Spake2pFree(&ctx);
        return ret;
    }
    \endcode

    \section spake2p_example_verifier Example: Verifier

    lookup_record() stands for the application's credential store. For an
    unknown identity it should return a deterministic fake record rather
    than failing (see Security Requirements).

    \code
    int verifier_run(WC_RNG* rng,
                     const byte* idV, word32 idVSz,
                     byte* key, word32* keySz)
    {
        wc_Spake2p ctx;
        byte   idP[64];
        word32 idPSz = sizeof(idP);
        byte   w0[WC_SPAKE2P_MAX_SCALAR_SZ];
        word32 w0Sz = sizeof(w0);
        byte   L[WC_SPAKE2P_MAX_L_SZ];
        word32 LSz = sizeof(L);
        byte   shareP[WC_SPAKE2P_MAX_SHARE_SZ];
        byte   shareV[WC_SPAKE2P_MAX_SHARE_SZ];
        byte   confirmP[WC_SPAKE2P_MAX_CONFIRM_SZ];
        byte   confirmV[WC_SPAKE2P_MAX_CONFIRM_SZ];
        word32 sharePSz = sizeof(shareP);
        word32 shareVSz = sizeof(shareV);
        word32 confirmPSz = sizeof(confirmP);
        word32 confirmVSz = sizeof(confirmV);
        int ret;

        // Message 1: Prover -> Verifier (identity framed by the app)
        ret = app_recv(idP, &idPSz);
        if (ret == 0)
            ret = app_recv(shareP, &sharePSz);
        if (ret == 0)
            ret = lookup_record(idP, idPSz, w0, &w0Sz, L, &LSz);
        if (ret != 0)
            return ret;

        ret = wc_Spake2pInit(&ctx, WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
                             WC_SPAKE2P_VERIFIER, NULL, INVALID_DEVID);
        if (ret != 0)
            return ret;

        ret = wc_Spake2pSetContext(&ctx, appContext,
                                   sizeof(appContext) - 1);
        if (ret == 0)
            ret = wc_Spake2pSetIdentities(&ctx, idP, idPSz, idV, idVSz);
        if (ret == 0)
            ret = wc_Spake2pSetVerifierSecrets(&ctx, w0, w0Sz, L, LSz);
        if (ret == 0)
            ret = wc_Spake2pGenerateShare(&ctx, rng, shareV, &shareVSz);
        if (ret == 0) {
            ret = wc_Spake2pProcessPeerShare(&ctx, shareP, sharePSz,
                                             confirmV, &confirmVSz);
        }

        // Message 2: Verifier -> Prover
        if (ret == 0)
            ret = app_send(shareV, shareVSz);
        if (ret == 0)
            ret = app_send(confirmV, confirmVSz);

        // Message 3: Prover -> Verifier
        if (ret == 0)
            ret = app_recv(confirmP, &confirmPSz);
        if (ret == 0)
            ret = wc_Spake2pVerifyPeerConfirm(&ctx, confirmP, confirmPSz);
        // On MAC_CMP_FAILED_E: count a failed attempt for idP.

        if (ret == 0)
            ret = wc_Spake2pGetSharedKey(&ctx, key, keySz);

        wc_Spake2pFree(&ctx);
        wc_ForceZero(w0, sizeof(w0));
        wc_ForceZero(L, sizeof(L));
        return ret;
    }
    \endcode
*/

/*!
    \ingroup SPAKE2P

    \brief Derives the scalars w0 and w1 from the output of a password-based
    key derivation function. This is the first step of registration (see
    the group overview); it is not part of the online exchange.

    The caller runs a PBKDF with a per-user salt over the RFC 9383 encoding
    of the password and identities. Prefer a memory-hard function: RFC 9383
    recommends scrypt (wc_scrypt()) or Argon2id. wc_PBKDF2() resists
    hardware-accelerated guessing less well, but may be required by an
    application protocol (for example Matter), by FIPS compliance, or by the
    memory limits of the Prover; if used, choose as high an iteration count
    as the slowest Prover can tolerate. The encoded input is:

    \verbatim
    len(pw) || pw || len(idProver) || idProver || len(idVerifier) || idVerifier
    \endverbatim

    where len() is an eight-byte little-endian byte count and an unknown
    identity is encoded as a zero length with no bytes (see Registration in
    the group overview). The PBKDF output length is
    2 * (ceil(log2(order)) / 8 + 8) bytes: 80 bytes for P-256, 112 for
    P-384, 148 for P-521. The first half is w0s and the second half is
    w1s. This function computes w0 = w0s mod order and w1 = w1s mod order
    and writes each as a big-endian scalar exactly as long as the group
    order (32, 48, or 66 bytes).

    This function does not see the PBKDF input, so protocols that define a
    different input (for example Matter) can use it unchanged.

    The extra 8 bytes per half make the bias of the modular reduction
    negligible. Other lengths are accepted from the group order length up
    to twice the group order length, but the recommended lengths should be
    used for interoperability with RFC 9383.

    The caller should zeroize the PBKDF output after this call.

    \return 0 on success.
    \return BAD_FUNC_ARG if any pointer is NULL, the suite is unknown, or
    w0sSz or w1sSz is shorter than the group order length or longer than
    twice the group order length.
    \return BUFFER_E if *w0Sz or *w1Sz is smaller than the group order
    length.
    \return NOT_COMPILED_IN if the suite's curve is not compiled in.
    \return MEMORY_E if a temporary cannot be allocated.
    \return <0 on other errors. On any error after the arguments are
    validated, the first group-order-length bytes of w0 and w1 are zeroed.

    \param suite the ciphersuite, one of WC_SPAKE2P_*. Determines the group
    order.
    \param w0s first half of the PBKDF output.
    \param w0sSz length of w0s in bytes.
    \param w1s second half of the PBKDF output.
    \param w1sSz length of w1s in bytes.
    \param w0 buffer that receives w0. WC_SPAKE2P_MAX_SCALAR_SZ bytes is
    always enough.
    \param w0Sz on input, the size of w0; on output, the number of bytes
    written.
    \param w1 buffer that receives w1. WC_SPAKE2P_MAX_SCALAR_SZ bytes is
    always enough.
    \param w1Sz on input, the size of w1; on output, the number of bytes
    written.
    \param heap heap hint for temporary allocations, or NULL.

    _Example_
    \code
    // in/inSz: len(pw) || pw || len(idProver) || idProver ||
    //          len(idVerifier) || idVerifier (see the Registration example)
    byte   ws[80];   // P-256: w0s || w1s, 40 bytes each
    byte   w0[WC_SPAKE2P_MAX_SCALAR_SZ];
    byte   w1[WC_SPAKE2P_MAX_SCALAR_SZ];
    word32 w0Sz = sizeof(w0);
    word32 w1Sz = sizeof(w1);
    int    ret;

    // scrypt with RFC 9383 parameters N = 2^15, r = 8, p = 1
    ret = wc_scrypt(ws, in, (int)inSz, salt, (int)saltSz, 15, 8, 1,
                    (int)sizeof(ws));
    if (ret == 0) {
        ret = wc_Spake2pDeriveW0W1(WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
                                   ws, 40, ws + 40, 40,
                                   w0, &w0Sz, w1, &w1Sz, NULL);
    }
    wc_ForceZero(ws, sizeof(ws));
    \endcode

    \sa wc_Spake2pComputeL
    \sa wc_Spake2pSetProverSecrets
    \sa wc_scrypt
    \sa wc_PBKDF2
*/
int wc_Spake2pDeriveW0W1(int suite,
    const byte* w0s, word32 w0sSz, const byte* w1s, word32 w1sSz,
    byte* w0, word32* w0Sz, byte* w1, word32* w1Sz, void* heap);

/*!
    \ingroup SPAKE2P

    \brief Computes the Verifier's registration value L = w1 * P, where P is
    the generator of the suite's curve. Together with w0, L forms the
    registration record that the Verifier stores in place of the password.

    L is written as a SEC1 uncompressed point (0x04 || X || Y): 65 bytes
    for P-256, 97 for P-384, 133 for P-521. This is typically called once,
    at registration, by whichever party knows the password. The Verifier
    must store L but must never store w1.

    \return 0 on success.
    \return BAD_FUNC_ARG if any pointer is NULL, the suite is unknown, or
    w1 is not a valid scalar (not exactly the group order length, zero, or
    not less than the group order).
    \return BUFFER_E if *LSz is too small for the encoded point. Nothing is
    written to L.
    \return NOT_COMPILED_IN if the suite's curve is not compiled in, or the
    build excludes ECC key import or export (NO_ECC_KEY_IMPORT,
    NO_ECC_KEY_EXPORT).
    \return MEMORY_E if a temporary cannot be allocated.
    \return <0 on other errors.

    \param suite the ciphersuite, one of WC_SPAKE2P_*.
    \param w1 the w1 scalar, as output by wc_Spake2pDeriveW0W1().
    \param w1Sz length of w1 in bytes; must equal the group order length
    (32, 48, or 66 bytes), as output by wc_Spake2pDeriveW0W1().
    \param L buffer that receives the encoded point.
    WC_SPAKE2P_MAX_L_SZ bytes is always enough.
    \param LSz on input, the size of L; on output, the number of bytes
    written.
    \param heap heap hint for temporary allocations, or NULL.
    \param devId device id for crypto callbacks, or INVALID_DEVID.

    _Example_
    \code
    byte   L[WC_SPAKE2P_MAX_L_SZ];
    word32 LSz = sizeof(L);
    int    ret;

    ret = wc_Spake2pComputeL(WC_SPAKE2P_P256_SHA256_HKDF_HMAC, w1, w1Sz,
                             L, &LSz, NULL, INVALID_DEVID);
    if (ret == 0) {
        // Store (w0, L) for this user on the Verifier.
    }
    \endcode

    \sa wc_Spake2pDeriveW0W1
    \sa wc_Spake2pSetVerifierSecrets
*/
int wc_Spake2pComputeL(int suite, const byte* w1, word32 w1Sz,
    byte* L, word32* LSz, void* heap, int devId);

/*!
    \ingroup SPAKE2P

    \brief Initializes a SPAKE2+ context for one protocol run in the given
    role.

    The wc_Spake2p structure is declared in the public header so it can be
    allocated on the stack or embedded in another structure, but its
    fields are private; access it only through this API. A context handles
    exactly one exchange. To run another, call wc_Spake2pFree() and then
    wc_Spake2pInit() again.

    The context is zeroed before the arguments are checked, so
    wc_Spake2pFree() may be called on it even if this function fails.
    Calling wc_Spake2pInit() on a context that is in use without first
    calling wc_Spake2pFree() leaks its allocations.

    \return 0 on success.
    \return BAD_FUNC_ARG if ctx is NULL or role is not WC_SPAKE2P_PROVER or
    WC_SPAKE2P_VERIFIER, or the suite value is unknown.
    \return NOT_COMPILED_IN if the suite's curve, hash, or MAC is not
    compiled in.

    \param ctx the context to initialize.
    \param suite the ciphersuite, one of WC_SPAKE2P_*. Must match the
    peer's.
    \param role WC_SPAKE2P_PROVER or WC_SPAKE2P_VERIFIER.
    \param heap heap hint for allocations made by this context, or NULL.
    \param devId device id for crypto callbacks, or INVALID_DEVID.

    _Example_
    \code
    wc_Spake2p ctx;
    int ret;

    ret = wc_Spake2pInit(&ctx, WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
                         WC_SPAKE2P_PROVER, NULL, INVALID_DEVID);
    if (ret == 0) {
        // ... run the exchange ...
        wc_Spake2pFree(&ctx);
    }
    \endcode

    \sa wc_Spake2pFree
    \sa wc_Spake2pNew
*/
int wc_Spake2pInit(wc_Spake2p* ctx, int suite, int role,
    void* heap, int devId);

/*!
    \ingroup SPAKE2P

    \brief Releases resources held by a context and zeroizes all secret
    material in it: w0, w1 or L, the ephemeral scalar, and all derived keys.
    The structure itself is not freed. It may be passed to
    wc_Spake2pInit() again.

    Call this after every run, whether it succeeded or failed. Passing NULL
    is a no-op.

    \param ctx the context to free.

    _Example_
    \code
    wc_Spake2p ctx;

    if (wc_Spake2pInit(&ctx, WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
                       WC_SPAKE2P_VERIFIER, NULL, INVALID_DEVID) == 0) {
        // ... run the exchange ...
        wc_Spake2pFree(&ctx);
    }
    \endcode

    \sa wc_Spake2pInit
    \sa wc_Spake2pDelete
*/
void wc_Spake2pFree(wc_Spake2p* ctx);

/*!
    \ingroup SPAKE2P

    \brief Allocates and initializes a SPAKE2+ context on the heap.
    Equivalent to allocating a wc_Spake2p and calling wc_Spake2pInit() on
    it. Use wc_Spake2pDelete() to free it.

    Not available when WC_NO_CONSTRUCTORS is defined.

    \return a pointer to the new context on success.
    \return NULL on failure; if result_code is not NULL, the error is
    stored there (MEMORY_E, BAD_FUNC_ARG, or NOT_COMPILED_IN).

    \param suite the ciphersuite, one of WC_SPAKE2P_*.
    \param role WC_SPAKE2P_PROVER or WC_SPAKE2P_VERIFIER.
    \param heap heap hint used for the allocation and by the context, or
    NULL.
    \param devId device id for crypto callbacks, or INVALID_DEVID.
    \param result_code optional; receives 0 on success or the error code on
    failure.

    _Example_
    \code
    int ret;
    wc_Spake2p* ctx = wc_Spake2pNew(WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
                                    WC_SPAKE2P_PROVER, NULL,
                                    INVALID_DEVID, &ret);
    if (ctx != NULL) {
        // ... run the exchange ...
        wc_Spake2pDelete(ctx, &ctx);   // ctx is now NULL
    }
    \endcode

    \sa wc_Spake2pDelete
    \sa wc_Spake2pInit
*/
wc_Spake2p* wc_Spake2pNew(int suite, int role, void* heap, int devId,
    int* result_code);

/*!
    \ingroup SPAKE2P

    \brief Frees a context allocated with wc_Spake2pNew(): zeroizes it as
    wc_Spake2pFree() does, then releases its memory.

    If ctx_p is not NULL, *ctx_p is set to NULL afterward, so the caller's
    pointer cannot be used after free. Pass the address of the variable
    that holds ctx, or NULL if that is not needed.

    Not available when WC_NO_CONSTRUCTORS is defined.

    \return 0 on success.
    \return BAD_FUNC_ARG if ctx is NULL.

    \param ctx the context to free.
    \param ctx_p optional address of the caller's pointer to ctx; set to
    NULL on success.

    _Example_
    \code
    wc_Spake2p* ctx = wc_Spake2pNew(WC_SPAKE2P_P256_SHA256_HKDF_HMAC,
                                    WC_SPAKE2P_VERIFIER, NULL,
                                    INVALID_DEVID, NULL);
    // ...
    wc_Spake2pDelete(ctx, &ctx);
    \endcode

    \sa wc_Spake2pNew
    \sa wc_Spake2pFree
*/
int wc_Spake2pDelete(wc_Spake2p* ctx, wc_Spake2p** ctx_p);

/*!
    \ingroup SPAKE2P

    \brief Sets the application context string that is bound into the
    protocol transcript.

    The context ties the exchange to a particular application protocol and
    version, for example "MyApp SPAKE2+ v1". It may also include a hash of
    earlier messages of the application protocol (such as the one carrying
    the salt and PBKDF parameters) so that tampering with them makes the
    exchange fail. Both sides must set byte-for-byte identical contexts;
    a mismatch makes confirmation fail with MAC_CMP_FAILED_E.

    Optional; the default is an empty context. RFC 9383 makes the context
    optional; this documentation recommends always setting one, to prevent
    downgrade and cross-protocol attacks. Must be called before
    wc_Spake2pGenerateShare(). The data is copied, so the caller's buffer may
    be reused or deallocated immediately. Calling it again replaces the
    previous value; if it fails, the previous value is left unchanged and
    the context remains usable.

    \return 0 on success.
    \return BAD_FUNC_ARG if ctx is NULL, or context is NULL while contextSz
    is not 0.
    \return BAD_STATE_E if called after wc_Spake2pGenerateShare().
    \return MEMORY_E if the copy cannot be allocated.

    \param ctx an initialized context.
    \param context the context bytes, or NULL if contextSz is 0.
    \param contextSz length of context in bytes.

    _Example_
    \code
    static const byte appContext[] = "MyApp SPAKE2+ v1";

    ret = wc_Spake2pSetContext(&ctx, appContext, sizeof(appContext) - 1);
    \endcode

    \sa wc_Spake2pSetIdentities
    \sa wc_Spake2pGenerateShare
*/
int wc_Spake2pSetContext(wc_Spake2p* ctx, const byte* context,
    word32 contextSz);

/*!
    \ingroup SPAKE2P

    \brief Sets the Prover and Verifier identities that are bound into the
    protocol transcript.

    Identities are application-defined byte strings, such as a user name
    and a server host name or device identifier. Both sides must pass the
    same idProver and the same idVerifier (in the same argument positions,
    regardless of which role is calling); a mismatch makes confirmation
    fail with MAC_CMP_FAILED_E.

    Optional; the default is empty identities. Either identity may be empty
    by passing NULL with size 0, but RFC 9383 says both SHOULD be non-empty
    unless the identities are already implicit in the application; leaving
    them empty otherwise risks unknown key-share attacks. Must be called
    before wc_Spake2pGenerateShare(). The data is copied. Calling it again
    replaces both previous values; if it fails, neither previous value is
    changed and the context remains usable.

    \return 0 on success.
    \return BAD_FUNC_ARG if ctx is NULL, or an identity pointer is NULL
    while its size is not 0.
    \return BAD_STATE_E if called after wc_Spake2pGenerateShare().
    \return MEMORY_E if the copies cannot be allocated.

    \param ctx an initialized context.
    \param idProver the Prover's identity, or NULL if idProverSz is 0.
    \param idProverSz length of idProver in bytes.
    \param idVerifier the Verifier's identity, or NULL if idVerifierSz is 0.
    \param idVerifierSz length of idVerifier in bytes.

    _Example_
    \code
    static const byte user[]   = "alice";
    static const byte server[] = "auth.example.com";

    ret = wc_Spake2pSetIdentities(&ctx, user, sizeof(user) - 1,
                                  server, sizeof(server) - 1);
    \endcode

    \sa wc_Spake2pSetContext
    \sa wc_Spake2pGenerateShare
*/
int wc_Spake2pSetIdentities(wc_Spake2p* ctx,
    const byte* idProver, word32 idProverSz,
    const byte* idVerifier, word32 idVerifierSz);

/*!
    \ingroup SPAKE2P

    \brief Loads the Prover's long-term secrets w0 and w1. Prover only.

    w0 and w1 are the scalars output by wc_Spake2pDeriveW0W1(), either
    stored from registration or recomputed from the password at login.
    They are copied into the context and zeroized by wc_Spake2pFree().

    Must be called exactly once, after wc_Spake2pInit() and before
    wc_Spake2pGenerateShare().

    \return 0 on success.
    \return BAD_FUNC_ARG if any pointer is NULL, or w0 or w1 is not a valid
    scalar for the suite (wrong length, zero, or not less than the group
    order).
    \return BAD_STATE_E if ctx was initialized as WC_SPAKE2P_VERIFIER, or
    the secrets were already set.
    \return MEMORY_E if a temporary cannot be allocated.

    On any error the context is unchanged and remains usable.

    \param ctx a context initialized with WC_SPAKE2P_PROVER.
    \param w0 the w0 scalar.
    \param w0Sz length of w0 in bytes (the group order length).
    \param w1 the w1 scalar.
    \param w1Sz length of w1 in bytes (the group order length).

    _Example_
    \code
    ret = wc_Spake2pSetProverSecrets(&ctx, w0, w0Sz, w1, w1Sz);
    \endcode

    \sa wc_Spake2pDeriveW0W1
    \sa wc_Spake2pSetVerifierSecrets
*/
int wc_Spake2pSetProverSecrets(wc_Spake2p* ctx,
    const byte* w0, word32 w0Sz, const byte* w1, word32 w1Sz);

/*!
    \ingroup SPAKE2P

    \brief Loads the Verifier's registration record (w0, L). Verifier only.

    w0 is the scalar from wc_Spake2pDeriveW0W1() and L is the encoded point
    from wc_Spake2pComputeL(), both produced at registration for the
    Prover whose identity the Verifier is authenticating. L is checked to
    be a valid point on the curve. Both are copied into the context and
    zeroized by wc_Spake2pFree().

    If the Prover's identity is unknown, load a deterministic fake record
    for it instead of failing, so that the exchange fails at confirmation
    exactly as it would for a wrong password (see the group overview).

    Must be called exactly once, after wc_Spake2pInit() and before
    wc_Spake2pGenerateShare().

    \return 0 on success.
    \return BAD_FUNC_ARG if any pointer is NULL, or w0 is not a valid
    scalar for the suite.
    \return IS_POINT_E if L is not a valid encoded point on the curve,
    including any encoding other than SEC1 uncompressed of exactly
    1 + 2 * (field size) bytes. This includes the SEC1 encoding of the
    point at infinity, the single byte 0x00.
    \return ECC_INF_E if L is an uncompressed encoding with both
    coordinates zero (0x04 followed by all zero bytes), the affine form
    used for the point at infinity.
    \return BAD_STATE_E if ctx was initialized as WC_SPAKE2P_PROVER, or the
    secrets were already set.
    \return NOT_COMPILED_IN if ECC key import is not compiled in
    (NO_ECC_KEY_IMPORT).
    \return MEMORY_E if a temporary cannot be allocated.

    On any error the context is unchanged and remains usable.

    \param ctx a context initialized with WC_SPAKE2P_VERIFIER.
    \param w0 the w0 scalar.
    \param w0Sz length of w0 in bytes (the group order length).
    \param L the encoded point L = w1*P.
    \param LSz length of L in bytes.

    _Example_
    \code
    ret = wc_Spake2pSetVerifierSecrets(&ctx, w0, w0Sz, L, LSz);
    \endcode

    \sa wc_Spake2pComputeL
    \sa wc_Spake2pSetProverSecrets
*/
int wc_Spake2pSetVerifierSecrets(wc_Spake2p* ctx,
    const byte* w0, word32 w0Sz, const byte* L, word32 LSz);

/*!
    \ingroup SPAKE2P

    \brief Generates this side's ephemeral scalar and public share.

    - Prover: picks a random x and outputs shareP = x*P + w0*M.
    - Verifier: picks a random y and outputs shareV = y*P + w0*N.

    M and N are the fixed points for the suite's curve defined in RFC 9383.
    The share is a SEC1 uncompressed point and is sent to the peer as is.
    The Prover sends shareP in the first message; the Verifier sends shareV
    together with confirmV in the second message.

    Must be called after the secrets are loaded and before
    wc_Spake2pProcessPeerShare(). The context and identities can no longer
    be changed afterward.

    \return 0 on success.
    \return BAD_FUNC_ARG if ctx, share, or shareSz is NULL, or rng is NULL
    and no fixed ephemeral scalar was set.
    \return BAD_STATE_E if the secrets have not been loaded, or a share was
    already generated.
    \return BUFFER_E if *shareSz is too small. Nothing is written to
    share.
    \return ECC_INF_E if the computed share is the point at infinity. With
    a random ephemeral scalar this has negligible probability.
    \return NOT_COMPILED_IN if no implementation of the point arithmetic is
    available for the suite's curve (a WOLFSSL_SP_MATH build without the
    single-precision code for that curve).
    \return MEMORY_E if a temporary cannot be allocated.
    \return <0 on other RNG, ECC or math errors.

    On any error the context keeps its secrets and has no share, so the call
    may be retried; a randomly generated ephemeral scalar is zeroized.

    \param ctx a context with secrets loaded.
    \param rng an initialized RNG. The ephemeral scalar is drawn from it
    unless a fixed one was set with wc_Spake2pSetEphemeral() (test builds
    only); when not NULL it is also used to blind the scalar multiplications
    in builds without single-precision ECC code for the curve.
    \param share buffer that receives the encoded share.
    WC_SPAKE2P_MAX_SHARE_SZ bytes is always enough.
    \param shareSz on input, the size of share; on output, the number of
    bytes written.

    _Example_
    \code
    byte   shareP[WC_SPAKE2P_MAX_SHARE_SZ];
    word32 sharePSz = sizeof(shareP);

    ret = wc_Spake2pGenerateShare(&ctx, &rng, shareP, &sharePSz);
    if (ret == 0)
        ret = app_send(shareP, sharePSz);
    \endcode

    \sa wc_Spake2pProcessPeerShare
*/
int wc_Spake2pGenerateShare(wc_Spake2p* ctx, WC_RNG* rng,
    byte* share, word32* shareSz);

/*!
    \ingroup SPAKE2P

    \brief Processes the peer's share, derives the session keys, and
    outputs this side's confirmation MAC.

    This function:
    -# Validates the peer share: it must be a correctly encoded point on
       the curve and must not be the point at infinity.
    -# Computes the shared points Z and V.
    -# Builds the RFC 9383 transcript from the context, identities, M, N,
       both shares, Z, V and w0, and hashes it to K_main.
    -# Derives the confirmation keys and K_shared from K_main with HKDF.
    -# Outputs this side's confirmation MAC:
       - Prover: confirmP = MAC(K_confirmP, shareV)
       - Verifier: confirmV = MAC(K_confirmV, shareP)

    A success here does not mean the peer knows the password; that is
    only established by wc_Spake2pVerifyPeerConfirm().

    The Verifier sends its confirmation (confirmV) with shareV right away.
    The Prover must hold its confirmation (confirmP) until
    wc_Spake2pVerifyPeerConfirm() has accepted confirmV, and must not send
    it if verification fails.

    On failure, the context enters a failed state and all further calls
    except wc_Spake2pFree() return BAD_STATE_E.

    \return 0 on success.
    \return BAD_FUNC_ARG if any pointer is NULL.
    \return BAD_STATE_E if wc_Spake2pGenerateShare() has not been called, or
    this function was already called.
    \return BUFFER_E if *confirmSz is too small.
    \return IS_POINT_E if the peer share is malformed or not on the curve.
    \return ECC_INF_E if the peer share, or a computed point, is the point
    at infinity.
    \return <0 on other errors.

    \param ctx a context after wc_Spake2pGenerateShare().
    \param peerShare the peer's share as received (shareV for the Prover,
    shareP for the Verifier).
    \param peerShareSz length of peerShare in bytes.
    \param confirm buffer that receives this side's confirmation MAC.
    WC_SPAKE2P_MAX_CONFIRM_SZ bytes is always enough.
    \param confirmSz on input, the size of confirm; on output, the number of
    bytes written.

    _Example_
    \code
    // Verifier
    byte   confirmV[WC_SPAKE2P_MAX_CONFIRM_SZ];
    word32 confirmVSz = sizeof(confirmV);

    ret = wc_Spake2pProcessPeerShare(&ctx, shareP, sharePSz,
                                     confirmV, &confirmVSz);
    if (ret == 0)
        ret = app_send(shareV, shareVSz);
    if (ret == 0)
        ret = app_send(confirmV, confirmVSz);
    \endcode

    \sa wc_Spake2pGenerateShare
    \sa wc_Spake2pVerifyPeerConfirm
*/
int wc_Spake2pProcessPeerShare(wc_Spake2p* ctx,
    const byte* peerShare, word32 peerShareSz,
    byte* confirm, word32* confirmSz);

/*!
    \ingroup SPAKE2P

    \brief Verifies the peer's confirmation MAC, in constant time.

    - Prover: verifies confirmV received from the Verifier. Only after this
      succeeds should the Prover send confirmP.
    - Verifier: verifies confirmP received from the Prover.

    Success proves that the peer derived the same keys, and therefore
    knows the password (Verifier's view) or the registration record
    (Prover's view). After success, wc_Spake2pGetSharedKey() can be called.

    A failure means the password was wrong, the two sides used different
    contexts, identities, or suites, a message was altered, or an attack is
    in progress; these cases cannot be distinguished. On the Verifier,
    count each failure as a failed login attempt for rate limiting. On
    failure, the context enters a failed state and all further calls except
    wc_Spake2pFree() return BAD_STATE_E.

    \return 0 if the confirmation is valid.
    \return MAC_CMP_FAILED_E if the confirmation is invalid or has the
    wrong length.
    \return BAD_FUNC_ARG if ctx or peerConfirm is NULL.
    \return BAD_STATE_E if wc_Spake2pProcessPeerShare() has not succeeded,
    or the context is in a failed state.

    \param ctx a context after wc_Spake2pProcessPeerShare().
    \param peerConfirm the peer's confirmation MAC as received.
    \param peerConfirmSz length of peerConfirm in bytes.

    _Example_
    \code
    // Prover: check the Verifier before releasing confirmP
    ret = wc_Spake2pVerifyPeerConfirm(&ctx, confirmV, confirmVSz);
    if (ret == 0)
        ret = app_send(confirmP, confirmPSz);
    \endcode

    \sa wc_Spake2pProcessPeerShare
    \sa wc_Spake2pGetSharedKey
*/
int wc_Spake2pVerifyPeerConfirm(wc_Spake2p* ctx,
    const byte* peerConfirm, word32 peerConfirmSz);

/*!
    \ingroup SPAKE2P

    \brief Retrieves the shared session key K_shared.

    Available only after wc_Spake2pVerifyPeerConfirm() has succeeded, so an
    unconfirmed key can never be obtained. Both sides obtain the same key.
    The key length is the suite's hash output length (32 bytes for SHA-256
    suites, 64 for SHA-512 suites).

    Treat K_shared as input keying material: derive the actual traffic or
    application keys from it with wc_HKDF(), using labels that are unique
    per purpose and direction. Zeroize the buffer when done. The key may be
    retrieved more than once until wc_Spake2pFree() is called.

    \return 0 on success.
    \return BAD_FUNC_ARG if any pointer is NULL.
    \return BAD_STATE_E if the peer's confirmation has not been verified.
    \return BUFFER_E if *keySz is too small.

    \param ctx a confirmed context.
    \param key buffer that receives K_shared. WC_SPAKE2P_MAX_KEY_SZ bytes is
    always enough.
    \param keySz on input, the size of key; on output, the number of bytes
    written.

    _Example_
    \code
    byte   kShared[WC_SPAKE2P_MAX_KEY_SZ];
    word32 kSharedSz = sizeof(kShared);
    byte   appKey[32];

    ret = wc_Spake2pGetSharedKey(&ctx, kShared, &kSharedSz);
    if (ret == 0) {
        ret = wc_HKDF(WC_SHA256, kShared, kSharedSz, NULL, 0,
                      (const byte*)"MyApp traffic key", 17,
                      appKey, sizeof(appKey));
    }
    wc_ForceZero(kShared, sizeof(kShared));
    \endcode

    \sa wc_Spake2pVerifyPeerConfirm
    \sa wc_HKDF
*/
int wc_Spake2pGetSharedKey(wc_Spake2p* ctx, byte* key, word32* keySz);

/*!
    \ingroup SPAKE2P

    \brief Fixes the ephemeral scalar (x for the Prover, y for the Verifier)
    instead of drawing it from the RNG. For known-answer tests only, such as
    reproducing the RFC 9383 test vectors.

    Only available when WOLFSSL_SPAKE2P_TEST_HOOKS is defined. Never define
    that macro in production builds: reusing or predicting the ephemeral
    scalar breaks the security of the protocol and can reveal w0.

    Must be called before wc_Spake2pGenerateShare(). The scalar is copied by
    this function, and zeroized by wc_Spake2pFree().

    \return 0 on success.
    \return BAD_FUNC_ARG if ctx or scalar is NULL, or the scalar is not
    valid for the suite (wrong length, zero, or not less than the group
    order).
    \return BAD_STATE_E if called after wc_Spake2pGenerateShare().

    \param ctx an initialized context.
    \param scalar the ephemeral scalar, big-endian.
    \param scalarSz length of scalar in bytes (the group order length).

    _Example_
    \code
    #ifdef WOLFSSL_SPAKE2P_TEST_HOOKS
    ret = wc_Spake2pSetEphemeral(&ctx, rfcX, sizeof(rfcX));
    if (ret == 0)
        ret = wc_Spake2pGenerateShare(&ctx, NULL, shareP, &sharePSz);
    // Compare shareP against the RFC 9383 test vector.
    #endif
    \endcode

    \sa wc_Spake2pGenerateShare
*/
int wc_Spake2pSetEphemeral(wc_Spake2p* ctx, const byte* scalar,
    word32 scalarSz);
