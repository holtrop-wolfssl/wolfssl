/*
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

//! Integration tests for the `aead` crate trait implementations.
//!
//! Run with: `cargo test --features aead`

#![cfg(feature = "aead")]

use aead::{Aead, AeadInPlace, KeyInit, Payload};

// ---------------------------------------------------------------------------
// AES-128-GCM
// ---------------------------------------------------------------------------

/// NIST SP 800-38D, Test Case 2:
/// Key  = 00000000000000000000000000000000
/// IV   = 000000000000000000000000
/// PT   = 00000000000000000000000000000000
/// AAD  = (empty)
/// CT   = 0388dace60b6a392f328c2b971b2fe78
/// Tag  = ab6e47d42cec13bdf53a67b21257bddf
#[test]
#[cfg(aes_gcm)]
fn test_aes128gcm_nist_tc2_encrypt() {
    use wolfssl_wolfcrypt::aes::Aes128Gcm;

    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let expected_ciphertext = [
        0x03u8, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
    ];
    let expected_tag = [
        0xabu8, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
    ];

    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let nonce_arr: aead::Nonce<Aes128Gcm> = nonce.into();
    let mut buffer = [0u8; 16];
    let tag = cipher
        .encrypt_in_place_detached(&nonce_arr, &[], &mut buffer)
        .expect("AES-128-GCM encrypt failed");

    assert_eq!(buffer, expected_ciphertext);
    assert_eq!(&tag[..], &expected_tag);
}

#[test]
#[cfg(aes_gcm)]
fn test_aes128gcm_nist_tc2_decrypt() {
    use wolfssl_wolfcrypt::aes::Aes128Gcm;

    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let mut ciphertext = [
        0x03u8, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
    ];
    let tag_bytes = [
        0xabu8, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
    ];

    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let nonce_arr: aead::Nonce<Aes128Gcm> = nonce.into();
    let tag: aead::Tag<Aes128Gcm> = tag_bytes.into();
    cipher
        .decrypt_in_place_detached(&nonce_arr, &[], &mut ciphertext, &tag)
        .expect("AES-128-GCM decrypt failed");

    assert_eq!(ciphertext, [0u8; 16]);
}

/// Test AES-128-GCM roundtrip using the `aead::Aead` blanket impl (alloc).
#[test]
#[cfg(aes_gcm)]
fn test_aes128gcm_aead_roundtrip() {
    use wolfssl_wolfcrypt::aes::Aes128Gcm;

    let key = [0x42u8; 16];
    let nonce_bytes = [0x11u8; 12];
    let aad = b"associated data";
    let plaintext = b"Hello, AEAD world!";

    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let nonce: aead::Nonce<Aes128Gcm> = nonce_bytes.into();

    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("AES-128-GCM Aead::encrypt failed");

    let recovered = cipher
        .decrypt(&nonce, Payload { msg: &ciphertext, aad })
        .expect("AES-128-GCM Aead::decrypt failed");

    assert_eq!(recovered, plaintext);
}

/// Verify that decryption rejects a tampered tag.
#[test]
#[cfg(aes_gcm)]
fn test_aes128gcm_reject_bad_tag() {
    use wolfssl_wolfcrypt::aes::Aes128Gcm;

    let key = [0u8; 16];
    let nonce_bytes = [0u8; 12];
    let plaintext = b"some plaintext!";

    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let nonce: aead::Nonce<Aes128Gcm> = nonce_bytes.into();

    let mut ct = cipher.encrypt(&nonce, plaintext.as_ref()).expect("encrypt failed");
    let last = ct.len() - 1;
    ct[last] ^= 0xff;
    assert!(cipher.decrypt(&nonce, ct.as_slice()).is_err());
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

/// NIST SP 800-38D, Test Case 14 (256-bit key):
/// Key  = feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308
/// IV   = cafebabefacedbaddecaf888
/// PT   = d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a7
///        21c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39 (60 B)
/// AAD  = feedfacedeadbeeffeedfacedeadbeefabaddad2
/// CT   = 522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1a
///        a8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0a (60 B)
/// Tag  = 76fc6ece0f4e1768cddf8853bb2d551b
#[test]
#[cfg(aes_gcm)]
fn test_aes256gcm_nist_tc14_encrypt() {
    use wolfssl_wolfcrypt::aes::Aes256Gcm;

    let key = [
        0xfeu8, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    ];
    let nonce = [
        0xcau8, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88,
    ];
    let aad = [
        0xfeu8, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2,
    ];
    // 60-byte plaintext (TC13's 64-byte PT without the final 4 bytes 1aafd255)
    let plaintext = [
        0xd9u8, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39,
    ];
    // 60-byte ciphertext
    let expected_ciphertext = [
        0x52u8, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62,
    ];
    let expected_tag = [
        0x76u8, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b,
    ];

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce_arr: aead::Nonce<Aes256Gcm> = nonce.into();
    let mut buffer = plaintext;
    let tag = cipher
        .encrypt_in_place_detached(&nonce_arr, &aad, &mut buffer)
        .expect("AES-256-GCM encrypt failed");

    assert_eq!(buffer, expected_ciphertext);
    assert_eq!(&tag[..], &expected_tag);
}

/// Roundtrip test for AES-256-GCM using `aead::Aead`.
#[test]
#[cfg(aes_gcm)]
fn test_aes256gcm_aead_roundtrip() {
    use wolfssl_wolfcrypt::aes::Aes256Gcm;

    let key = [0xabu8; 32];
    let nonce_bytes = [0xbcu8; 12];
    let aad = b"test aad";
    let plaintext = b"AES-256-GCM roundtrip test";

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce: aead::Nonce<Aes256Gcm> = nonce_bytes.into();

    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("encrypt failed");

    let recovered = cipher
        .decrypt(&nonce, Payload { msg: &ciphertext, aad })
        .expect("decrypt failed");

    assert_eq!(recovered, plaintext);
}

// ---------------------------------------------------------------------------
// AES-128-CCM
// ---------------------------------------------------------------------------

/// Roundtrip test for AES-128-CCM using `aead::Aead`.
#[test]
#[cfg(aes_ccm)]
fn test_aes128ccm_aead_roundtrip() {
    use wolfssl_wolfcrypt::aes::Aes128Ccm;

    let key = [0x01u8; 16];
    let nonce_bytes = [0x02u8; 12];
    let aad = b"ccm aad";
    let plaintext = b"AES-128-CCM plaintext!";

    let cipher = Aes128Ccm::new_from_slice(&key).unwrap();
    let nonce: aead::Nonce<Aes128Ccm> = nonce_bytes.into();

    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("AES-128-CCM encrypt failed");

    let recovered = cipher
        .decrypt(&nonce, Payload { msg: &ciphertext, aad })
        .expect("AES-128-CCM decrypt failed");

    assert_eq!(recovered, plaintext);
}

/// Verify that AES-128-CCM decryption rejects a tampered ciphertext.
#[test]
#[cfg(aes_ccm)]
fn test_aes128ccm_reject_tampered() {
    use wolfssl_wolfcrypt::aes::Aes128Ccm;

    let key = [0x01u8; 16];
    let nonce_bytes = [0x02u8; 12];
    let plaintext = b"AES-128-CCM tamper test!";

    let cipher = Aes128Ccm::new_from_slice(&key).unwrap();
    let nonce: aead::Nonce<Aes128Ccm> = nonce_bytes.into();

    let mut ct = cipher.encrypt(&nonce, plaintext.as_ref()).expect("encrypt failed");
    ct[0] ^= 0x01;
    assert!(cipher.decrypt(&nonce, ct.as_slice()).is_err());
}

// ---------------------------------------------------------------------------
// AES-256-CCM
// ---------------------------------------------------------------------------

/// Roundtrip test for AES-256-CCM using `aead::Aead`.
#[test]
#[cfg(aes_ccm)]
fn test_aes256ccm_aead_roundtrip() {
    use wolfssl_wolfcrypt::aes::Aes256Ccm;

    let key = [0xddu8; 32];
    let nonce_bytes = [0xeeu8; 12];
    let aad = b"aes-256-ccm test";
    let plaintext = b"AES-256-CCM plaintext data";

    let cipher = Aes256Ccm::new_from_slice(&key).unwrap();
    let nonce: aead::Nonce<Aes256Ccm> = nonce_bytes.into();

    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("AES-256-CCM encrypt failed");

    let recovered = cipher
        .decrypt(&nonce, Payload { msg: &ciphertext, aad })
        .expect("AES-256-CCM decrypt failed");

    assert_eq!(recovered, plaintext);
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305
// ---------------------------------------------------------------------------

/// RFC 8439, Section 2.8.2 test vector.
///
/// Key  = 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
/// IV   = 070000004041424344454647
/// AAD  = 50515253c0c1c2c3c4c5c6c7
/// PT   = 4c61646965732061...
/// Tag  = 1ae10b594f09e26a7e902ecbd0600691
#[test]
#[cfg(chacha20_poly1305)]
fn test_chacha20poly1305_rfc8439_encrypt() {
    use wolfssl_wolfcrypt::chacha20_poly1305::ChaCha20Poly1305Aead;

    let key = [
        0x80u8, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce = [
        0x07u8, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
    ];
    let aad = [
        0x50u8, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let mut plaintext = [
        0x4cu8, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e,
    ];
    let expected_ciphertext = [
        0xd3u8, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    ];
    let expected_tag = [
        0x1au8, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ];

    let cipher = ChaCha20Poly1305Aead::new_from_slice(&key).unwrap();
    let nonce_arr: aead::Nonce<ChaCha20Poly1305Aead> = nonce.into();
    let tag = cipher
        .encrypt_in_place_detached(&nonce_arr, &aad, &mut plaintext)
        .expect("ChaCha20-Poly1305 encrypt failed");

    assert_eq!(plaintext, expected_ciphertext);
    assert_eq!(&tag[..], &expected_tag);
}

/// Roundtrip test for ChaCha20-Poly1305 using `aead::Aead`.
#[test]
#[cfg(chacha20_poly1305)]
fn test_chacha20poly1305_aead_roundtrip() {
    use wolfssl_wolfcrypt::chacha20_poly1305::ChaCha20Poly1305Aead;

    let key = [0x55u8; 32];
    let nonce_bytes = [0x66u8; 12];
    let aad = b"chacha20 aad";
    let plaintext = b"ChaCha20-Poly1305 roundtrip";

    let cipher = ChaCha20Poly1305Aead::new_from_slice(&key).unwrap();
    let nonce: aead::Nonce<ChaCha20Poly1305Aead> = nonce_bytes.into();

    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("encrypt failed");

    let recovered = cipher
        .decrypt(&nonce, Payload { msg: &ciphertext, aad })
        .expect("decrypt failed");

    assert_eq!(recovered, plaintext);
}

/// Verify that ChaCha20-Poly1305 rejects a tampered message.
#[test]
#[cfg(chacha20_poly1305)]
fn test_chacha20poly1305_reject_tampered() {
    use wolfssl_wolfcrypt::chacha20_poly1305::ChaCha20Poly1305Aead;

    let key = [0x77u8; 32];
    let nonce_bytes = [0x88u8; 12];
    let plaintext = b"tamper me!";

    let cipher = ChaCha20Poly1305Aead::new_from_slice(&key).unwrap();
    let nonce: aead::Nonce<ChaCha20Poly1305Aead> = nonce_bytes.into();

    let mut ct = cipher.encrypt(&nonce, plaintext.as_ref()).expect("encrypt failed");
    ct[0] ^= 0x01;
    assert!(cipher.decrypt(&nonce, ct.as_slice()).is_err());
}

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305
// ---------------------------------------------------------------------------

/// Roundtrip test for XChaCha20-Poly1305 using `aead::Aead`.
#[test]
#[cfg(xchacha20_poly1305)]
fn test_xchacha20poly1305_aead_roundtrip() {
    use wolfssl_wolfcrypt::chacha20_poly1305::XChaCha20Poly1305Aead;

    let key = [0xaau8; 32];
    let nonce_bytes = [0xbbu8; 24];
    let aad = b"xchacha20 aad";
    let plaintext = b"XChaCha20-Poly1305 roundtrip";

    let cipher = XChaCha20Poly1305Aead::new_from_slice(&key).unwrap();
    let nonce: aead::Nonce<XChaCha20Poly1305Aead> = nonce_bytes.into();

    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("XChaCha20-Poly1305 encrypt failed");

    let recovered = cipher
        .decrypt(&nonce, Payload { msg: &ciphertext, aad })
        .expect("XChaCha20-Poly1305 decrypt failed");

    assert_eq!(recovered, plaintext);
}

/// RFC 8439-based XChaCha20-Poly1305 known-answer test.
#[test]
#[cfg(xchacha20_poly1305)]
fn test_xchacha20poly1305_known_answer() {
    use wolfssl_wolfcrypt::chacha20_poly1305::XChaCha20Poly1305Aead;

    let key = [
        0x80u8, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce = [
        0x40u8, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];
    let aad = [
        0x50u8, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let mut plaintext = [
        0x4cu8, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e,
    ];
    let expected_ciphertext = [
        0xbdu8, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b,
        0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9, 0x39,
        0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc,
        0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39, 0x6c, 0xbb,
        0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44,
        0x0b, 0xf3, 0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39,
        0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16,
        0xcb, 0x96, 0xb7, 0x2e, 0x12, 0x13, 0xb4, 0x52,
        0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45,
        0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e,
        0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f,
        0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9,
        0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9,
        0x76, 0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13,
        0xb5, 0x2e,
    ];
    let expected_tag = [
        0xc0u8, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79,
        0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf, 0x49,
    ];

    let cipher = XChaCha20Poly1305Aead::new_from_slice(&key).unwrap();
    let nonce_arr: aead::Nonce<XChaCha20Poly1305Aead> = nonce.into();
    let tag = cipher
        .encrypt_in_place_detached(&nonce_arr, &aad, &mut plaintext)
        .expect("XChaCha20-Poly1305 encrypt failed");

    assert_eq!(plaintext, expected_ciphertext);
    assert_eq!(&tag[..], &expected_tag);
}

/// Verify that XChaCha20-Poly1305 decryption rejects a tampered ciphertext.
#[test]
#[cfg(xchacha20_poly1305)]
fn test_xchacha20poly1305_reject_tampered() {
    use wolfssl_wolfcrypt::chacha20_poly1305::XChaCha20Poly1305Aead;

    let key = [0x55u8; 32];
    let nonce_bytes = [0x66u8; 24];
    let plaintext = b"XChaCha tamper test";

    let cipher = XChaCha20Poly1305Aead::new_from_slice(&key).unwrap();
    let nonce: aead::Nonce<XChaCha20Poly1305Aead> = nonce_bytes.into();

    let mut ct = cipher.encrypt(&nonce, plaintext.as_ref()).expect("encrypt failed");
    ct[0] ^= 0x01;
    assert!(cipher.decrypt(&nonce, ct.as_slice()).is_err());
}
