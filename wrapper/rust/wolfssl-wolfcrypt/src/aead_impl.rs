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

/*!
This module implements the [`aead`](https://docs.rs/aead) crate's AEAD traits
for wolfCrypt's authenticated encryption algorithms.

Enable with the `aead` crate feature.

The following types are provided (each gated by the corresponding wolfSSL
build flag):

| Type                 | Algorithm           | Key | Nonce | Tag |
|----------------------|---------------------|-----|-------|-----|
| [`Aes128Gcm`]        | AES-128-GCM         | 16  | 12    | 16  |
| [`Aes256Gcm`]        | AES-256-GCM         | 32  | 12    | 16  |
| [`Aes128Ccm`]        | AES-128-CCM         | 16  | 12    | 16  |
| [`Aes256Ccm`]        | AES-256-CCM         | 32  | 12    | 16  |
| [`Aes128Eax`]        | AES-128-EAX         | 16  | 16    | 16  |
| [`Aes256Eax`]        | AES-256-EAX         | 32  | 16    | 16  |
| [`ChaCha20Poly1305`] | ChaCha20-Poly1305   | 32  | 12    | 16  |
| [`XChaCha20Poly1305`]| XChaCha20-Poly1305  | 32  | 24    | 16  |

All sizes are in bytes.
*/

#![cfg(feature = "aead")]

use crate::sys;
use core::mem::MaybeUninit;

pub use aead;
use aead::{AeadCore, AeadInPlace, KeyInit, KeySizeUser};
use aead::typenum::{U0, U12, U16, U24, U32};

// ---------------------------------------------------------------------------
// AES-GCM helpers
// ---------------------------------------------------------------------------

/// Encrypt `buffer` in-place using AES-GCM and write the authentication tag
/// to `tag`.  The same memory region is used for plaintext input and
/// ciphertext output (wolfCrypt's `wc_AesGcmEncrypt` supports overlapping
/// in/out pointers).
#[cfg(aes_gcm)]
fn gcm_encrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &mut [u8],
) -> Result<(), aead::Error> {
    let mut ws_aes = MaybeUninit::<sys::Aes>::uninit();
    let rc = unsafe {
        sys::wc_AesInit(ws_aes.as_mut_ptr(), core::ptr::null_mut(), sys::INVALID_DEVID)
    };
    if rc != 0 {
        return Err(aead::Error);
    }
    let mut ws_aes = unsafe { ws_aes.assume_init() };

    let rc = unsafe {
        sys::wc_AesGcmSetKey(&mut ws_aes, key.as_ptr(), key.len() as u32)
    };
    if rc != 0 {
        unsafe { sys::wc_AesFree(&mut ws_aes) };
        return Err(aead::Error);
    }

    // wolfCrypt AES-GCM supports in-place encryption (out == in).
    let buf_ptr = buffer.as_mut_ptr();
    let in_ptr = buf_ptr as *const u8;
    let rc = unsafe {
        sys::wc_AesGcmEncrypt(
            &mut ws_aes,
            buf_ptr, in_ptr, buffer.len() as u32,
            nonce.as_ptr(), nonce.len() as u32,
            tag.as_mut_ptr(), tag.len() as u32,
            aad.as_ptr(), aad.len() as u32,
        )
    };
    unsafe { sys::wc_AesFree(&mut ws_aes) };
    if rc != 0 {
        return Err(aead::Error);
    }
    Ok(())
}

/// Decrypt `buffer` in-place using AES-GCM and verify `tag`.
#[cfg(aes_gcm)]
fn gcm_decrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8],
) -> Result<(), aead::Error> {
    let mut ws_aes = MaybeUninit::<sys::Aes>::uninit();
    let rc = unsafe {
        sys::wc_AesInit(ws_aes.as_mut_ptr(), core::ptr::null_mut(), sys::INVALID_DEVID)
    };
    if rc != 0 {
        return Err(aead::Error);
    }
    let mut ws_aes = unsafe { ws_aes.assume_init() };

    let rc = unsafe {
        sys::wc_AesGcmSetKey(&mut ws_aes, key.as_ptr(), key.len() as u32)
    };
    if rc != 0 {
        unsafe { sys::wc_AesFree(&mut ws_aes) };
        return Err(aead::Error);
    }

    let buf_ptr = buffer.as_mut_ptr();
    let in_ptr = buf_ptr as *const u8;
    let rc = unsafe {
        sys::wc_AesGcmDecrypt(
            &mut ws_aes,
            buf_ptr, in_ptr, buffer.len() as u32,
            nonce.as_ptr(), nonce.len() as u32,
            tag.as_ptr(), tag.len() as u32,
            aad.as_ptr(), aad.len() as u32,
        )
    };
    unsafe { sys::wc_AesFree(&mut ws_aes) };
    if rc != 0 {
        return Err(aead::Error);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// AES-CCM helpers
// ---------------------------------------------------------------------------

#[cfg(aes_ccm)]
fn ccm_encrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &mut [u8],
) -> Result<(), aead::Error> {
    let mut ws_aes = MaybeUninit::<sys::Aes>::uninit();
    let rc = unsafe {
        sys::wc_AesInit(ws_aes.as_mut_ptr(), core::ptr::null_mut(), sys::INVALID_DEVID)
    };
    if rc != 0 {
        return Err(aead::Error);
    }
    let mut ws_aes = unsafe { ws_aes.assume_init() };

    let rc = unsafe {
        sys::wc_AesCcmSetKey(&mut ws_aes, key.as_ptr(), key.len() as u32)
    };
    if rc != 0 {
        unsafe { sys::wc_AesFree(&mut ws_aes) };
        return Err(aead::Error);
    }

    let buf_ptr = buffer.as_mut_ptr();
    let in_ptr = buf_ptr as *const u8;
    let rc = unsafe {
        sys::wc_AesCcmEncrypt(
            &mut ws_aes,
            buf_ptr, in_ptr, buffer.len() as u32,
            nonce.as_ptr(), nonce.len() as u32,
            tag.as_mut_ptr(), tag.len() as u32,
            aad.as_ptr(), aad.len() as u32,
        )
    };
    unsafe { sys::wc_AesFree(&mut ws_aes) };
    if rc != 0 {
        return Err(aead::Error);
    }
    Ok(())
}

#[cfg(aes_ccm)]
fn ccm_decrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8],
) -> Result<(), aead::Error> {
    let mut ws_aes = MaybeUninit::<sys::Aes>::uninit();
    let rc = unsafe {
        sys::wc_AesInit(ws_aes.as_mut_ptr(), core::ptr::null_mut(), sys::INVALID_DEVID)
    };
    if rc != 0 {
        return Err(aead::Error);
    }
    let mut ws_aes = unsafe { ws_aes.assume_init() };

    let rc = unsafe {
        sys::wc_AesCcmSetKey(&mut ws_aes, key.as_ptr(), key.len() as u32)
    };
    if rc != 0 {
        unsafe { sys::wc_AesFree(&mut ws_aes) };
        return Err(aead::Error);
    }

    let buf_ptr = buffer.as_mut_ptr();
    let in_ptr = buf_ptr as *const u8;
    let rc = unsafe {
        sys::wc_AesCcmDecrypt(
            &mut ws_aes,
            buf_ptr, in_ptr, buffer.len() as u32,
            nonce.as_ptr(), nonce.len() as u32,
            tag.as_ptr(), tag.len() as u32,
            aad.as_ptr(), aad.len() as u32,
        )
    };
    unsafe { sys::wc_AesFree(&mut ws_aes) };
    if rc != 0 {
        return Err(aead::Error);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// AES-EAX helpers
// ---------------------------------------------------------------------------

#[cfg(aes_eax)]
fn eax_encrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &mut [u8],
) -> Result<(), aead::Error> {
    let buf_ptr = buffer.as_mut_ptr();
    let in_ptr = buf_ptr as *const u8;
    let rc = unsafe {
        sys::wc_AesEaxEncryptAuth(
            key.as_ptr(), key.len() as u32,
            buf_ptr, in_ptr, buffer.len() as u32,
            nonce.as_ptr(), nonce.len() as u32,
            tag.as_mut_ptr(), tag.len() as u32,
            aad.as_ptr(), aad.len() as u32,
        )
    };
    if rc != 0 {
        return Err(aead::Error);
    }
    Ok(())
}

#[cfg(aes_eax)]
fn eax_decrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8],
) -> Result<(), aead::Error> {
    let buf_ptr = buffer.as_mut_ptr();
    let in_ptr = buf_ptr as *const u8;
    let rc = unsafe {
        sys::wc_AesEaxDecryptAuth(
            key.as_ptr(), key.len() as u32,
            buf_ptr, in_ptr, buffer.len() as u32,
            nonce.as_ptr(), nonce.len() as u32,
            tag.as_ptr(), tag.len() as u32,
            aad.as_ptr(), aad.len() as u32,
        )
    };
    if rc != 0 {
        return Err(aead::Error);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Macro to reduce boilerplate for key-holding AEAD wrapper types
// ---------------------------------------------------------------------------

macro_rules! impl_aead {
    (
        name = $name:ident,
        key_size = $key_size:ty,
        key_len = $key_len:literal,
        nonce_size = $nonce_size:ty,
        tag_size = $tag_size:ty,
        encrypt_fn = $encrypt_fn:ident,
        decrypt_fn = $decrypt_fn:ident,
        cfg = $cfg:meta,
        doc = $doc:literal,
    ) => {
        #[$cfg]
        #[doc = $doc]
        pub struct $name {
            key: [u8; $key_len],
        }

        #[$cfg]
        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        #[$cfg]
        impl AeadCore for $name {
            type NonceSize = $nonce_size;
            type TagSize = $tag_size;
            type CiphertextOverhead = U0;
        }

        #[$cfg]
        impl KeyInit for $name {
            fn new(key: &aead::Key<Self>) -> Self {
                let mut k = [0u8; $key_len];
                k.copy_from_slice(key.as_ref());
                $name { key: k }
            }
        }

        #[$cfg]
        impl AeadInPlace for $name {
            fn encrypt_in_place_detached(
                &self,
                nonce: &aead::Nonce<Self>,
                associated_data: &[u8],
                buffer: &mut [u8],
            ) -> Result<aead::Tag<Self>, aead::Error> {
                let mut tag = aead::Tag::<Self>::default();
                $encrypt_fn(&self.key, nonce.as_ref(), associated_data, buffer, tag.as_mut())?;
                Ok(tag)
            }

            fn decrypt_in_place_detached(
                &self,
                nonce: &aead::Nonce<Self>,
                associated_data: &[u8],
                buffer: &mut [u8],
                tag: &aead::Tag<Self>,
            ) -> Result<(), aead::Error> {
                $decrypt_fn(&self.key, nonce.as_ref(), associated_data, buffer, tag.as_ref())
            }
        }
    };
}

// ---------------------------------------------------------------------------
// AES-GCM
// ---------------------------------------------------------------------------

impl_aead!(
    name = Aes128Gcm,
    key_size = U16,
    key_len = 16,
    nonce_size = U12,
    tag_size = U16,
    encrypt_fn = gcm_encrypt_in_place,
    decrypt_fn = gcm_decrypt_in_place,
    cfg = cfg(aes_gcm),
    doc = "AES-128-GCM authenticated encryption (12-byte nonce, 16-byte tag).",
);

impl_aead!(
    name = Aes256Gcm,
    key_size = U32,
    key_len = 32,
    nonce_size = U12,
    tag_size = U16,
    encrypt_fn = gcm_encrypt_in_place,
    decrypt_fn = gcm_decrypt_in_place,
    cfg = cfg(aes_gcm),
    doc = "AES-256-GCM authenticated encryption (12-byte nonce, 16-byte tag).",
);

// ---------------------------------------------------------------------------
// AES-CCM
// ---------------------------------------------------------------------------

impl_aead!(
    name = Aes128Ccm,
    key_size = U16,
    key_len = 16,
    nonce_size = U12,
    tag_size = U16,
    encrypt_fn = ccm_encrypt_in_place,
    decrypt_fn = ccm_decrypt_in_place,
    cfg = cfg(aes_ccm),
    doc = "AES-128-CCM authenticated encryption (12-byte nonce, 16-byte tag).",
);

impl_aead!(
    name = Aes256Ccm,
    key_size = U32,
    key_len = 32,
    nonce_size = U12,
    tag_size = U16,
    encrypt_fn = ccm_encrypt_in_place,
    decrypt_fn = ccm_decrypt_in_place,
    cfg = cfg(aes_ccm),
    doc = "AES-256-CCM authenticated encryption (12-byte nonce, 16-byte tag).",
);

// ---------------------------------------------------------------------------
// AES-EAX
// ---------------------------------------------------------------------------

impl_aead!(
    name = Aes128Eax,
    key_size = U16,
    key_len = 16,
    nonce_size = U16,
    tag_size = U16,
    encrypt_fn = eax_encrypt_in_place,
    decrypt_fn = eax_decrypt_in_place,
    cfg = cfg(aes_eax),
    doc = "AES-128-EAX authenticated encryption (16-byte nonce, 16-byte tag).",
);

impl_aead!(
    name = Aes256Eax,
    key_size = U32,
    key_len = 32,
    nonce_size = U16,
    tag_size = U16,
    encrypt_fn = eax_encrypt_in_place,
    decrypt_fn = eax_decrypt_in_place,
    cfg = cfg(aes_eax),
    doc = "AES-256-EAX authenticated encryption (16-byte nonce, 16-byte tag).",
);

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305
// ---------------------------------------------------------------------------

/// ChaCha20-Poly1305 authenticated encryption (12-byte nonce, 16-byte tag).
#[cfg(chacha20_poly1305)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

#[cfg(chacha20_poly1305)]
impl KeySizeUser for ChaCha20Poly1305 {
    type KeySize = U32;
}

#[cfg(chacha20_poly1305)]
impl AeadCore for ChaCha20Poly1305 {
    type NonceSize = U12;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

#[cfg(chacha20_poly1305)]
impl KeyInit for ChaCha20Poly1305 {
    fn new(key: &aead::Key<Self>) -> Self {
        let mut k = [0u8; 32];
        k.copy_from_slice(key.as_ref());
        ChaCha20Poly1305 { key: k }
    }
}

#[cfg(chacha20_poly1305)]
impl AeadInPlace for ChaCha20Poly1305 {
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<aead::Tag<Self>, aead::Error> {
        let mut tag = aead::Tag::<Self>::default();
        let aad_size = associated_data.len() as u32;
        let buf_size = buffer.len() as u32;
        let buf_ptr = buffer.as_mut_ptr();
        let in_ptr = buf_ptr as *const u8;
        let rc = unsafe {
            sys::wc_ChaCha20Poly1305_Encrypt(
                self.key.as_ptr(), nonce.as_ref().as_ptr(),
                associated_data.as_ptr(), aad_size,
                in_ptr, buf_size,
                buf_ptr, tag.as_mut().as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(aead::Error);
        }
        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &aead::Tag<Self>,
    ) -> Result<(), aead::Error> {
        let aad_size = associated_data.len() as u32;
        let buf_size = buffer.len() as u32;
        let buf_ptr = buffer.as_mut_ptr();
        let in_ptr = buf_ptr as *const u8;
        let rc = unsafe {
            sys::wc_ChaCha20Poly1305_Decrypt(
                self.key.as_ptr(), nonce.as_ref().as_ptr(),
                associated_data.as_ptr(), aad_size,
                in_ptr, buf_size,
                tag.as_ref().as_ptr(), buf_ptr,
            )
        };
        if rc != 0 {
            return Err(aead::Error);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305
// ---------------------------------------------------------------------------

/// XChaCha20-Poly1305 authenticated encryption (24-byte nonce, 16-byte tag).
#[cfg(xchacha20_poly1305)]
pub struct XChaCha20Poly1305 {
    key: [u8; 32],
}

#[cfg(xchacha20_poly1305)]
impl KeySizeUser for XChaCha20Poly1305 {
    type KeySize = U32;
}

#[cfg(xchacha20_poly1305)]
impl AeadCore for XChaCha20Poly1305 {
    type NonceSize = U24;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

#[cfg(xchacha20_poly1305)]
impl KeyInit for XChaCha20Poly1305 {
    fn new(key: &aead::Key<Self>) -> Self {
        let mut k = [0u8; 32];
        k.copy_from_slice(key.as_ref());
        XChaCha20Poly1305 { key: k }
    }
}

#[cfg(xchacha20_poly1305)]
impl AeadInPlace for XChaCha20Poly1305 {
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<aead::Tag<Self>, aead::Error> {
        // wc_XChaCha20Poly1305_Encrypt appends the 16-byte auth tag to the
        // ciphertext output buffer.  We need a temporary output buffer that is
        // plaintext_len + AUTH_TAG_SIZE, then split off the tag.
        // To avoid heap allocation, use a fixed-size stack buffer for the
        // extra tag bytes and copy the ciphertext portion back in-place.
        let buf_ptr = buffer.as_mut_ptr();
        let in_ptr = buf_ptr as *const u8;
        let buf_len = buffer.len();
        // Temporary storage for the auth tag that XChaCha appends.
        let mut tag_buf = [0u8; 16];
        // Use a small shim: encrypt to a temporary combined output of
        // ciphertext + tag.  We call wc_XChaCha20Poly1305_Encrypt which
        // writes (buf_len + 16) bytes to `out`.  Work directly in buffer +
        // tag_buf by manually calling the C function with a destination that
        // spans both.
        //
        // wolfCrypt XChaCha20-Poly1305 writes the tag as the last 16 bytes of
        // the output.  We provide a contiguous region [buffer | tag_buf].
        // Since they are separate allocations on the stack we cannot do that
        // safely.  Instead, encrypt via the one-shot function and then split.
        let _ = (buf_ptr, in_ptr, buf_len, &mut tag_buf);

        // Use a heap-free approach: call wc_XChaCha20Poly1305_Encrypt where
        // out == in (in-place) and out_sz = in_sz + 16.  The tag is the last
        // 16 bytes.  We need a contiguous output region of in_sz + 16.
        // Since we cannot extend the caller's buffer, use an on-stack array
        // sized to MAX_STACK_XCHACHA_PLAINTEXT.  If the plaintext fits, use
        // it; otherwise return an error.
        const MAX_INLINE: usize = 4096;
        if buffer.len() > MAX_INLINE {
            return Err(aead::Error);
        }
        let mut out_buf = [0u8; MAX_INLINE + 16];
        let out_len = buffer.len() + 16;
        let rc = unsafe {
            sys::wc_XChaCha20Poly1305_Encrypt(
                out_buf.as_mut_ptr(), out_len,
                in_ptr, buf_len,
                associated_data.as_ptr(), associated_data.len(),
                nonce.as_ref().as_ptr(), nonce.as_ref().len(),
                self.key.as_ptr(), self.key.len(),
            )
        };
        if rc != 0 {
            return Err(aead::Error);
        }
        buffer.copy_from_slice(&out_buf[..buf_len]);
        let mut tag = aead::Tag::<Self>::default();
        tag.as_mut().copy_from_slice(&out_buf[buf_len..buf_len + 16]);
        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &aead::Tag<Self>,
    ) -> Result<(), aead::Error> {
        // wc_XChaCha20Poly1305_Decrypt expects the tag appended after the
        // ciphertext.  Build a combined [ciphertext | tag] buffer on the
        // stack and call the function.
        const MAX_INLINE: usize = 4096;
        let buf_len = buffer.len();
        if buf_len > MAX_INLINE {
            return Err(aead::Error);
        }
        let mut in_buf = [0u8; MAX_INLINE + 16];
        in_buf[..buf_len].copy_from_slice(buffer);
        in_buf[buf_len..buf_len + 16].copy_from_slice(tag.as_ref());
        let rc = unsafe {
            sys::wc_XChaCha20Poly1305_Decrypt(
                buffer.as_mut_ptr(), buf_len,
                in_buf.as_ptr(), buf_len + 16,
                associated_data.as_ptr(), associated_data.len(),
                nonce.as_ref().as_ptr(), nonce.as_ref().len(),
                self.key.as_ptr(), self.key.len(),
            )
        };
        if rc != 0 {
            return Err(aead::Error);
        }
        Ok(())
    }
}
