// SPDX-FileCopyrightText: Copyright 2025 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::ptr;

use crate::ossl::api::{openssl_error, OsslErrorKind, OsslResult};
use crate::ossl_check;

use crypto_openssl_sys::*;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static FORCE_CTX_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_FETCH_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_UPDATE_FAIL: Cell<bool> = const { Cell::new(false) };
    static FORCE_FINAL_FAIL: Cell<bool> = const { Cell::new(false) };
    static FORCE_CIPHER_MODE: Cell<c_int> = const { Cell::new(-1) };
    static FORCE_SET_PARAMS_FAIL: Cell<bool> = const { Cell::new(false) };
}

#[inline]
fn cipher_ctx_new() -> *mut EVP_CIPHER_CTX {
    #[cfg(test)]
    {
        if FORCE_CTX_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EVP_CIPHER_CTX_new() }
}

#[inline]
fn cipher_fetch(name: *const c_char) -> *mut EVP_CIPHER {
    #[cfg(test)]
    {
        if FORCE_FETCH_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EVP_CIPHER_fetch(ptr::null_mut(), name, ptr::null()) }
}

#[inline]
fn cipher_mode(ctx: *mut EVP_CIPHER_CTX) -> c_int {
    #[cfg(test)]
    {
        let forced = FORCE_CIPHER_MODE.with(|flag| flag.get());
        if forced >= 0 {
            return forced;
        }
    }
    unsafe { EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(ctx)) }
}

#[inline]
fn cipher_ctx_set_params(ctx: *mut EVP_CIPHER_CTX, params: *mut OSSL_PARAM) -> c_int {
    #[cfg(test)]
    {
        if FORCE_SET_PARAMS_FAIL.with(|flag| flag.get()) {
            return 0;
        }
    }
    unsafe { EVP_CIPHER_CTX_set_params(ctx, params) }
}

#[inline]
fn encrypt_update(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    out_len: *mut c_int,
    input: *const u8,
    input_len: c_int,
) -> c_int {
    #[cfg(test)]
    {
        if FORCE_UPDATE_FAIL.with(|flag| flag.get()) {
            return 0;
        }
    }
    unsafe { EVP_EncryptUpdate(ctx, out as *mut _, out_len, input, input_len) }
}

#[inline]
fn decrypt_update(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    out_len: *mut c_int,
    input: *const u8,
    input_len: c_int,
) -> c_int {
    #[cfg(test)]
    {
        if FORCE_UPDATE_FAIL.with(|flag| flag.get()) {
            return 0;
        }
    }
    unsafe { EVP_DecryptUpdate(ctx, out as *mut _, out_len, input, input_len) }
}

#[inline]
fn encrypt_final(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, out_len: *mut c_int) -> c_int {
    #[cfg(test)]
    {
        if FORCE_FINAL_FAIL.with(|flag| flag.get()) {
            return 0;
        }
    }
    unsafe { EVP_EncryptFinal_ex(ctx, out as *mut _, out_len) }
}

#[inline]
fn decrypt_final(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, out_len: *mut c_int) -> c_int {
    #[cfg(test)]
    {
        if FORCE_FINAL_FAIL.with(|flag| flag.get()) {
            return 0;
        }
    }
    unsafe { EVP_DecryptFinal_ex(ctx, out as *mut _, out_len) }
}

pub struct AesCipher {
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *mut EVP_CIPHER,
}

impl AesCipher {
    fn new(algorithm: &str) -> OsslResult<Self> {
        let ctx = cipher_ctx_new();
        if ctx.is_null() {
            return Err(openssl_error(OsslErrorKind::CipherCtxCreateFailed));
        }
        let alg = CString::new(algorithm).unwrap();
        let cipher = cipher_fetch(alg.as_ptr());
        if cipher.is_null() {
            unsafe { EVP_CIPHER_CTX_free(ctx) };
            return Err(openssl_error(OsslErrorKind::CipherFetchFailed));
        }
        Ok(Self { ctx, cipher })
    }

    #[inline]
    pub fn is_encrypting(&self) -> bool {
        unsafe { EVP_CIPHER_CTX_is_encrypting(self.ctx) == 1 }
    }

    fn init_cipher(
        algorithm: &str,
        key: &[u8],
        iv: &[u8],
        init_fn: unsafe extern "C" fn(
            ctx: *mut EVP_CIPHER_CTX,
            cipher: *const EVP_CIPHER,
            key: *const u8,
            iv: *const u8,
            params: *const OSSL_PARAM,
        ) -> c_int,
    ) -> OsslResult<Self> {
        let aes = Self::new(algorithm)?;

        ossl_check!(
            unsafe { init_fn(aes.ctx, aes.cipher, ptr::null(), ptr::null(), ptr::null()) },
            OsslErrorKind::CipherInitFailed
        );

        let mode = cipher_mode(aes.ctx);
        if mode == EVP_CIPH_GCM_MODE || mode == EVP_CIPH_CCM_MODE {
            let mut iv_len = iv.len();
            let mut params = [
                unsafe { OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN.as_ptr() as *const _, &mut iv_len) },
                unsafe { OSSL_PARAM_construct_end() },
            ];
            ossl_check!(cipher_ctx_set_params(aes.ctx, params.as_mut_ptr()), OsslErrorKind::CipherSetIvLenFailed);
        } else {
            ossl_check!(
                unsafe { init_fn(aes.ctx, aes.cipher, key.as_ptr(), iv.as_ptr(), ptr::null()) },
                OsslErrorKind::CipherInitFailed
            );
        }

        ossl_check!(
            unsafe { init_fn(aes.ctx, ptr::null(), key.as_ptr(), iv.as_ptr(), ptr::null()) },
            OsslErrorKind::CipherInitFailed
        );

        Ok(aes)
    }

    pub fn create_encryptor(algorithm: &str, key: &[u8], iv: &[u8]) -> OsslResult<Self> {
        Self::init_cipher(algorithm, key, iv, EVP_EncryptInit_ex2)
    }

    pub fn create_decryptor(algorithm: &str, key: &[u8], iv: &[u8]) -> OsslResult<Self> {
        Self::init_cipher(algorithm, key, iv, EVP_DecryptInit_ex2)
    }

    pub fn set_auto_padding(&mut self, enabled: bool) {
        unsafe { EVP_CIPHER_CTX_set_padding(self.ctx, if enabled { 1 } else { 0 }) };
    }

    pub fn set_aad(&mut self, aad: &[u8]) -> OsslResult<()> {
        let mut out_len = 0;
        ossl_check!(
            unsafe {
                if self.is_encrypting() {
                    EVP_EncryptUpdate(self.ctx, ptr::null_mut(), &mut out_len, aad.as_ptr(), aad.len() as c_int)
                } else {
                    EVP_DecryptUpdate(self.ctx, ptr::null_mut(), &mut out_len, aad.as_ptr(), aad.len() as c_int)
                }
            },
            OsslErrorKind::CipherSetAadFailed
        );
        Ok(())
    }

    pub fn set_auth_tag(&mut self, auth_tag: &[u8]) -> OsslResult<()> {
        if auth_tag.is_empty() {
            return Err(openssl_error(OsslErrorKind::CipherAuthTagEmpty));
        }
        let mut params = [
            unsafe {
                OSSL_PARAM_construct_octet_string(
                    OSSL_CIPHER_PARAM_AEAD_TAG.as_ptr() as *const _,
                    auth_tag.as_ptr() as *mut _,
                    auth_tag.len(),
                )
            },
            unsafe { OSSL_PARAM_construct_end() },
        ];
        ossl_check!(
            unsafe { EVP_CIPHER_CTX_set_params(self.ctx, params.as_mut_ptr()) },
            OsslErrorKind::CipherSetAuthTagFailed
        );
        Ok(())
    }

    pub fn get_auth_tag(&self, tag_len: usize) -> OsslResult<Vec<u8>> {
        let mut tag = vec![0u8; tag_len];
        let mut params = [
            unsafe {
                OSSL_PARAM_construct_octet_string(
                    OSSL_CIPHER_PARAM_AEAD_TAG.as_ptr() as *const _,
                    tag.as_mut_ptr() as *mut _,
                    tag_len,
                )
            },
            unsafe { OSSL_PARAM_construct_end() },
        ];
        ossl_check!(
            unsafe { EVP_CIPHER_CTX_get_params(self.ctx, params.as_mut_ptr()) },
            OsslErrorKind::CipherGetAuthTagFailed
        );
        Ok(tag)
    }

    pub fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> OsslResult<usize> {
        let block_size = unsafe { EVP_CIPHER_CTX_get_block_size(self.ctx) } as usize;
        let old_output_len = output.len();
        output.resize(old_output_len + input.len() + block_size, 0);

        let mut out_len: c_int = 0;
        let rc = unsafe {
            if self.is_encrypting() {
                encrypt_update(
                    self.ctx,
                    output.as_mut_ptr().add(old_output_len),
                    &mut out_len,
                    input.as_ptr(),
                    input.len() as c_int,
                )
            } else {
                decrypt_update(
                    self.ctx,
                    output.as_mut_ptr().add(old_output_len),
                    &mut out_len,
                    input.as_ptr(),
                    input.len() as c_int,
                )
            }
        };
        if rc != 1 {
            return if self.is_encrypting() {
                Err(openssl_error(OsslErrorKind::CipherUpdateEncryptFailed))
            } else {
                Err(openssl_error(OsslErrorKind::CipherUpdateDecryptFailed))
            };
        }
        output.truncate(old_output_len + out_len as usize);
        Ok(out_len as usize)
    }

    pub fn finalize(&mut self, output: &mut Vec<u8>) -> OsslResult<usize> {
        let block_size = unsafe { EVP_CIPHER_CTX_get_block_size(self.ctx) } as usize;
        let old_output_len = output.len();
        output.resize(old_output_len + block_size, 0);

        let mut out_len: c_int = 0;
        let rc = unsafe {
            if self.is_encrypting() {
                encrypt_final(self.ctx, output.as_mut_ptr().add(old_output_len), &mut out_len)
            } else {
                decrypt_final(self.ctx, output.as_mut_ptr().add(old_output_len), &mut out_len)
            }
        };
        ossl_check!(
            rc,
            if self.is_encrypting() {
                OsslErrorKind::CipherFinalizeEncryptFailed
            } else {
                OsslErrorKind::CipherFinalizeDecryptFailed
            }
        );
        output.truncate(old_output_len + out_len as usize);
        Ok(out_len as usize)
    }

    #[allow(dead_code)]
    /// Expose raw context pointer if needed by other modules
    pub fn as_ptr(&self) -> *mut EVP_CIPHER_CTX {
        self.ctx
    }
}

impl Drop for AesCipher {
    fn drop(&mut self) {
        unsafe {
            if !self.ctx.is_null() {
                EVP_CIPHER_CTX_free(self.ctx);
            }
            if !self.cipher.is_null() {
                EVP_CIPHER_free(self.cipher);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ossl::api::with_thread_local_cell;
    use crate::ossl::api::OsslErrorKind;
    use std::ptr;

    const KEY_16: &[u8] = b"1234567890123456";
    const IV_16: &[u8] = b"1234567890123456";
    const IV_12: &[u8] = b"123456789012";

    #[test]
    fn create_encryptor_rejects_invalid_algorithm() {
        let err = AesCipher::create_encryptor("invalid-cipher", KEY_16, IV_16).err().expect("expected error");
        assert_eq!(err.kind(), &OsslErrorKind::CipherFetchFailed);
    }

    #[test]
    fn set_auth_tag_rejects_empty() {
        let mut cipher = AesCipher::create_decryptor("aes-128-gcm", KEY_16, IV_16).unwrap();
        let err = cipher.set_auth_tag(&[]).err().expect("expected error");
        assert_eq!(err.kind(), &OsslErrorKind::CipherAuthTagEmpty);
    }

    #[test]
    fn create_encryptor_fails_when_ctx_null() {
        let err =
            with_thread_local_cell(&FORCE_CTX_NULL, true, || AesCipher::create_encryptor("aes-128-cbc", KEY_16, IV_16))
                .err()
                .expect("expected error");
        assert_eq!(err.kind(), &OsslErrorKind::CipherCtxCreateFailed);
    }

    #[test]
    fn create_encryptor_fails_when_cipher_null() {
        let err = with_thread_local_cell(&FORCE_FETCH_NULL, true, || {
            AesCipher::create_encryptor("aes-128-cbc", KEY_16, IV_16)
        })
        .err()
        .expect("expected error");
        assert_eq!(err.kind(), &OsslErrorKind::CipherFetchFailed);
    }

    #[test]
    fn create_encryptor_gcm_sets_iv_length() {
        let cipher = AesCipher::create_encryptor("aes-128-gcm", KEY_16, IV_12).unwrap();
        let iv_len = unsafe { EVP_CIPHER_CTX_get_iv_length(cipher.ctx) };
        assert_eq!(iv_len, IV_12.len() as c_int);
    }

    #[test]
    fn create_encryptor_gcm_sets_custom_iv_length() {
        let iv = b"12345678";
        let cipher = AesCipher::create_encryptor("aes-128-gcm", KEY_16, iv).unwrap();
        let iv_len = unsafe { EVP_CIPHER_CTX_get_iv_length(cipher.ctx) };
        assert_eq!(iv_len, iv.len() as c_int);
    }

    #[test]
    fn create_encryptor_gcm_reports_set_iv_length_failure_when_forced_to_gcm() {
        let err = with_thread_local_cell(&FORCE_CIPHER_MODE, EVP_CIPH_GCM_MODE, || {
            with_thread_local_cell(&FORCE_SET_PARAMS_FAIL, true, || {
                AesCipher::create_encryptor("aes-128-gcm", KEY_16, b"12345678")
            })
        })
        .err()
        .expect("expected error");
        assert_eq!(err.kind(), &OsslErrorKind::CipherSetIvLenFailed);
    }

    #[test]
    fn create_encryptor_gcm_reports_set_iv_length_failure_when_forced_to_ccm() {
        let err = with_thread_local_cell(&FORCE_CIPHER_MODE, EVP_CIPH_CCM_MODE, || {
            with_thread_local_cell(&FORCE_SET_PARAMS_FAIL, true, || {
                AesCipher::create_encryptor("aes-128-gcm", KEY_16, b"12345678")
            })
        })
        .err()
        .expect("expected error");
        assert_eq!(err.kind(), &OsslErrorKind::CipherSetIvLenFailed);
    }

    #[test]
    fn create_decryptor_gcm_sets_custom_iv_length() {
        let iv = b"12345678";
        let cipher = AesCipher::create_decryptor("aes-128-gcm", KEY_16, iv).unwrap();
        let iv_len = unsafe { EVP_CIPHER_CTX_get_iv_length(cipher.ctx) };
        assert_eq!(iv_len, iv.len() as c_int);
    }

    #[test]
    fn update_reports_encrypt_error() {
        let mut cipher = AesCipher::create_encryptor("aes-128-cbc", KEY_16, IV_16).unwrap();
        let err = with_thread_local_cell(&FORCE_UPDATE_FAIL, true, || cipher.update(b"hello", &mut Vec::new()))
            .err()
            .expect("expected error");
        assert_eq!(err.kind(), &OsslErrorKind::CipherUpdateEncryptFailed);
    }

    #[test]
    fn update_reports_decrypt_error() {
        let mut cipher = AesCipher::create_decryptor("aes-128-cbc", KEY_16, IV_16).unwrap();
        let err = with_thread_local_cell(&FORCE_UPDATE_FAIL, true, || cipher.update(b"hello", &mut Vec::new()))
            .err()
            .expect("expected error");
        assert_eq!(err.kind(), &OsslErrorKind::CipherUpdateDecryptFailed);
    }

    #[test]
    fn finalize_reports_encrypt_error() {
        let mut cipher = AesCipher::create_encryptor("aes-128-cbc", KEY_16, IV_16).unwrap();
        let err = with_thread_local_cell(&FORCE_FINAL_FAIL, true, || cipher.finalize(&mut Vec::new()))
            .err()
            .expect("expected error");
        assert_eq!(err.kind(), &OsslErrorKind::CipherFinalizeEncryptFailed);
    }

    #[test]
    fn finalize_reports_decrypt_error() {
        let mut cipher = AesCipher::create_decryptor("aes-128-cbc", KEY_16, IV_16).unwrap();
        let err = with_thread_local_cell(&FORCE_FINAL_FAIL, true, || cipher.finalize(&mut Vec::new()))
            .err()
            .expect("expected error");
        assert_eq!(err.kind(), &OsslErrorKind::CipherFinalizeDecryptFailed);
    }

    #[test]
    fn drop_handles_null_pointers() {
        let _cipher = AesCipher { ctx: ptr::null_mut(), cipher: ptr::null_mut() };
    }
}
