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
use std::ptr;

use crate::ossl::api::{openssl_error, OsslResult};
use crate::ossl::key::{PKey, PKeyCtx};
use crate::ossl_check;
use crypto_openssl_sys::*;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static FORCE_PKEY_PUBLIC_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_PKEY_CTX_FROM_PKEY_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_PKEY_CTX_FROM_NAME_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_PKEY_KEYGEN_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_PKEY_PRIVATE_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_PKEY_GET_ENC_KEY_ZERO: Cell<bool> = const { Cell::new(false) };
}

#[inline]
fn pkey_new_raw_public_key(alg: *const std::os::raw::c_char, key: *const u8, key_len: usize) -> *mut EVP_PKEY {
    #[cfg(test)]
    {
        if FORCE_PKEY_PUBLIC_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EVP_PKEY_new_raw_public_key_ex(ptr::null_mut(), alg, ptr::null_mut(), key, key_len) }
}

#[inline]
fn pkey_ctx_new_from_pkey(pkey: *mut EVP_PKEY) -> *mut EVP_PKEY_CTX {
    #[cfg(test)]
    {
        if FORCE_PKEY_CTX_FROM_PKEY_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EVP_PKEY_CTX_new_from_pkey(std::ptr::null_mut(), pkey, std::ptr::null_mut()) }
}

#[inline]
fn pkey_ctx_new_from_name(alg: *const std::os::raw::c_char) -> *mut EVP_PKEY_CTX {
    #[cfg(test)]
    {
        if FORCE_PKEY_CTX_FROM_NAME_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg, ptr::null_mut()) }
}

#[inline]
fn pkey_new_raw_private_key(alg: *const std::os::raw::c_char, key: *const u8, key_len: usize) -> *mut EVP_PKEY {
    #[cfg(test)]
    {
        if FORCE_PKEY_PRIVATE_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EVP_PKEY_new_raw_private_key_ex(ptr::null_mut(), alg, ptr::null_mut(), key, key_len) }
}

#[inline]
fn pkey_get_encoded_public_key(pkey: *mut EVP_PKEY, buf: *mut *mut u8) -> usize {
    #[cfg(test)]
    {
        if FORCE_PKEY_GET_ENC_KEY_ZERO.with(|flag| flag.get()) {
            unsafe { *buf = ptr::null_mut() };
            return 0;
        }
    }
    unsafe { EVP_PKEY_get1_encoded_public_key(pkey, buf) }
}

/// Wrapper for ML-KEM encapsulation using OpenSSL EVP APIs.
pub struct MlkemEncapsulation(PKey);

impl MlkemEncapsulation {
    pub fn create(algorithm: &str, encapsulation_key: &[u8]) -> OsslResult<Self> {
        let alg = CString::new(algorithm).unwrap();
        let p = pkey_new_raw_public_key(alg.as_ptr(), encapsulation_key.as_ptr(), encapsulation_key.len());
        if p.is_null() {
            return Err(openssl_error("Key initialization failed"));
        }
        Ok(MlkemEncapsulation(PKey::new(p)))
    }

    /// Returns a tuple of wrapped key and secret key.
    pub fn encapsulate(&self) -> OsslResult<(Vec<u8>, Vec<u8>)> {
        let raw = pkey_ctx_new_from_pkey(self.0.as_mut_ptr());
        if raw.is_null() {
            return Err(openssl_error("Failed to create context from key"));
        }
        let ctx = PKeyCtx(raw);

        ossl_check!(
            unsafe { EVP_PKEY_encapsulate_init(ctx.as_ptr(), std::ptr::null_mut()) },
            "Failed to init encapsulation"
        );

        let mut wlen = 0usize;
        let mut slen = 0usize;
        ossl_check!(
            unsafe { EVP_PKEY_encapsulate(ctx.as_ptr(), ptr::null_mut(), &mut wlen, ptr::null_mut(), &mut slen,) },
            "Failed to determine buffer sizes"
        );

        let mut wrapped = vec![0u8; wlen];
        let mut secret = vec![0u8; slen];
        ossl_check!(
            unsafe {
                EVP_PKEY_encapsulate(ctx.as_ptr(), wrapped.as_mut_ptr(), &mut wlen, secret.as_mut_ptr(), &mut slen)
            },
            "Encapsulation failed"
        );

        wrapped.truncate(wlen);
        secret.truncate(slen);
        Ok((wrapped, secret))
    }
}

/// KEM decapsulator
/// Wrapper for ML-KEM decapsulation using OpenSSL EVP APIs.
pub struct MlkemDecapsulation(PKey);

impl MlkemDecapsulation {
    /// Generate a new keypair
    pub fn create(algorithm: &str) -> OsslResult<Self> {
        let alg = CString::new(algorithm).unwrap();
        let gen_ctx = pkey_ctx_new_from_name(alg.as_ptr());
        if gen_ctx.is_null() {
            return Err(openssl_error("Keygen context init failed"));
        }
        let gen_ctx = PKeyCtx(gen_ctx);
        ossl_check!(unsafe { EVP_PKEY_keygen_init(gen_ctx.as_ptr()) }, "Keygen init failed");

        // actually generate
        let mut raw: *mut EVP_PKEY = ptr::null_mut();
        ossl_check!(unsafe { EVP_PKEY_keygen(gen_ctx.as_ptr(), &mut raw) }, "Keygen failed");
        #[cfg(test)]
        if FORCE_PKEY_KEYGEN_NULL.with(|flag| flag.get()) {
            raw = ptr::null_mut();
        }
        if raw.is_null() {
            return Err(openssl_error("Keygen returned null"));
        }
        Ok(MlkemDecapsulation(PKey::new(raw)))
    }

    /// Import an existing private key
    pub fn create_from_private_key(algorithm: &str, private_key: &[u8]) -> OsslResult<Self> {
        let alg = CString::new(algorithm).unwrap();
        let p = pkey_new_raw_private_key(alg.as_ptr(), private_key.as_ptr(), private_key.len());
        if p.is_null() {
            return Err(openssl_error("Importing private key failed"));
        }
        Ok(MlkemDecapsulation(PKey::new(p)))
    }

    /// Recover shared secret from wrapped key
    pub fn decapsulate(&self, wrapped_key: &[u8]) -> OsslResult<Vec<u8>> {
        let raw = pkey_ctx_new_from_pkey(self.0.as_mut_ptr());
        if raw.is_null() {
            return Err(openssl_error("Failed to create context from key"));
        }
        let ctx = PKeyCtx(raw);
        ossl_check!(unsafe { EVP_PKEY_decapsulate_init(ctx.as_ptr(), ptr::null_mut()) }, "Decapsulate init failed");

        let mut klen = 0usize;
        ossl_check!(
            unsafe {
                EVP_PKEY_decapsulate(ctx.as_ptr(), ptr::null_mut(), &mut klen, wrapped_key.as_ptr(), wrapped_key.len())
            },
            "Length query failed"
        );

        let mut key = vec![0u8; klen];
        ossl_check!(
            unsafe {
                EVP_PKEY_decapsulate(ctx.as_ptr(), key.as_mut_ptr(), &mut klen, wrapped_key.as_ptr(), wrapped_key.len())
            },
            "Decapsulation failed"
        );

        key.truncate(klen);
        Ok(key)
    }

    /// Get the public (encapsulation) key
    pub fn get_encapsulation_key(&self) -> OsslResult<Vec<u8>> {
        let mut buf: *mut u8 = ptr::null_mut();
        let len = pkey_get_encoded_public_key(self.0.as_mut_ptr(), &mut buf);
        if len == 0 {
            return Err(openssl_error("Extracting public key failed"));
        }
        let slice = unsafe { std::slice::from_raw_parts(buf, len) };
        let v = slice.to_vec();
        unsafe { OPENSSL_free_fn(buf as *mut _) };
        Ok(v)
    }

    /// Export the private key in raw form (to be re-imported with `create_from_private_key`)
    pub fn get_private_key(&self) -> OsslResult<Vec<u8>> {
        let mut len = 0usize;
        ossl_check!(
            unsafe { EVP_PKEY_get_raw_private_key(self.0.as_mut_ptr(), ptr::null_mut(), &mut len) },
            "Failed to determine ML-KEM private key length"
        );
        let mut out = vec![0u8; len];
        ossl_check!(
            unsafe { EVP_PKEY_get_raw_private_key(self.0.as_mut_ptr(), out.as_mut_ptr(), &mut len) },
            "Failed to export ML-KEM private key"
        );
        out.truncate(len);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_algorithm_rejected() {
        match MlkemEncapsulation::create("INVALID", &[0x01, 0x02]) {
            Err(err) => assert!(err.to_string().contains("Key initialization failed")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn create_fails_when_keygen_ctx_null() {
        FORCE_PKEY_CTX_FROM_NAME_NULL.with(|flag| flag.set(true));
        let res = MlkemDecapsulation::create("ML-KEM-512");
        FORCE_PKEY_CTX_FROM_NAME_NULL.with(|flag| flag.set(false));
        match res {
            Err(err) => assert!(err.to_string().contains("Keygen context init failed")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn create_fails_when_keygen_returns_null() {
        FORCE_PKEY_KEYGEN_NULL.with(|flag| flag.set(true));
        let res = MlkemDecapsulation::create("ML-KEM-512");
        FORCE_PKEY_KEYGEN_NULL.with(|flag| flag.set(false));
        match res {
            Err(err) => assert!(err.to_string().contains("Keygen returned null")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn create_from_private_key_fails_when_null() {
        FORCE_PKEY_PRIVATE_NULL.with(|flag| flag.set(true));
        let res = MlkemDecapsulation::create_from_private_key("ML-KEM-512", &[0x01, 0x02]);
        FORCE_PKEY_PRIVATE_NULL.with(|flag| flag.set(false));
        match res {
            Err(err) => assert!(err.to_string().contains("Importing private key failed")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn encapsulate_fails_when_ctx_null() {
        let dec = MlkemDecapsulation::create("ML-KEM-512").unwrap();
        let pk = dec.get_encapsulation_key().unwrap();
        let enc = MlkemEncapsulation::create("ML-KEM-512", &pk).unwrap();
        FORCE_PKEY_CTX_FROM_PKEY_NULL.with(|flag| flag.set(true));
        let res = enc.encapsulate();
        FORCE_PKEY_CTX_FROM_PKEY_NULL.with(|flag| flag.set(false));
        match res {
            Err(err) => assert!(err.to_string().contains("Failed to create context from key")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn decapsulate_fails_when_ctx_null() {
        let dec = MlkemDecapsulation::create("ML-KEM-512").unwrap();
        FORCE_PKEY_CTX_FROM_PKEY_NULL.with(|flag| flag.set(true));
        let res = dec.decapsulate(&[0x01; 800]);
        FORCE_PKEY_CTX_FROM_PKEY_NULL.with(|flag| flag.set(false));
        match res {
            Err(err) => assert!(err.to_string().contains("Failed to create context from key")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn get_encapsulation_key_fails_when_len_zero() {
        let dec = MlkemDecapsulation::create("ML-KEM-512").unwrap();
        FORCE_PKEY_GET_ENC_KEY_ZERO.with(|flag| flag.set(true));
        let res = dec.get_encapsulation_key();
        FORCE_PKEY_GET_ENC_KEY_ZERO.with(|flag| flag.set(false));
        match res {
            Err(err) => assert!(err.to_string().contains("Extracting public key failed")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn create_encapsulation_fails_when_pkey_null() {
        FORCE_PKEY_PUBLIC_NULL.with(|flag| flag.set(true));
        let res = MlkemEncapsulation::create("ML-KEM-512", &[0x01; 10]);
        FORCE_PKEY_PUBLIC_NULL.with(|flag| flag.set(false));
        match res {
            Err(err) => assert!(err.to_string().contains("Key initialization failed")),
            Ok(_) => panic!("expected error"),
        }
    }
}
