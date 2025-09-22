use crate::ossl::api::{openssl_error, OsslError, OsslResult};
use crate::ossl::ec::*;
use crate::ossl_check;
use crypto_openssl_sys::*;
use std::{os::raw::c_int, ptr};
use std::ffi::CString;
use crate::ossl::key::PKey;

/// KEM encapsulator
pub struct MlkemEncapsulation(PKey);

impl MlkemEncapsulation {
    pub fn create(algorithm: &str, encapsulation_key: &[u8]) -> OsslResult<Self> {
        let alg = CString::new(algorithm).unwrap();
        let p = unsafe {
            EVP_PKEY_new_raw_public_key_ex(
                ptr::null_mut(),
                alg.as_ptr(),
                ptr::null_mut(),
                encapsulation_key.as_ptr(),
                encapsulation_key.len(),
            )
        };
        if p.is_null() {
            return Err(openssl_error("Key initialization failed"));
        }
        Ok(MlkemEncapsulation(PKey::new(p)))
    }

    /// Returns a tuple of wrapped key and secret key.
    pub fn encapsulate(&self) -> OsslResult<(Vec<u8>, Vec<u8>)> {
        let raw = unsafe {
            EVP_PKEY_CTX_new_from_pkey(std::ptr::null_mut(), self.0.as_mut_ptr(), std::ptr::null_mut())
        };
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
            unsafe {
                EVP_PKEY_encapsulate(
                    ctx.as_ptr(),
                    ptr::null_mut(),
                    &mut wlen,
                    ptr::null_mut(),
                    &mut slen,
                )
            },
            "Failed to determine buffer sizes"
        );

        let mut wrapped = vec![0u8; wlen];
        let mut secret = vec![0u8; slen];
        ossl_check!(
            unsafe {
                EVP_PKEY_encapsulate(
                    ctx.as_ptr(),
                    wrapped.as_mut_ptr(),
                    &mut wlen,
                    secret.as_mut_ptr(),
                    &mut slen,
                )
            },
            "Encapsulation failed"
        );

        wrapped.truncate(wlen);
        secret.truncate(slen);
        Ok((wrapped, secret))
    }
}

/// KEM decapsulator
pub struct MlkemDecapsulation(PKey);

impl MlkemDecapsulation {
    /// Generate a new keypair
    pub fn create(algorithm: &str) -> OsslResult<Self> {
        let alg = CString::new(algorithm).unwrap();
        let gen_ctx = unsafe {
            EVP_PKEY_CTX_new_from_name(
                ptr::null_mut(),
                alg.as_ptr(),
                ptr::null_mut(),
            )
        };
        if gen_ctx.is_null() {
            return Err(openssl_error("Keygen context init failed"));
        }
        let gen_ctx = PKeyCtx(gen_ctx);
        ossl_check!(
            unsafe { EVP_PKEY_keygen_init(gen_ctx.as_ptr()) },
            "Keygen init failed"
        );

        // actually generate
        let mut raw: *mut EVP_PKEY = ptr::null_mut();
        ossl_check!(
            unsafe { EVP_PKEY_keygen(gen_ctx.as_ptr(), &mut raw) },
            "Keygen failed"
        );
        if raw.is_null() {
            return Err(openssl_error("Keygen returned null"));
        }
        Ok(MlkemDecapsulation(PKey(raw)))
    }

    /// Import an existing private key
    pub fn create_from_private_key(algorithm: &str, private_key: &[u8]) -> OsslResult<Self> {
        let alg = CString::new(algorithm).unwrap();
        let p = unsafe {
            EVP_PKEY_new_raw_private_key_ex(
                ptr::null_mut(),
                alg.as_ptr(),
                ptr::null_mut(),
                private_key.as_ptr(),
                private_key.len(),
            )
        };
        if p.is_null() {
            return Err(openssl_error("Importing private key failed"));
        }
        Ok(MlkemDecapsulation(PKey(p)))
    }

    /// Recover shared secret from wrapped key
    pub fn decapsulate(&self, wrapped_key: &[u8]) -> OsslResult<Vec<u8>> {
        let raw = unsafe {
            EVP_PKEY_CTX_new_from_pkey(
                std::ptr::null_mut(),
                self.0.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        if raw.is_null() {
            return Err(openssl_error("Failed to create context from key"));
        }
        let ctx = PKeyCtx(raw);
        ossl_check!(
            unsafe { EVP_PKEY_decapsulate_init(ctx.as_ptr(), ptr::null_mut()) },
            "Decapsulate init failed"
        );

        let mut klen = 0usize;
        ossl_check!(
            unsafe {
                EVP_PKEY_decapsulate(
                    ctx.as_ptr(),
                    ptr::null_mut(),
                    &mut klen,
                    wrapped_key.as_ptr(),
                    wrapped_key.len(),
                )
            },
            "Length query failed"
        );

        let mut key = vec![0u8; klen];
        ossl_check!(
            unsafe {
                EVP_PKEY_decapsulate(
                    ctx.as_ptr(),
                    key.as_mut_ptr(),
                    &mut klen,
                    wrapped_key.as_ptr(),
                    wrapped_key.len(),
                )
            },
            "Decapsulation failed"
        );

        key.truncate(klen);
        Ok(key)
    }

    /// Get the public (encapsulation) key
    pub fn get_encapsulation_key(&self) -> OsslResult<Vec<u8>> {
        let mut buf: *mut u8 = ptr::null_mut();
        let len = unsafe { EVP_PKEY_get1_encoded_public_key(self.0.as_ptr(), &mut buf) };
        if len == 0 {
            return Err(openssl_error("Extracting public key failed"));
        }
        let slice = unsafe { std::slice::from_raw_parts(buf, len) };
        let v = slice.to_vec();
        unsafe { OPENSSL_free_fn(buf as *mut _) };
        Ok(v)
    }

    /// Export the private key in PKCS8 DER form
    pub fn get_private_key(&self) -> OsslResult<Vec<u8>> {
        self.0.to_der_private()
    }
}
