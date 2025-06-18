use crate::bindings::api::*;
use crate::ossl_check;
use crypto_openssl_sys::*;
use std::os::raw::{c_char, c_int};
use std::ptr;

pub struct PKeyCtx(*mut EVP_PKEY_CTX);

impl PKeyCtx {
    /// expose the raw EVP_PKEY_CTX pointer
    pub fn as_ptr(&self) -> *mut EVP_PKEY_CTX {
        self.0
    }
}

impl Drop for PKeyCtx {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_CTX_free(self.0) };
    }
}

/// BIO wrapper
pub struct Bio(*mut BIO);

impl Bio {
    /// Create a new memory BIO
    pub fn new_mem() -> Result<Self, OsslError> {
        let b = unsafe { BIO_new(BIO_s_mem()) };
        if b.is_null() {
            Err(throw_openssl_error("Failed to create BIO"))
        } else {
            Ok(Bio(b))
        }
    }

    /// Create a BIO from a byte slice
    pub fn from_slice(data: &[u8]) -> Result<Self, OsslError> {
        let b = unsafe { BIO_new_mem_buf(data.as_ptr() as *const _, data.len() as c_int) };
        if b.is_null() {
            Err(throw_openssl_error("Failed to create BIO from buffer"))
        } else {
            Ok(Bio(b))
        }
    }

    /// Read all bytes from BIO
    pub fn to_vec(&self) -> Vec<u8> {
        unsafe {
            let mut ptr_data: *mut c_char = std::ptr::null_mut();
            let len = BIO_get_mem_data(self.0, &mut ptr_data) as isize;
            if len <= 0 || ptr_data.is_null() {
                return Vec::new();
            }
            // now cast to *const u8
            let slice = slice::from_raw_parts(ptr_data as *const u8, len as usize);
            slice.to_vec()
        }
    }
}

impl Drop for Bio {
    fn drop(&mut self) {
        unsafe { BIO_free(self.0) };
    }
}

/// EVP_PKEY wrapper
pub struct PKey(*mut EVP_PKEY);

impl PKey {
    pub fn from_der_private(data: &[u8]) -> Result<Self, OsslError> {
        let bio = Bio::from_slice(data)?;
        let p = unsafe { d2i_PrivateKey_bio(bio.0, ptr::null_mut()) };
        if p.is_null() {
            Err(throw_openssl_error("Failed to load private key from DER"))
        } else {
            Ok(PKey(p))
        }
    }

    pub fn from_der_public(data: &[u8]) -> Result<Self, OsslError> {
        let bio = Bio::from_slice(data)?;
        let p = unsafe { d2i_PUBKEY_bio(bio.0, ptr::null_mut()) };
        if p.is_null() {
            Err(throw_openssl_error("Failed to load public key from DER"))
        } else {
            Ok(PKey(p))
        }
    }

    pub fn to_der_private(&self) -> Result<Vec<u8>, OsslError> {
        let bio = Bio::new_mem()?;
        ossl_check!(
            unsafe {
                i2d_PKCS8PrivateKey_bio(
                    bio.0,
                    self.0,
                    ptr::null(),
                    ptr::null(),
                    0,
                    None,
                    ptr::null_mut(),
                )
            },
            "Failed to convert private key to DER"
        );
        Ok(bio.to_vec())
    }

    pub fn to_der_public(&self) -> Result<Vec<u8>, OsslError> {
        let bio = Bio::new_mem()?;
        ossl_check!(
            unsafe { i2d_PUBKEY_bio(bio.0, self.0) },
            "Failed to convert public key to DER"
        );
        Ok(bio.to_vec())
    }

    /// expose the raw EVP_PKEY pointer
    pub fn as_ptr(&self) -> *mut EVP_PKEY {
        self.0
    }
}

impl Drop for PKey {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_free(self.0) };
    }
}

/// ECDH context
pub struct Ecdh {
    ctx: PKeyCtx,
    _local: PKey,
}

impl Ecdh {
    pub fn new(priv_der: &[u8]) -> Result<Self, OsslError> {
        let p = PKey::from_der_private(priv_der)?;
        let raw = unsafe { EVP_PKEY_CTX_new(p.0, ptr::null_mut()) };
        if raw.is_null() {
            return Err(throw_openssl_error("Failed to create ECDH context"));
        }
        let ctx = PKeyCtx(raw);
        ossl_check!(
            unsafe { EVP_PKEY_derive_init(ctx.0) },
            "Failed to init ECDH context"
        );
        Ok(Ecdh { ctx, _local: p })
    }

    pub fn compute_secret(&self, pub_der: &[u8]) -> Result<Vec<u8>, OsslError> {
        let peer = PKey::from_der_public(pub_der)?;
        ossl_check!(
            unsafe { EVP_PKEY_derive_set_peer(self.ctx.0, peer.0) },
            "Failed to set peer"
        );
        let mut len: usize = 0;
        ossl_check!(
            unsafe { EVP_PKEY_derive(self.ctx.0, ptr::null_mut(), &mut len) },
            "Failed to compute secret"
        );
        let mut secret = vec![0u8; len];
        ossl_check!(
            unsafe { EVP_PKEY_derive(self.ctx.0, secret.as_mut_ptr(), &mut len) },
            "Failed to compute secret"
        );
        secret.truncate(len);
        Ok(secret)
    }
}
