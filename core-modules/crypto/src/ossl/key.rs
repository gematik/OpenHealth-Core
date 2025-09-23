use std::ptr;
use crypto_openssl_sys::{d2i_PUBKEY_bio, d2i_PrivateKey_bio, i2d_PKCS8PrivateKey_bio, i2d_PUBKEY_bio, EVP_PKEY_CTX_free, EVP_PKEY_free, EVP_PKEY, EVP_PKEY_CTX};
use crate::ossl::api::{openssl_error, OsslResult};
use crate::ossl::bio::Bio;
use crate::ossl_check;

pub struct PKeyCtx(pub *mut EVP_PKEY_CTX);

impl PKeyCtx {
    pub fn as_ptr(&self) -> *mut EVP_PKEY_CTX {
        self.0
    }
}

impl Drop for PKeyCtx {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_CTX_free(self.0) };
    }
}

pub struct PKey(*mut EVP_PKEY);

impl PKey {
    pub fn new(pkey: *mut EVP_PKEY) -> Self {
        PKey(pkey)
    }

    pub fn from_der_private(data: &[u8]) -> OsslResult<Self> {
        let mut bio = Bio::from_slice(data)?;
        let p = unsafe { d2i_PrivateKey_bio(bio.as_mut_ptr(), ptr::null_mut()) };
        if p.is_null() {
            Err(openssl_error("Failed to load private key from DER"))
        } else {
            Ok(PKey(p))
        }
    }

    pub fn from_der_public(data: &[u8]) -> OsslResult<Self> {
        let mut bio = Bio::from_slice(data)?;
        let p = unsafe { d2i_PUBKEY_bio(bio.as_mut_ptr(), ptr::null_mut()) };
        if p.is_null() {
            Err(openssl_error("Failed to load public key from DER"))
        } else {
            Ok(PKey(p))
        }
    }

    pub fn to_der_private(&self) -> OsslResult<Vec<u8>> {
        let mut bio = Bio::new_mem()?;
        ossl_check!(
            unsafe {
                i2d_PKCS8PrivateKey_bio(
                    bio.as_mut_ptr(),
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

    pub fn to_der_public(&self) -> OsslResult<Vec<u8>> {
        let mut bio = Bio::new_mem()?;
        ossl_check!(
            unsafe { i2d_PUBKEY_bio(bio.as_mut_ptr(), self.0) },
            "Failed to convert public key to DER"
        );
        Ok(bio.to_vec())
    }

    pub fn as_mut_ptr(&self) -> *mut EVP_PKEY {
        self.0
    }
}

impl Drop for PKey {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_free(self.0) };
    }
}
