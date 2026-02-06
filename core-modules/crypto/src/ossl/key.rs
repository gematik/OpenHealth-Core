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

use std::ptr;

use crate::ossl::api::{openssl_error, OsslResult};
use crate::ossl::bio::Bio;
use crate::ossl_check;
use crypto_openssl_sys::{
    d2i_PUBKEY_bio, d2i_PrivateKey_bio, i2d_PKCS8PrivateKey_bio, i2d_PUBKEY_bio, EVP_PKEY_CTX_free, EVP_PKEY_free,
    EVP_PKEY, EVP_PKEY_CTX,
};

/// Wrapper around `EVP_PKEY_CTX` that frees the context on drop.
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

/// Wrapper around `EVP_PKEY` with automatic resource management.
pub struct PKey(*mut EVP_PKEY);

impl PKey {
    pub fn new(pkey: *mut EVP_PKEY) -> Self {
        Self(pkey)
    }

    pub fn from_der_private(data: &[u8]) -> OsslResult<Self> {
        let mut bio = Bio::from_slice(data)?;
        let p = unsafe { d2i_PrivateKey_bio(bio.as_mut_ptr(), ptr::null_mut()) };
        if p.is_null() {
            Err(openssl_error("Failed to load private key from DER"))
        } else {
            Ok(Self(p))
        }
    }

    pub fn from_der_public(data: &[u8]) -> OsslResult<Self> {
        let mut bio = Bio::from_slice(data)?;
        let p = unsafe { d2i_PUBKEY_bio(bio.as_mut_ptr(), ptr::null_mut()) };
        if p.is_null() {
            Err(openssl_error("Failed to load public key from DER"))
        } else {
            Ok(Self(p))
        }
    }

    pub fn to_der_private(&self) -> OsslResult<Vec<u8>> {
        let mut bio = Bio::new_mem()?;
        ossl_check!(
            unsafe {
                i2d_PKCS8PrivateKey_bio(bio.as_mut_ptr(), self.0, ptr::null(), ptr::null(), 0, None, ptr::null_mut())
            },
            "Failed to convert private key to DER"
        );
        Ok(bio.to_vec())
    }

    pub fn to_der_public(&self) -> OsslResult<Vec<u8>> {
        let mut bio = Bio::new_mem()?;
        ossl_check!(unsafe { i2d_PUBKEY_bio(bio.as_mut_ptr(), self.0) }, "Failed to convert public key to DER");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_der_private_rejects_invalid_data() {
        match PKey::from_der_private(&[]) {
            Err(err) => assert!(err.to_string().starts_with("Failed to load private key")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn from_der_public_rejects_invalid_data() {
        match PKey::from_der_public(&[]) {
            Err(err) => assert!(err.to_string().starts_with("Failed to load public key")),
            Ok(_) => panic!("expected error"),
        }
    }
}
