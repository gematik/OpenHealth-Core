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

use std::{ffi::CString, ptr};

use crate::ossl::api::{openssl_error, OsslResult};
use crate::ossl_check;
use crypto_openssl_sys::*;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static FORCE_MAC_FETCH_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_MAC_CTX_NULL: Cell<bool> = const { Cell::new(false) };
}

#[inline]
fn mac_fetch(name: *const std::os::raw::c_char) -> *mut EVP_MAC {
    #[cfg(test)]
    {
        if FORCE_MAC_FETCH_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EVP_MAC_fetch(ptr::null_mut(), name, ptr::null_mut()) }
}

#[inline]
fn mac_ctx_new(mac: *mut EVP_MAC) -> *mut EVP_MAC_CTX {
    #[cfg(test)]
    {
        if FORCE_MAC_CTX_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EVP_MAC_CTX_new(mac) }
}

pub struct Mac {
    mac: *mut EVP_MAC,
    ctx: *mut EVP_MAC_CTX,
}

impl Drop for Mac {
    fn drop(&mut self) {
        unsafe {
            EVP_MAC_CTX_free(self.ctx);
            EVP_MAC_free(self.mac);
        }
    }
}

impl Mac {
    /// Fetches MAC and allocates a new context.
    fn new(name: &str) -> OsslResult<Self> {
        let cname = CString::new(name).unwrap();
        let mac = mac_fetch(cname.as_ptr());
        if mac.is_null() {
            return Err(openssl_error("EVP_MAC_fetch failed"));
        }
        let ctx = mac_ctx_new(mac);
        if ctx.is_null() {
            unsafe { EVP_MAC_free(mac) };
            return Err(openssl_error("EVP_MAC_CTX_new failed"));
        }
        Ok(Mac { mac, ctx })
    }

    /// Creates and initializes a MAC with the given key and cipher name.
    pub fn create(key: &[u8], name: &str, cipher: Option<&str>, digest: Option<&str>) -> OsslResult<Self> {
        let cm = Self::new(name)?;

        // Hold CStrings so their memory outlives EVP_MAC_init
        let name_cipher = CString::new("cipher").unwrap();
        let name_digest = CString::new("digest").unwrap();
        let val_cipher = cipher.map(|c| CString::new(c).unwrap());
        let val_digest = digest.map(|d| CString::new(d).unwrap());

        let mut params = Vec::with_capacity(3);

        if let Some(val_cipher) = &val_cipher {
            params.push(unsafe {
                OSSL_PARAM_construct_utf8_string(name_cipher.as_ptr(), val_cipher.as_ptr() as *mut _, 0)
            });
        }

        if let Some(val_digest) = &val_digest {
            params.push(unsafe {
                OSSL_PARAM_construct_utf8_string(name_digest.as_ptr(), val_digest.as_ptr() as *mut _, 0)
            });
        }

        params.push(unsafe { OSSL_PARAM_construct_end() });

        ossl_check!(unsafe { EVP_MAC_init(cm.ctx, key.as_ptr(), key.len(), params.as_ptr()) }, "EVP_MAC_init failed");
        Ok(cm)
    }

    /// Feeds more data into the MAC.
    pub fn update(&mut self, input: &[u8]) -> OsslResult<()> {
        ossl_check!(unsafe { EVP_MAC_update(self.ctx, input.as_ptr(), input.len()) }, "EVP_MAC_update failed");
        Ok(())
    }

    /// Finalizes and returns the MAC bytes.
    pub fn finalize(&mut self) -> OsslResult<Vec<u8>> {
        // first call to get output length
        let mut outl = 0usize;
        ossl_check!(
            unsafe { EVP_MAC_final(self.ctx, ptr::null_mut(), &mut outl, 0) },
            "EVP_MAC_final failed to get output length"
        );

        let mut out = vec![0u8; outl];
        ossl_check!(
            unsafe { EVP_MAC_final(self.ctx, out.as_mut_ptr(), &mut outl, outl) },
            "EVP_MAC_final failed to finalize"
        );
        out.truncate(outl);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ossl::api::with_thread_local_cell;

    #[test]
    fn new_fails_when_fetch_null() {
        let res = with_thread_local_cell(&FORCE_MAC_FETCH_NULL, true, || Mac::new("HMAC"));
        match res {
            Err(err) => assert!(err.to_string().starts_with("EVP_MAC_fetch failed")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn new_fails_when_ctx_null() {
        let res = with_thread_local_cell(&FORCE_MAC_CTX_NULL, true, || Mac::new("HMAC"));
        match res {
            Err(err) => assert!(err.to_string().starts_with("EVP_MAC_CTX_new failed")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn create_rejects_invalid_cmac_cipher() {
        // The EVP_MAC CMAC implementation expects a valid cipher name.
        match Mac::create(&[0u8; 16], "CMAC", Some("not-a-cipher"), None) {
            Err(err) => assert!(err.to_string().starts_with("EVP_MAC_init failed")),
            Ok(_) => panic!("expected error"),
        }
    }
}
