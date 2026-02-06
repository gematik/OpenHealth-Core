// SPDX-FileCopyrightText: Copyright 2025 - 2026 gematik GmbH
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

use crate::ossl::api::{openssl_error, OsslErrorKind, OsslResult};
use crate::{ossl_check, ossl_require};
use crypto_openssl_sys::*;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static FORCE_MD_CTX_NULL: Cell<bool> = const { Cell::new(false) };
}

#[inline]
fn md_ctx_new() -> *mut EVP_MD_CTX {
    #[cfg(test)]
    {
        if FORCE_MD_CTX_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EVP_MD_CTX_new() }
}

/// RAII wrapper around `EVP_MD_CTX` for hashing operations.
pub struct Digest {
    ctx: *mut EVP_MD_CTX,
}

impl Drop for Digest {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_free(self.ctx);
        }
    }
}

impl Digest {
    pub fn create(algorithm: &str) -> OsslResult<Self> {
        let cname = CString::new(algorithm).unwrap();
        let md = unsafe { EVP_MD_fetch(ptr::null_mut(), cname.as_ptr(), ptr::null_mut()) };
        ossl_require!(!md.is_null(), OsslErrorKind::DigestInvalidAlgorithm { algorithm: algorithm.to_string() });
        let ctx = md_ctx_new();
        if ctx.is_null() {
            unsafe { EVP_MD_free(md) };
            return Err(openssl_error(OsslErrorKind::DigestCtxCreateFailed));
        }

        let init_res = unsafe { EVP_DigestInit_ex(ctx, md, ptr::null_mut()) };
        unsafe { EVP_MD_free(md) };
        ossl_check!(init_res, OsslErrorKind::DigestInitFailed);

        Ok(Self { ctx })
    }

    /// Feeds more data into the digest.
    pub fn update(&mut self, input: &[u8]) -> OsslResult<()> {
        ossl_check!(
            unsafe { EVP_DigestUpdate(self.ctx, input.as_ptr() as *const _, input.len()) },
            OsslErrorKind::DigestUpdateFailed
        );
        Ok(())
    }

    /// Finalizes and returns the digest bytes.
    pub fn finalize(&mut self, output_length: usize) -> OsslResult<Vec<u8>> {
        let md = unsafe { EVP_MD_CTX_md(self.ctx) };
        let flags = unsafe { EVP_MD_get_flags(md) };
        if flags & (EVP_MD_FLAG_XOF as std::os::raw::c_ulong) != 0 {
            let mut out = vec![0u8; output_length];
            ossl_check!(
                unsafe { EVP_DigestFinalXOF(self.ctx, out.as_mut_ptr() as *mut _, output_length) },
                OsslErrorKind::DigestFinalizeXofFailed
            );
            return Ok(out);
        }

        let mut len = unsafe { EVP_MD_get_size(md) } as u32;
        let mut out = vec![0u8; len as usize];
        ossl_check!(
            unsafe { EVP_DigestFinal_ex(self.ctx, out.as_mut_ptr(), &mut len) },
            OsslErrorKind::DigestFinalizeFailed
        );
        out.truncate(len as usize);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ossl::api::with_thread_local_cell;

    #[test]
    fn create_fails_when_ctx_null() {
        let err = with_thread_local_cell(&FORCE_MD_CTX_NULL, true, || Digest::create("sha256"))
            .err()
            .expect("expected error");
        assert_eq!(err.kind(), &OsslErrorKind::DigestCtxCreateFailed);
    }
}
