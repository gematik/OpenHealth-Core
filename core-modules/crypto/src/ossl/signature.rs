// SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
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
use crate::ossl::ec::EcPublicKey;
use crate::ossl::key::PKeyCtx;
use crypto_openssl_sys::*;

pub fn verify_ecdsa_message(
    public_key: &EcPublicKey,
    digest_name: &str,
    message: &[u8],
    signature: &[u8],
) -> OsslResult<bool> {
    let md_ctx = unsafe { EVP_MD_CTX_new() };
    if md_ctx.is_null() {
        return Err(openssl_error(OsslErrorKind::SignatureDigestCtxCreateFailed));
    }
    let digest = CString::new(digest_name)
        .map_err(|_| openssl_error(OsslErrorKind::DigestInvalidAlgorithm { algorithm: digest_name.to_string() }))?;
    let init_result = unsafe {
        EVP_DigestVerifyInit_ex(
            md_ctx,
            ptr::null_mut(),
            digest.as_ptr(),
            ptr::null_mut(),
            ptr::null(),
            public_key.as_pkey().as_mut_ptr(),
            ptr::null(),
        )
    };
    if init_result != 1 {
        unsafe { EVP_MD_CTX_free(md_ctx) };
        return Err(openssl_error(OsslErrorKind::EcdsaVerifyInitFailed));
    }

    let verify_result =
        unsafe { EVP_DigestVerify(md_ctx, signature.as_ptr(), signature.len(), message.as_ptr(), message.len()) };
    unsafe { EVP_MD_CTX_free(md_ctx) };
    match verify_result {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(openssl_error(OsslErrorKind::EcdsaVerifyFailed)),
    }
}

pub fn verify_ecdsa_digest(public_key: &EcPublicKey, digest: &[u8], signature: &[u8]) -> OsslResult<bool> {
    let raw_ctx =
        unsafe { EVP_PKEY_CTX_new_from_pkey(ptr::null_mut(), public_key.as_pkey().as_mut_ptr(), ptr::null()) };
    if raw_ctx.is_null() {
        return Err(openssl_error(OsslErrorKind::EcdsaVerifyInitFailed));
    }
    let verify_ctx = PKeyCtx(raw_ctx);

    if unsafe { EVP_PKEY_verify_init_ex(verify_ctx.as_ptr(), ptr::null()) } != 1 {
        return Err(openssl_error(OsslErrorKind::EcdsaVerifyInitFailed));
    }

    let verify_result = unsafe {
        EVP_PKEY_verify(verify_ctx.as_ptr(), signature.as_ptr(), signature.len(), digest.as_ptr(), digest.len())
    };
    match verify_result {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(openssl_error(OsslErrorKind::EcdsaVerifyFailed)),
    }
}
