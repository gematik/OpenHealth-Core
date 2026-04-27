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
use crate::ossl::key::{PKey, PKeyCtx};
use crypto_openssl_sys::*;

pub struct EcPublicKey(PKey);

impl EcPublicKey {
    pub fn from_uncompressed(curve_name: &str, public_key: &[u8]) -> OsslResult<Self> {
        let algorithm = CString::new("EC").expect("static string has no nul");
        let raw_ctx = unsafe { EVP_PKEY_CTX_new_from_name(ptr::null_mut(), algorithm.as_ptr(), ptr::null()) };
        if raw_ctx.is_null() {
            return Err(openssl_error(OsslErrorKind::EcPublicKeyImportCtxCreateFailed));
        }
        let import_ctx = PKeyCtx(raw_ctx);
        if unsafe { EVP_PKEY_fromdata_init(import_ctx.as_ptr()) } != 1 {
            return Err(openssl_error(OsslErrorKind::EcPublicKeyImportInitFailed));
        }

        let group = CString::new(curve_name).expect("curve names have no nul");
        let mut params = [
            unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_GROUP_NAME.as_ptr() as *const _,
                    group.as_ptr() as *mut _,
                    0,
                )
            },
            unsafe {
                OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_PUB_KEY.as_ptr() as *const _,
                    public_key.as_ptr() as *mut _,
                    public_key.len(),
                )
            },
            unsafe { OSSL_PARAM_construct_end() },
        ];

        let mut pkey: *mut EVP_PKEY = ptr::null_mut();
        if unsafe { EVP_PKEY_fromdata(import_ctx.as_ptr(), &mut pkey, EVP_PKEY_PUBLIC_KEY, params.as_mut_ptr()) } != 1
            || pkey.is_null()
        {
            return Err(openssl_error(OsslErrorKind::EcPublicKeyImportFailed));
        }
        Ok(Self(PKey::new(pkey)))
    }
}

pub fn verify_ecdsa(
    public_key: &EcPublicKey,
    digest_name: &str,
    message: &[u8],
    der_signature: &[u8],
) -> OsslResult<bool> {
    let md_ctx = unsafe { EVP_MD_CTX_new() };
    if md_ctx.is_null() {
        return Err(openssl_error(OsslErrorKind::SignatureDigestCtxCreateFailed));
    }
    let digest = CString::new(digest_name).expect("digest names have no nul");
    let init_result = unsafe {
        EVP_DigestVerifyInit_ex(
            md_ctx,
            ptr::null_mut(),
            digest.as_ptr(),
            ptr::null_mut(),
            ptr::null(),
            public_key.0.as_mut_ptr(),
            ptr::null(),
        )
    };
    if init_result != 1 {
        unsafe { EVP_MD_CTX_free(md_ctx) };
        return Err(openssl_error(OsslErrorKind::EcdsaVerifyInitFailed));
    }

    let verify_result = unsafe {
        EVP_DigestVerify(md_ctx, der_signature.as_ptr(), der_signature.len(), message.as_ptr(), message.len())
    };
    unsafe { EVP_MD_CTX_free(md_ctx) };
    match verify_result {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(openssl_error(OsslErrorKind::EcdsaVerifyFailed)),
    }
}
