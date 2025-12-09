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
use std::os::raw::c_int;
use std::ptr;

use crate::ossl::api::{openssl_error, OsslResult};
use crate::ossl::key::{PKey, PKeyCtx};
use crate::ossl_check;
use crypto_openssl_sys::point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED;
use crypto_openssl_sys::*;

pub struct EcPoint {
    group: *mut EC_GROUP,
    point: *mut EC_POINT,
}

impl EcPoint {
    pub fn create_from_curve(name: &str) -> OsslResult<Self> {
        let cstr = CString::new(name).unwrap();
        let nid = unsafe { OBJ_txt2nid(cstr.as_ptr()) };
        if nid == NID_undef {
            return Err(openssl_error(&format!("Failed to get nid for curve {name}")));
        }
        let grp = unsafe { EC_GROUP_new_by_curve_name(nid) };
        if grp.is_null() {
            return Err(openssl_error("Failed to create EC_GROUP"));
        }
        let pt = unsafe { EC_POINT_new(grp) };
        if pt.is_null() {
            unsafe { EC_GROUP_free(grp) };
            return Err(openssl_error("Failed to create EC_POINT"));
        }
        Ok(EcPoint { group: grp, point: pt })
    }

    pub fn from_public(name: &str, data: &[u8]) -> OsslResult<Self> {
        let ep = EcPoint::create_from_curve(name)?;
        ossl_check!(
            unsafe { EC_POINT_oct2point(ep.group, ep.point, data.as_ptr(), data.len(), ptr::null_mut()) as c_int },
            "Failed to create ec point from uncompressed public key"
        );
        Ok(ep)
    }

    pub fn clone(&self) -> OsslResult<Self> {
        let g2 = unsafe { EC_GROUP_dup(self.group) };
        if g2.is_null() {
            return Err(openssl_error("Failed to dup EC_GROUP"));
        }
        let p2 = unsafe { EC_POINT_dup(self.point, self.group) };
        if p2.is_null() {
            unsafe { EC_GROUP_free(g2) };
            return Err(openssl_error("Failed to dup EC_POINT"));
        }
        Ok(EcPoint { group: g2, point: p2 })
    }

    pub fn add(&self, other: &EcPoint) -> OsslResult<Self> {
        let r = self.clone()?;
        ossl_check!(
            unsafe { EC_POINT_add(self.group, r.point, self.point, other.point, ptr::null_mut(),) },
            "EC_POINT_add failed"
        );
        Ok(r)
    }

    pub fn mul(&self, scalar: &[u8]) -> OsslResult<Self> {
        let bn = unsafe { BN_signed_bin2bn(scalar.as_ptr(), scalar.len() as c_int, ptr::null_mut()) };
        if bn.is_null() {
            return Err(openssl_error("Failed to convert scalar to BIGNUM"));
        }
        let r = self.clone()?;
        ossl_check!(
            unsafe { EC_POINT_mul(self.group, r.point, ptr::null_mut(), self.point, bn, ptr::null_mut(),) },
            "EC_POINT_mul failed"
        );
        unsafe { BN_free(bn) };
        Ok(r)
    }

    pub fn to_bytes(&self) -> OsslResult<Vec<u8>> {
        let len = unsafe {
            EC_POINT_point2oct(
                self.group,
                self.point,
                POINT_CONVERSION_UNCOMPRESSED,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        };
        if len == 0 {
            return Err(openssl_error("Failed to get public key size"));
        }
        let mut buf = vec![0u8; len as usize];
        let out = unsafe {
            EC_POINT_point2oct(
                self.group,
                self.point,
                POINT_CONVERSION_UNCOMPRESSED,
                buf.as_mut_ptr(),
                len,
                ptr::null_mut(),
            )
        };
        if out == 0 {
            return Err(openssl_error("Error during ec point conversion"));
        }
        buf.truncate(out as usize);
        Ok(buf)
    }
}

impl Drop for EcPoint {
    fn drop(&mut self) {
        unsafe {
            EC_POINT_free(self.point);
            EC_GROUP_free(self.group);
        }
    }
}

/// EC keypair
pub struct EcKeypair {
    pkey: PKey,
}

impl EcKeypair {
    pub fn generate(curve: &str) -> OsslResult<Self> {
        let ctx = unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ptr::null_mut()) };
        if ctx.is_null() {
            return Err(openssl_error("Failed to create EVP_PKEY_CTX"));
        }
        let ctx = PKeyCtx(ctx);
        ossl_check!(unsafe { EVP_PKEY_keygen_init(ctx.0) }, "Failed to init keygen");
        let cs = CString::new(curve).unwrap();
        let nid = unsafe { OBJ_sn2nid(cs.as_ptr()) };
        if nid == NID_undef {
            return Err(openssl_error(&format!("Invalid curve name: {}", curve)));
        }
        ossl_check!(unsafe { EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.0, nid) }, "Failed to set EC curve");
        let mut raw: *mut EVP_PKEY = ptr::null_mut();
        ossl_check!(unsafe { EVP_PKEY_keygen(ctx.0, &mut raw) }, "Key generation failed");
        Ok(EcKeypair { pkey: PKey::new(raw) })
    }

    pub fn private_key_der(&self) -> OsslResult<Vec<u8>> {
        self.pkey.to_der_private()
    }
    pub fn public_key_der(&self) -> OsslResult<Vec<u8>> {
        self.pkey.to_der_public()
    }
}

/// ECDH context
pub struct Ecdh {
    ctx: PKeyCtx,
    _local: PKey,
}

impl Ecdh {
    pub fn new(priv_der: &[u8]) -> OsslResult<Self> {
        let p = PKey::from_der_private(priv_der)?;
        let raw = unsafe { EVP_PKEY_CTX_new(p.as_mut_ptr(), ptr::null_mut()) };
        if raw.is_null() {
            return Err(openssl_error("Failed to create ECDH context"));
        }
        let ctx = PKeyCtx(raw);
        ossl_check!(unsafe { EVP_PKEY_derive_init(ctx.0) }, "Failed to init ECDH context");
        Ok(Ecdh { ctx, _local: p })
    }

    pub fn compute_secret(&self, pub_der: &[u8]) -> OsslResult<Vec<u8>> {
        let peer = PKey::from_der_public(pub_der)?;
        ossl_check!(unsafe { EVP_PKEY_derive_set_peer(self.ctx.0, peer.as_mut_ptr()) }, "Failed to set peer");
        let mut len: usize = 0;
        ossl_check!(unsafe { EVP_PKEY_derive(self.ctx.0, ptr::null_mut(), &mut len) }, "Failed to compute secret");
        let mut secret = vec![0u8; len];
        ossl_check!(unsafe { EVP_PKEY_derive(self.ctx.0, secret.as_mut_ptr(), &mut len) }, "Failed to compute secret");
        secret.truncate(len);
        Ok(secret)
    }
}
