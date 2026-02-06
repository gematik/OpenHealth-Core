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

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static FORCE_GROUP_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_POINT_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_GROUP_DUP_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_POINT_DUP_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_BN_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_POINT2OCT_LEN_ZERO: Cell<bool> = const { Cell::new(false) };
    static FORCE_POINT2OCT_OUT_ZERO: Cell<bool> = const { Cell::new(false) };
    static FORCE_PKEY_CTX_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_ECDH_CTX_NULL: Cell<bool> = const { Cell::new(false) };
}

#[inline]
fn ec_group_new(nid: c_int) -> *mut EC_GROUP {
    #[cfg(test)]
    {
        if FORCE_GROUP_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EC_GROUP_new_by_curve_name(nid) }
}

#[inline]
fn ec_point_new(group: *mut EC_GROUP) -> *mut EC_POINT {
    #[cfg(test)]
    {
        if FORCE_POINT_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EC_POINT_new(group) }
}

#[inline]
fn ec_group_dup(group: *mut EC_GROUP) -> *mut EC_GROUP {
    #[cfg(test)]
    {
        if FORCE_GROUP_DUP_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EC_GROUP_dup(group) }
}

#[inline]
fn ec_point_dup(point: *mut EC_POINT, group: *mut EC_GROUP) -> *mut EC_POINT {
    #[cfg(test)]
    {
        if FORCE_POINT_DUP_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EC_POINT_dup(point, group) }
}

#[inline]
fn bn_signed_bin2bn(data: *const u8, len: c_int) -> *mut BIGNUM {
    #[cfg(test)]
    {
        if FORCE_BN_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { BN_signed_bin2bn(data, len, ptr::null_mut()) }
}

#[inline]
fn ec_point2oct(
    group: *const EC_GROUP,
    point: *const EC_POINT,
    form: point_conversion_form_t,
    buf: *mut u8,
    len: usize,
    ctx: *mut BN_CTX,
) -> usize {
    #[cfg(test)]
    {
        if buf.is_null() && FORCE_POINT2OCT_LEN_ZERO.with(|flag| flag.get()) {
            return 0;
        }
        if !buf.is_null() && FORCE_POINT2OCT_OUT_ZERO.with(|flag| flag.get()) {
            return 0;
        }
    }
    unsafe { EC_POINT_point2oct(group, point, form, buf, len, ctx) }
}

#[inline]
fn pkey_ctx_new_id(id: c_int) -> *mut EVP_PKEY_CTX {
    #[cfg(test)]
    {
        if FORCE_PKEY_CTX_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EVP_PKEY_CTX_new_id(id, ptr::null_mut()) }
}

#[inline]
fn pkey_ctx_new(pkey: *mut EVP_PKEY) -> *mut EVP_PKEY_CTX {
    #[cfg(test)]
    {
        if FORCE_ECDH_CTX_NULL.with(|flag| flag.get()) {
            return ptr::null_mut();
        }
    }
    unsafe { EVP_PKEY_CTX_new(pkey, ptr::null_mut()) }
}

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
        let grp = ec_group_new(nid);
        if grp.is_null() {
            return Err(openssl_error("Failed to create EC_GROUP"));
        }
        let pt = ec_point_new(grp);
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
        let g2 = ec_group_dup(self.group);
        if g2.is_null() {
            return Err(openssl_error("Failed to dup EC_GROUP"));
        }
        let p2 = ec_point_dup(self.point, self.group);
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
        let bn = bn_signed_bin2bn(scalar.as_ptr(), scalar.len() as c_int);
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
        let len =
            ec_point2oct(self.group, self.point, POINT_CONVERSION_UNCOMPRESSED, ptr::null_mut(), 0, ptr::null_mut());
        if len == 0 {
            return Err(openssl_error("Failed to get public key size"));
        }
        let mut buf = vec![0u8; len];
        let out =
            ec_point2oct(self.group, self.point, POINT_CONVERSION_UNCOMPRESSED, buf.as_mut_ptr(), len, ptr::null_mut());
        if out == 0 {
            return Err(openssl_error("Error during ec point conversion"));
        }
        buf.truncate(out);
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
        let ctx = pkey_ctx_new_id(EVP_PKEY_EC);
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
        let raw = pkey_ctx_new(p.as_mut_ptr());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ossl::api::with_thread_local_cell;
    use hex::decode;

    #[test]
    fn create_from_curve_rejects_invalid_name() {
        match EcPoint::create_from_curve("invalid-curve") {
            Err(err) => assert!(err.to_string().contains("Failed to get nid")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn keypair_generate_rejects_invalid_curve() {
        match EcKeypair::generate("invalid-curve") {
            Err(err) => assert!(err.to_string().contains("Invalid curve name")),
            Ok(_) => panic!("expected error"),
        }
    }

    fn prime256v1_point() -> EcPoint {
        let bytes = prime256v1_bytes();
        EcPoint::from_public("prime256v1", &bytes).unwrap()
    }

    fn prime256v1_bytes() -> Vec<u8> {
        decode(
            "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296\
             4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        )
        .unwrap()
    }

    #[test]
    fn create_from_curve_fails_when_group_null() {
        let res = with_thread_local_cell(&FORCE_GROUP_NULL, true, || EcPoint::create_from_curve("prime256v1"));
        match res {
            Err(err) => assert!(err.to_string().contains("Failed to create EC_GROUP")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn create_from_curve_fails_when_point_null() {
        let res = with_thread_local_cell(&FORCE_POINT_NULL, true, || EcPoint::create_from_curve("prime256v1"));
        match res {
            Err(err) => assert!(err.to_string().contains("Failed to create EC_POINT")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn clone_fails_when_group_dup_null() {
        let point = prime256v1_point();
        let res = with_thread_local_cell(&FORCE_GROUP_DUP_NULL, true, || point.clone());
        match res {
            Err(err) => assert!(err.to_string().contains("Failed to dup EC_GROUP")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn clone_fails_when_point_dup_null() {
        let point = prime256v1_point();
        let res = with_thread_local_cell(&FORCE_POINT_DUP_NULL, true, || point.clone());
        match res {
            Err(err) => assert!(err.to_string().contains("Failed to dup EC_POINT")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn mul_fails_when_bn_null() {
        let point = prime256v1_point();
        let res = with_thread_local_cell(&FORCE_BN_NULL, true, || point.mul(&[0x01]));
        match res {
            Err(err) => assert!(err.to_string().contains("Failed to convert scalar")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn to_bytes_fails_when_len_zero() {
        let point = prime256v1_point();
        let res = with_thread_local_cell(&FORCE_POINT2OCT_LEN_ZERO, true, || point.to_bytes());
        match res {
            Err(err) => assert!(err.to_string().contains("Failed to get public key size")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn to_bytes_fails_when_output_zero() {
        let point = prime256v1_point();
        let res = with_thread_local_cell(&FORCE_POINT2OCT_OUT_ZERO, true, || point.to_bytes());
        match res {
            Err(err) => assert!(err.to_string().contains("Error during ec point conversion")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn keypair_generate_fails_when_ctx_null() {
        let res = with_thread_local_cell(&FORCE_PKEY_CTX_NULL, true, || EcKeypair::generate("prime256v1"));
        match res {
            Err(err) => assert!(err.to_string().contains("Failed to create EVP_PKEY_CTX")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn ecdh_new_fails_when_ctx_null() {
        let keypair = EcKeypair::generate("prime256v1").unwrap();
        let priv_der = keypair.private_key_der().unwrap();
        let res = with_thread_local_cell(&FORCE_ECDH_CTX_NULL, true, || Ecdh::new(&priv_der));
        match res {
            Err(err) => assert!(err.to_string().contains("Failed to create ECDH context")),
            Ok(_) => panic!("expected error"),
        }
    }
}
