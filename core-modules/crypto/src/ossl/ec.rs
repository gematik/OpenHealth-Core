use std::ffi::CString;
use crate::ossl::api::*;
use crate::ossl_check;
use crypto_openssl_sys::*;
use std::os::raw::{c_char, c_int};
use std::ptr;
use crypto_openssl_sys::point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED;

pub struct PKeyCtx(pub *mut EVP_PKEY_CTX);

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
    pub fn new_mem() -> OsslResult<Self> {
        let b = unsafe { BIO_new(BIO_s_mem()) };
        if b.is_null() {
            Err(openssl_error("Failed to create BIO"))
        } else {
            Ok(Bio(b))
        }
    }

    /// Create a BIO from a byte slice
    pub fn from_slice(data: &[u8]) -> OsslResult<Self> {
        let b = unsafe { BIO_new_mem_buf(data.as_ptr() as *const _, data.len() as c_int) };
        if b.is_null() {
            Err(openssl_error("Failed to create BIO from buffer"))
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
            let slice = unsafe { std::slice::from_raw_parts(ptr_data as *const u8, len as usize) };
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
pub struct PKey(pub *mut EVP_PKEY);

impl PKey {
    pub fn from_der_private(data: &[u8]) -> OsslResult<Self> {
        let bio = Bio::from_slice(data)?;
        let p = unsafe { d2i_PrivateKey_bio(bio.0, ptr::null_mut()) };
        if p.is_null() {
            Err(openssl_error("Failed to load private key from DER"))
        } else {
            Ok(PKey(p))
        }
    }

    pub fn from_der_public(data: &[u8]) -> OsslResult<Self> {
        let bio = Bio::from_slice(data)?;
        let p = unsafe { d2i_PUBKEY_bio(bio.0, ptr::null_mut()) };
        if p.is_null() {
            Err(openssl_error("Failed to load public key from DER"))
        } else {
            Ok(PKey(p))
        }
    }

    pub fn to_der_private(&self) -> OsslResult<Vec<u8>> {
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

    pub fn to_der_public(&self) -> OsslResult<Vec<u8>> {
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

/// EC point wrapper
pub struct EcPoint {
    group: *mut EC_GROUP,
    point: *mut EC_POINT,
}

impl EcPoint {
    pub fn create_from_curve(name: &str) -> OsslResult<Self> {
        let cstr = CString::new(name).unwrap();
        let nid = unsafe { OBJ_txt2nid(cstr.as_ptr()) };
        if nid == NID_undef {
            return Err(openssl_error(&format!("Failed to get nid for curve {}", name)));
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
        let mut ep = EcPoint::create_from_curve(name)?;
        ossl_check!(unsafe { EC_POINT_oct2point(ep.group, ep.point, data.as_ptr(), data.len() as usize, ptr::null_mut()) as c_int },
                    "Failed to create ec point from uncompressed public key");
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
        let mut r = self.clone()?;
        ossl_check!(unsafe { EC_POINT_add(self.group, r.point, self.point, other.point, ptr::null_mut()) },
                    "EC_POINT_add failed");
        Ok(r)
    }

    pub fn mul(&self, scalar: &[u8]) -> OsslResult<Self> {
        let bn = unsafe { BN_signed_bin2bn(scalar.as_ptr(), scalar.len() as c_int, ptr::null_mut()) };
        if bn.is_null() {
            return Err(openssl_error("Failed to convert scalar to BIGNUM"));
        }
        let mut r = self.clone()?;
        ossl_check!(unsafe { EC_POINT_mul(self.group, r.point, ptr::null_mut(), self.point, bn, ptr::null_mut()) },
                    "EC_POINT_mul failed");
        unsafe { BN_free(bn) };
        Ok(r)
    }

    pub fn to_bytes(&self) -> OsslResult<Vec<u8>> {
        let len = unsafe { EC_POINT_point2oct(self.group, self.point, POINT_CONVERSION_UNCOMPRESSED, ptr::null_mut(), 0, ptr::null_mut()) };
        if len == 0 {
            return Err(openssl_error("Failed to get public key size"));
        }
        let mut buf = vec![0u8; len as usize];
        let out = unsafe { EC_POINT_point2oct(self.group, self.point, POINT_CONVERSION_UNCOMPRESSED, buf.as_mut_ptr(), len, ptr::null_mut()) };
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
        Ok(EcKeypair { pkey: PKey(raw) })
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
        let raw = unsafe { EVP_PKEY_CTX_new(p.0, ptr::null_mut()) };
        if raw.is_null() {
            return Err(openssl_error("Failed to create ECDH context"));
        }
        let ctx = PKeyCtx(raw);
        ossl_check!(
            unsafe { EVP_PKEY_derive_init(ctx.0) },
            "Failed to init ECDH context"
        );
        Ok(Ecdh { ctx, _local: p })
    }

    pub fn compute_secret(&self, pub_der: &[u8]) -> OsslResult<Vec<u8>> {
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
