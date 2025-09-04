use std::ffi::CString;
use std::os::raw::c_int;
use std::ptr;
use crypto_openssl_sys::*;
use crate::ossl::api::*;
use crate::ossl_check;

pub struct HashGenerator {
    md: *mut EVP_MD,
    ctx: *mut EVP_MD_CTX,
    output_length: usize,
}

impl Drop for HashGenerator {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_free(self.ctx);
            EVP_MD_free(self.md);
        }
    }
}

impl HashGenerator {
    /// Fetches the digest algorithm and allocates a new context.
    pub fn new(hash_name: &str) -> OsslResult<Self> {
        let cname = CString::new(hash_name).unwrap();
        let md = unsafe {
            // OpenSSL 3 style fetch
            EVP_MD_fetch(ptr::null_mut(), cname.as_ptr(), ptr::null_mut())
        };
        if md.is_null() {
            return Err(openssl_error(
                &format!("Invalid hash algorithm: {}", hash_name)
            ));
        }
        let ctx = unsafe { EVP_MD_CTX_new() };
        if ctx.is_null() {
            unsafe { EVP_MD_free(md) };
            return Err(openssl_error("Failed to create EVP_MD_CTX"));
        }
        Ok(HashGenerator { md, ctx, output_length: 0 })
    }

    /// Convenience constructor that also calls DigestInit.
    pub fn create(hash_name: &str) -> OsslResult<Self> {
        let mut this = Self::new(hash_name)?;
        ossl_check!(
            unsafe { EVP_DigestInit_ex(this.ctx, this.md, ptr::null_mut()) },
            "Failed to initialize digest"
        );
        Ok(this)
    }

    /// Feeds more data into the digest.
    pub fn update(&mut self, data: &[u8]) -> OsslResult<()> {
        ossl_check!(
            unsafe { EVP_DigestUpdate(self.ctx, data.as_ptr() as *const _, data.len() as usize) },
            "Failed to update digest"
        );
        Ok(())
    }

    /// For XOF (eXtendable-Output Functions) you must specify an output length.
    /// For fixed-length hashes you may only ever request the one true size.
    pub fn set_final_output_length(&mut self, length: usize) {
        let flags = unsafe { EVP_MD_get_flags(self.md) };
        if flags & EVP_MD_FLAG_XOF as u64 != 0 {
            if length == 0 {
                panic!("Output length must be specified for XOF hashes");
            }
            self.output_length = length;
        } else {
            let fixed = unsafe { EVP_MD_get_size(self.md) } as usize;
            if length != 0 && length != fixed {
                panic!("Fixed-length hash does not support variable output size");
            }
        }
    }

    /// Finalizes and returns the digest bytes.
    pub fn finalize(&self) -> OsslResult<Vec<u8>> {
        let flags = unsafe { EVP_MD_get_flags(self.md) };
        if flags & EVP_MD_FLAG_XOF as u64 != 0 {
            let mut out = vec![0u8; self.output_length];
            ossl_check!(
                unsafe { EVP_DigestFinalXOF(self.ctx, out.as_mut_ptr() as *mut _, self.output_length) },
                "Failed to finalize XOF digest"
            );
            return Ok(out);
        }

        let mut len = unsafe { EVP_MD_get_size(self.md) } as u32;
        let mut out = vec![0u8; len as usize];
        ossl_check!(
            unsafe { EVP_DigestFinal_ex(self.ctx, out.as_mut_ptr(), &mut len) },
            "Failed to finalize digest"
        );
        out.truncate(len as usize);
        Ok(out)
    }
}