use crate::ossl::api::*;
use crate::{ossl_check, ossl_require};
use crypto_openssl_sys::*;
use std::ffi::CString;
use std::ptr;

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
        ossl_require!(
            !md.is_null(),
            &format!("Invalid hash algorithm: {algorithm}")
        );
        let ctx = unsafe { EVP_MD_CTX_new() };
        if ctx.is_null() {
            unsafe { EVP_MD_free(md) };
            return Err(openssl_error("Failed to create EVP_MD_CTX"));
        }

        let init_res = unsafe { EVP_DigestInit_ex(ctx, md, ptr::null_mut()) };
        unsafe { EVP_MD_free(md) };
        ossl_check!(
            init_res,
            "Failed to initialize digest"
        );

        Ok(Digest {
            ctx,
        })
    }

    /// Feeds more data into the digest.
    pub fn update(&mut self, input: &[u8]) -> OsslResult<()> {
        ossl_check!(
            unsafe { EVP_DigestUpdate(self.ctx, input.as_ptr() as *const _, input.len() as usize) },
            "Failed to update digest"
        );
        Ok(())
    }

    /// Finalizes and returns the digest bytes.
    pub fn finalize(&mut self, output_length: usize) -> OsslResult<Vec<u8>> {
        let md = unsafe { EVP_MD_CTX_md(self.ctx) };
        let flags = unsafe { EVP_MD_get_flags(md) };
        if flags & EVP_MD_FLAG_XOF as u64 != 0 {
            let mut out = vec![0u8; output_length];
            ossl_check!(
                unsafe {
                    EVP_DigestFinalXOF(self.ctx, out.as_mut_ptr() as *mut _, output_length)
                },
                "Failed to finalize XOF digest"
            );
            return Ok(out);
        }

        let mut len = unsafe { EVP_MD_get_size(md) } as u32;
        let mut out = vec![0u8; len as usize];
        ossl_check!(
            unsafe { EVP_DigestFinal_ex(self.ctx, out.as_mut_ptr(), &mut len) },
            "Failed to finalize digest"
        );
        out.truncate(len as usize);
        Ok(out)
    }
}
