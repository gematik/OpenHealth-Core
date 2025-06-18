use std::{ffi::CString, ptr};
use crypto_openssl_sys::*;
use crate::bindings::api::{throw_openssl_error, OsslError};
use crate::ossl_check;

pub struct Cmac {
    mac: *mut EVP_MAC,
    ctx: *mut EVP_MAC_CTX,
}

impl Drop for Cmac {
    fn drop(&mut self) {
        unsafe {
            EVP_MAC_CTX_free(self.ctx);
            EVP_MAC_free(self.mac);
        }
    }
}

impl Cmac {
    /// Fetches CMAC and allocates a new context.
    pub fn new() -> Result<Self, OsslError> {
        let mac = unsafe { EVP_MAC_fetch(ptr::null_mut(), CString::new("CMAC").unwrap().as_ptr(), ptr::null_mut()) };
        if mac.is_null() {
            return Err(throw_openssl_error("EVP_MAC_fetch failed"));
        }
        let ctx = unsafe { EVP_MAC_CTX_new(mac) };
        if ctx.is_null() {
            unsafe { EVP_MAC_free(mac) };
            return Err(throw_openssl_error("EVP_MAC_CTX_new failed"));
        }
        Ok(Cmac { mac, ctx })
    }

    /// Creates and initializes a CMAC with the given key and cipher name.
    pub fn create(key: &[u8], cipher: &str) -> Result<Self, OsslError> {
        let mut cm = Self::new()?;

        let cname = CString::new("cipher").unwrap();
        let alg_c = CString::new(cipher).unwrap();
        let mut params: [OSSL_PARAM; 2] = unsafe {
            [
                OSSL_PARAM_construct_utf8_string(
                    cname.as_ptr(),
                    alg_c.as_ptr() as *mut _,
                    0,
                ),
                OSSL_PARAM_construct_end(),
            ]
        };

        ossl_check!(
            unsafe { EVP_MAC_init(cm.ctx, key.as_ptr(), key.len(), params.as_ptr()) },
            "EVP_MAC_init failed"
        );
        Ok(cm)
    }

    /// Feeds more data into the CMAC.
    pub fn update(&mut self, data: &[u8]) -> Result<(), OsslError> {
        ossl_check!(
            unsafe { EVP_MAC_update(self.ctx, data.as_ptr(), data.len()) },
            "EVP_MAC_update failed"
        );
        Ok(())
    }

    /// Finalizes and returns the MAC bytes.
    pub fn finalize(&mut self) -> Result<Vec<u8>, OsslError> {
        // first call to get output length
        let mut outl: usize = 0;
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