use std::{ffi::CString, ptr};

use crate::ossl::api::{openssl_error, OsslResult};
use crate::ossl_check;
use crypto_openssl_sys::*;

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
        let mac = unsafe { EVP_MAC_fetch(ptr::null_mut(), cname.as_ptr(), ptr::null_mut()) };
        if mac.is_null() {
            return Err(openssl_error("EVP_MAC_fetch failed"));
        }
        let ctx = unsafe { EVP_MAC_CTX_new(mac) };
        if ctx.is_null() {
            unsafe { EVP_MAC_free(mac) };
            return Err(openssl_error("EVP_MAC_CTX_new failed"));
        }
        Ok(Mac { mac, ctx })
    }

    /// Creates and initializes a MAC with the given key and cipher name.
    pub fn create(
        key: &[u8],
        name: &str,
        cipher: Option<&str>,
        digest: Option<&str>,
    ) -> OsslResult<Self> {
        let cm = Self::new(name)?;

        // Hold CStrings so their memory outlives EVP_MAC_init
        let name_cipher = CString::new("cipher").unwrap();
        let name_digest = CString::new("digest").unwrap();
        let val_cipher = cipher.map(|c| CString::new(c).unwrap());
        let val_digest = digest.map(|d| CString::new(d).unwrap());

        let mut params = Vec::with_capacity(3);

        if let Some(val_cipher) = &val_cipher {
            params.push(unsafe {
                OSSL_PARAM_construct_utf8_string(
                    name_cipher.as_ptr(),
                    val_cipher.as_ptr() as *mut _,
                    0,
                )
            });
        }

        if let Some(val_digest) = &val_digest {
            params.push(unsafe {
                OSSL_PARAM_construct_utf8_string(
                    name_digest.as_ptr(),
                    val_digest.as_ptr() as *mut _,
                    0,
                )
            });
        }

        params.push(unsafe { OSSL_PARAM_construct_end() });

        ossl_check!(
            unsafe { EVP_MAC_init(cm.ctx, key.as_ptr(), key.len(), params.as_ptr()) },
            "EVP_MAC_init failed"
        );
        Ok(cm)
    }

    /// Feeds more data into the MAC.
    pub fn update(&mut self, input: &[u8]) -> OsslResult<()> {
        ossl_check!(
            unsafe { EVP_MAC_update(self.ctx, input.as_ptr(), input.len()) },
            "EVP_MAC_update failed"
        );
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
