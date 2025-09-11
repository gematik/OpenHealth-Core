// aes.rs
use std::ffi::CString;
use std::os::raw::c_int;
use std::ptr;

use crate::ossl::api::openssl_error;
use crate::ossl::api::OsslResult;
use crate::ossl_check;

use crypto_openssl_sys::*;

pub struct AesCipher {
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *mut EVP_CIPHER,
}

impl AesCipher {
    fn new(algorithm: &str) -> OsslResult<Self> {
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        if ctx.is_null() {
            return Err(openssl_error("Failed to create cipher context"));
        }
        let alg = CString::new(algorithm).unwrap();
        let cipher = unsafe { EVP_CIPHER_fetch(ptr::null_mut(), alg.as_ptr(), ptr::null()) };
        if cipher.is_null() {
            unsafe { EVP_CIPHER_CTX_free(ctx) };
            return Err(openssl_error("Failed to fetch cipher"));
        }
        Ok(Self { ctx, cipher })
    }

    #[inline]
    pub fn is_encrypting(&self) -> bool {
        unsafe { EVP_CIPHER_CTX_is_encrypting(self.ctx) == 1 }
    }

    fn init_cipher(
        algorithm: &str,
        key: &[u8],
        iv: &[u8],
        init_fn: unsafe extern "C" fn(
            ctx: *mut EVP_CIPHER_CTX,
            cipher: *const EVP_CIPHER,
            key: *const u8,
            iv: *const u8,
            params: *const OSSL_PARAM,
        ) -> c_int,
    ) -> OsslResult<Self> {
        let aes = AesCipher::new(algorithm)?;

        ossl_check!(
            unsafe { init_fn(aes.ctx, aes.cipher, ptr::null(), ptr::null(), ptr::null()) },
            "Failed to initialize cipher"
        );

        let mode = unsafe { EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(aes.ctx)) };
        if mode == EVP_CIPH_GCM_MODE as i32 || mode == EVP_CIPH_CCM_MODE as i32 {
            let mut iv_len = iv.len();
            let mut params = [
                unsafe {
                    OSSL_PARAM_construct_size_t(
                        OSSL_CIPHER_PARAM_IVLEN.as_ptr() as *const _,
                        &mut iv_len,
                    )
                },
                unsafe { OSSL_PARAM_construct_end() },
            ];
            ossl_check!(
                unsafe { EVP_CIPHER_CTX_set_params(aes.ctx, params.as_mut_ptr()) },
                "Failed to set IV length"
            );
        } else {
            ossl_check!(
                unsafe { init_fn(aes.ctx, aes.cipher, key.as_ptr(), iv.as_ptr(), ptr::null()) },
                "Failed to initialize cipher"
            );
        }

        ossl_check!(
            unsafe { init_fn(aes.ctx, ptr::null(), key.as_ptr(), iv.as_ptr(), ptr::null()) },
            "Failed to initialize cipher"
        );

        Ok(aes)
    }

    pub fn create_encryptor(algorithm: &str, key: &[u8], iv: &[u8]) -> OsslResult<Self> {
        Self::init_cipher(algorithm, key, iv, EVP_EncryptInit_ex2)
    }

    pub fn create_decryptor(algorithm: &str, key: &[u8], iv: &[u8]) -> OsslResult<Self> {
        Self::init_cipher(algorithm, key, iv, EVP_DecryptInit_ex2)
    }

    pub fn set_auto_padding(&mut self, enabled: bool) {
        unsafe { EVP_CIPHER_CTX_set_padding(self.ctx, if enabled { 1 } else { 0 }) };
    }

    pub fn set_aad(&mut self, aad: &[u8]) -> OsslResult<()> {
        let mut out_len = 0;
        ossl_check!(
            unsafe {
                if self.is_encrypting() {
                    EVP_EncryptUpdate(
                        self.ctx,
                        ptr::null_mut(),
                        &mut out_len,
                        aad.as_ptr(),
                        aad.len() as c_int,
                    )
                } else {
                    EVP_DecryptUpdate(
                        self.ctx,
                        ptr::null_mut(),
                        &mut out_len,
                        aad.as_ptr(),
                        aad.len() as c_int,
                    )
                }
            },
            "Failed to set AAD"
        );
        Ok(())
    }

    pub fn set_auth_tag(&mut self, auth_tag: &[u8]) -> OsslResult<()> {
        if auth_tag.is_empty() {
            return Err(openssl_error("Authentication tag cannot be empty"));
        }
        let mut params = [
            unsafe {
                OSSL_PARAM_construct_octet_string(
                    OSSL_CIPHER_PARAM_AEAD_TAG.as_ptr() as *const _,
                    auth_tag.as_ptr() as *mut _,
                    auth_tag.len(),
                )
            },
            unsafe { OSSL_PARAM_construct_end() },
        ];
        ossl_check!(
            unsafe { EVP_CIPHER_CTX_set_params(self.ctx, params.as_mut_ptr()) },
            "Failed to set authentication tag"
        );
        Ok(())
    }

    pub fn get_auth_tag(&self, tag_len: usize) -> OsslResult<Vec<u8>> {
        let mut tag = vec![0u8; tag_len];
        let mut params = [
            unsafe {
                OSSL_PARAM_construct_octet_string(
                    OSSL_CIPHER_PARAM_AEAD_TAG.as_ptr() as *const i8,
                    tag.as_mut_ptr() as *mut _,
                    tag_len,
                )
            },
            unsafe { OSSL_PARAM_construct_end() },
        ];
        ossl_check!(
            unsafe { EVP_CIPHER_CTX_get_params(self.ctx, params.as_mut_ptr()) },
            "Failed to get authentication tag"
        );
        Ok(tag)
    }

    pub fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> OsslResult<usize> {
        let block_size = unsafe { EVP_CIPHER_CTX_get_block_size(self.ctx) } as usize;
        let old_output_len = output.len();
        output.resize(old_output_len + input.len() + block_size, 0);

        let mut out_len: c_int = 0;
        let rc = unsafe {
            if self.is_encrypting() {
                EVP_EncryptUpdate(
                    self.ctx,
                    output.as_mut_ptr().add(old_output_len),
                    &mut out_len,
                    input.as_ptr(),
                    input.len() as c_int,
                )
            } else {
                EVP_DecryptUpdate(
                    self.ctx,
                    output.as_mut_ptr().add(old_output_len),
                    &mut out_len,
                    input.as_ptr(),
                    input.len() as c_int,
                )
            }
        };
        if rc != 1 {
            return if self.is_encrypting() {
                Err(openssl_error("Encryption failed during update"))
            } else {
                Err(openssl_error("Decryption failed during update"))
            };
        }
        output.truncate(old_output_len + out_len as usize);
        Ok(out_len as usize)
    }

    pub fn finalize(&mut self, output: &mut Vec<u8>) -> OsslResult<usize> {
        let block_size = unsafe { EVP_CIPHER_CTX_get_block_size(self.ctx) } as usize;
        let old_output_len = output.len();
        output.resize(old_output_len + block_size, 0);

        let mut out_len: c_int = 0;
        let rc = unsafe {
            if self.is_encrypting() {
                EVP_EncryptFinal_ex(
                    self.ctx,
                    output.as_mut_ptr().add(old_output_len),
                    &mut out_len,
                )
            } else {
                EVP_DecryptFinal_ex(
                    self.ctx,
                    output.as_mut_ptr().add(old_output_len),
                    &mut out_len,
                )
            }
        };
        ossl_check!(
            rc,
            if self.is_encrypting() {
                "Encryption failed during finalization"
            } else {
                "Decryption failed during finalization"
            }
        );
        output.truncate(old_output_len + out_len as usize);
        Ok(out_len as usize)
    }

    /// Expose raw context pointer if needed by other modules
    pub fn as_ptr(&self) -> *mut EVP_CIPHER_CTX {
        self.ctx
    }
}

impl Drop for AesCipher {
    fn drop(&mut self) {
        unsafe {
            if !self.ctx.is_null() {
                EVP_CIPHER_CTX_free(self.ctx);
            }
            if !self.cipher.is_null() {
                EVP_CIPHER_free(self.cipher);
            }
        }
    }
}
