use crate::cipher::aes::Cipher;
pub use crate::error::CryptoResult;
use crate::{cipher, ossl};
use std::sync::Mutex;

// Safety: OpenSSL EVP cipher contexts are not thread-safe for concurrent use.
// In this crate, all access goes through a Mutex (no concurrent use), and the
// object may be moved across threads by UniFFI.
unsafe impl Send for ossl::cipher::AesCipher {}

#[derive(uniffi::Object)]
pub struct AesCipher {
    inner: Mutex<cipher::aes::AesCipher>,
}

impl From<cipher::aes::AesCipher> for AesCipher {
    fn from(inner: cipher::aes::AesCipher) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }
}

#[uniffi::export]
impl AesCipher {
    fn update(&self, input: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut cipher = self.inner.lock().unwrap();
        let mut output = Vec::new();
        cipher.update(input, &mut output)?;
        Ok(output)
    }

    fn finalize(&self) -> CryptoResult<Vec<u8>> {
        let mut cipher = self.inner.lock().unwrap();
        let mut output = Vec::new();
        cipher.finalize(&mut output)?;
        Ok(output)
    }
}
