use std::sync::{Arc, Mutex};
use crate::ossl::api::OsslError;
use crate::key::key::{Key, SecretKey};
use crate::ossl;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CryptoError {
    #[error("cipher finalized twice")]
    FinalizedTwice,
    #[error("openssl error: {0}")]
    Native(String),
}

impl From<OsslError> for CryptoError {
    fn from(e: OsslError) -> Self {
        CryptoError::Native(e.to_string())
    }
}

pub type CryptoResult<T> = Result<T, CryptoError>;

#[derive(Clone)]
pub struct Iv(pub Vec<u8>);

uniffi::custom_newtype!(Iv, Vec<u8>);

impl Iv {
    pub fn new(iv: impl Into<Vec<u8>>) -> Self {
        Self(iv.into())
    }
}

impl AsRef<[u8]> for Iv {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Default)]
pub struct Aad(Vec<u8>);

uniffi::custom_newtype!(Aad, Vec<u8>);

impl Aad {
    pub fn new(aad: impl Into<Vec<u8>>) -> Self {
        Self(aad.into())
    }
}

impl AsRef<[u8]> for Aad {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone)]
pub struct Tag(Vec<u8>);
impl Tag {
    pub fn new(tag: impl Into<Vec<u8>>) -> Self {
        Self(tag.into())
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Padding switch for block modes (PKCS#7 on/off).
#[derive(Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum Padding {
    Pkcs7,
    None,
}

#[derive(Clone, uniffi::Enum)]
pub enum AesCipherSpec {
    Ecb { padding: Padding },
    Cbc { iv: Iv, padding: Padding },
    Gcm { iv: Iv, aad: Aad },
}

impl AesCipherSpec {
    fn algorithm(&self) -> &'static str {
        match self {
            AesCipherSpec::Ecb { .. } => "aes-128-ecb",
            AesCipherSpec::Cbc { .. } => "aes-128-cbc",
            AesCipherSpec::Gcm { .. } => "aes-128-gcm",
        }
    }

    fn iv_bytes(&self) -> Option<&[u8]> {
        match self {
            AesCipherSpec::Ecb { .. } => None,
            AesCipherSpec::Cbc { iv, .. } => Some(iv.as_ref()),
            AesCipherSpec::Gcm { iv, .. } => Some(iv.as_ref()),
        }
    }

    fn aad_bytes(&self) -> Option<&[u8]> {
        match self {
            AesCipherSpec::Ecb { .. } => None,
            AesCipherSpec::Cbc { .. } => None,
            AesCipherSpec::Gcm { aad, .. } => Some(aad.as_ref()),
        }
    }

    fn auto_padding(&self) -> Option<bool> {
        match self {
            AesCipherSpec::Ecb { padding, .. } => Some(*padding == Padding::Pkcs7),
            AesCipherSpec::Cbc { padding, .. } => Some(*padding == Padding::Pkcs7),
            AesCipherSpec::Gcm { .. } => None,
        }
    }

    pub fn cipher(self, key: SecretKey) -> CryptoResult<AesCipher> {
        let mut enc = ossl::cipher::AesCipher::create_encryptor(
            self.algorithm(),
            key.as_ref(),
            self.iv_bytes().unwrap_or(&[]),
        )?;

        if let Some(pad) = self.auto_padding() {
            enc.set_auto_padding(pad);
        }

        if let Some(aad) = self.aad_bytes() {
            enc.set_aad(aad)?;
        }

        Ok(AesCipher {
            native: Mutex::new(enc),
            spec: self,
            key,
        })
    }
}

#[uniffi::export]
pub fn cipher_from_spec(spec: AesCipherSpec, key: SecretKey) -> CryptoResult<AesCipher> {
    spec.cipher(key)
}

// // The native API is NOT thread-safe.
// unsafe impl Send for ossl::cipher::AesCipher {}
// unsafe impl Sync for ossl::cipher::AesCipher {}

pub struct AesCipher {
    native: ossl::cipher::AesCipher,
    spec: AesCipherSpec,
    key: SecretKey,
}

#[derive(Clone)]
pub enum AesDecipherSpec {
    Ecb { padding: Padding },
    Cbc { iv: Iv, padding: Padding },
    Gcm { iv: Iv, aad: Aad, tag: Tag },
}

pub struct AesDecipher {
    native: ossl::cipher::AesCipher,
    spec: AesDecipherSpec,
    key: SecretKey,
}

/// Streaming cipher interface (encrypt/decrypt). Caller supplies output buffer.
/// `finalize` writes any remaining bytes and returns an optional auth tag (GCM encrypt only).
pub trait Cipher {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<usize>;
    fn finalize(&mut self, output: &mut Vec<u8>) -> CryptoResult<usize>;
}

impl Cipher for AesCipher {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<usize> {
        let mut cipher = self.native.lock().unwrap();
        let len = cipher.update(input, output)?;
        Ok(len)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> CryptoResult<usize> {
        let mut cipher = self.native.lock().unwrap();
        let len = cipher.finalize(output)?;
        Ok(len)
    }
}

impl Cipher for AesDecipher {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<usize> {
        let mut cipher = self.native.lock().unwrap();
        let len = cipher.update(input, output)?;
        Ok(len)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> CryptoResult<usize> {
        let mut cipher = self.native.lock().unwrap();
        let len = cipher.finalize(output)?;
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::key::SecretKey;

    const KEY_16: &[u8] = b"1234567890123456";
    const IV_16: &[u8] = b"1234567890123456";

    // Test vectors you gave (ECB/CBC are implementation+padding dependent).
    const ECB_HEX: &str = "C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1";
    const CBC_HEX: &str = "67 23 83 A2 43 37 DC 8A 35 64 A2 00 F2 1E E8 C0";

    const GCM_CT_HEX: &str = "CE C1 89 D0 E8 4D EC A8 E6 08 DD";
    const GCM_TAG_HEX: &str = "0F 98 50 42 1A DA DC FF 64 5F 7E 79 79 E2 E6 8A";

    fn key() -> SecretKey {
        SecretKey(KEY_16.to_vec())
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|h| u8::from_str_radix(h, 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn run_enc(spec: AesCipherSpec, plaintext: &[u8]) -> (Vec<u8>, Option<Tag>) {
        let mut c = spec.cipher(key()).unwrap();
        let mut out = Vec::new();
        c.update(plaintext, &mut out).unwrap();
        let tag = c.finalize(&mut out).unwrap();
        (out, tag)
    }

    fn run_dec(spec: AesDecipherSpec, ciphertext: &[u8]) -> Vec<u8> {
        let mut c = native_create_decipher(&spec, &key()).unwrap();
        let mut out = Vec::new();
        c.update(ciphertext, &mut out).unwrap();
        let _ = c.finalize(&mut out).unwrap();
        out
    }

    #[test]
    fn aes_ecb_128_encrypt() {

        let (ct, _) = run_enc(
            AesCipherSpec::Ecb {
                padding: Padding::Pkcs7,
            },
            b"Hello World",
        );
        assert_eq!(to_hex(&ct), ECB_HEX);
    }

    #[test]
    fn aes_ecb_128_decrypt() {
        let pt = run_dec(
            AesDecipherSpec::Ecb {
                padding: Padding::Pkcs7,
            },
            &hex_to_bytes(ECB_HEX),
        );
        assert_eq!(pt, b"Hello World");
    }

    #[test]
    fn aes_cbc_128_encrypt() {
        let (ct, _) = run_enc(
            AesCipherSpec::Cbc {
                iv: Iv::new(IV_16),
                padding: Padding::Pkcs7,
            },
            b"Hello World",
        );
        assert_eq!(to_hex(&ct), CBC_HEX);
    }

    #[test]
    fn aes_cbc_128_decrypt() {
        let pt = run_dec(
            AesDecipherSpec::Cbc {
                iv: Iv::new(IV_16),
                padding: Padding::Pkcs7,
            },
            &hex_to_bytes(CBC_HEX),
        );
        assert_eq!(pt, b"Hello World");
    }

    #[test]
    fn aes_gcm_128_encrypt() {
        let (ct, tag) = run_enc(
            AesCipherSpec::Gcm {
                iv: Iv::new(IV_16),
                aad: Aad::default(),
            },
            b"Hello World",
        );
        assert_eq!(to_hex(&ct), GCM_CT_HEX);
        assert_eq!(to_hex(tag.as_ref().unwrap().as_slice()), GCM_TAG_HEX);
    }

    #[test]
    fn aes_gcm_128_decrypt() {
        let pt = run_dec(
            AesDecipherSpec::Gcm {
                iv: Iv::new(IV_16),
                aad: Aad::default(),
                tag: Tag::new(hex_to_bytes(GCM_TAG_HEX)),
            },
            &hex_to_bytes(GCM_CT_HEX),
        );
        assert_eq!(pt, b"Hello World");
    }

    #[test]
    fn round_trip_gcm() {
        let msg = b"The quick brown fox";
        let (ct, tag) = run_enc(
            AesCipherSpec::Gcm {
                iv: Iv::new(IV_16),
                aad: Aad::new(&b"AAD"[..]),
            },
            msg,
        );
        let pt = run_dec(
            AesDecipherSpec::Gcm {
                iv: Iv::new(IV_16),
                aad: Aad::new(&b"AAD"[..]),
                tag: tag.unwrap(),
            },
            &ct,
        );
        assert_eq!(pt, msg);
    }
}
