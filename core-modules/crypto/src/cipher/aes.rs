use crate::key::key::{Key, SecretKey};
use crate::ossl;
use crate::ossl::api::OsslError;
use crate::utils::byte_unit::ByteUnit;
use std::sync::{Arc, Mutex};
pub use crate::error::CryptoResult;

#[derive(Clone)]
pub struct Iv(pub Vec<u8>);

#[cfg(feature = "uniffi")]
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
pub struct Aad(pub Vec<u8>);

#[cfg(feature = "uniffi")]
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
pub struct Tag(pub Vec<u8>);
impl Tag {
    pub fn new(tag: impl Into<Vec<u8>>) -> Self {
        Self(tag.into())
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "uniffi")]
uniffi::custom_newtype!(Tag, Vec<u8>);

/// Padding switch for block modes (PKCS#7 on/off).
#[derive(Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum Padding {
    Pkcs7,
    None,
}

#[derive(Clone, uniffi::Enum)]
pub enum AesCipherSpec {
    Ecb {
        padding: Padding,
    },
    Cbc {
        iv: Iv,
        padding: Padding,
    },
    Gcm {
        iv: Iv,
        aad: Aad,
        tag_length: ByteUnit,
    },
}

impl AesCipherSpec {
    fn algorithm(&self, key_size: &ByteUnit) -> String {
        match self {
            AesCipherSpec::Ecb { .. } => format!("aes-{}-ecb", key_size.bits()),
            AesCipherSpec::Cbc { .. } => format!("aes-{}-cbc", key_size.bits()),
            AesCipherSpec::Gcm { .. } => format!("aes-{}-gcm", key_size.bits()),
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

    fn tag_length(&self) -> Option<ByteUnit> {
        match self {
            AesCipherSpec::Ecb { .. } => None,
            AesCipherSpec::Cbc { .. } => None,
            AesCipherSpec::Gcm { tag_length, .. } => Some(*tag_length),
        }
    }

    pub fn cipher(self, key: SecretKey) -> CryptoResult<AesCipher> {
        let mut cipher = ossl::cipher::AesCipher::create_encryptor(
            &*self.algorithm(&key.size()),
            key.as_ref(),
            self.iv_bytes().unwrap_or(&[]),
        )?;

        if let Some(pad) = self.auto_padding() {
            cipher.set_auto_padding(pad);
        }

        if let Some(aad) = self.aad_bytes() {
            cipher.set_aad(aad)?;
        }

        Ok(AesCipher {
            cipher: cipher,
            spec: self,
            key,
        })
    }
}

// // The native API is NOT thread-safe.
// unsafe impl Send for ossl::cipher::AesCipher {}
// unsafe impl Sync for ossl::cipher::AesCipher {}

pub struct AesCipher {
    cipher: ossl::cipher::AesCipher,
    spec: AesCipherSpec,
    key: SecretKey,
}

#[derive(Clone)]
pub enum AesDecipherSpec {
    Ecb {
        padding: Padding,
    },
    Cbc {
        iv: Iv,
        padding: Padding,
    },
    Gcm {
        iv: Iv,
        aad: Aad,
        auth_tag: Tag,
    },
}

impl AesDecipherSpec {
    fn algorithm(&self, key_size: &ByteUnit) -> String {
        match self {
            AesDecipherSpec::Ecb { .. } => format!("aes-{}-ecb", key_size.bits()),
            AesDecipherSpec::Cbc { .. } => format!("aes-{}-cbc", key_size.bits()),
            AesDecipherSpec::Gcm { .. } => format!("aes-{}-gcm", key_size.bits()),
        }
    }

    fn iv_bytes(&self) -> Option<&[u8]> {
        match self {
            AesDecipherSpec::Ecb { .. } => None,
            AesDecipherSpec::Cbc { iv, .. } => Some(iv.as_ref()),
            AesDecipherSpec::Gcm { iv, .. } => Some(iv.as_ref()),
        }
    }

    fn aad_bytes(&self) -> Option<&[u8]> {
        match self {
            AesDecipherSpec::Ecb { .. } => None,
            AesDecipherSpec::Cbc { .. } => None,
            AesDecipherSpec::Gcm { aad, .. } => Some(aad.as_ref()),
        }
    }

    fn auto_padding(&self) -> Option<bool> {
        match self {
            AesDecipherSpec::Ecb { padding, .. } => Some(*padding == Padding::Pkcs7),
            AesDecipherSpec::Cbc { padding, .. } => Some(*padding == Padding::Pkcs7),
            AesDecipherSpec::Gcm { .. } => None,
        }
    }

    fn auth_tag(&self) -> Option<&Tag> {
        match self {
            AesDecipherSpec::Ecb { .. } => None,
            AesDecipherSpec::Cbc { .. } => None,
            AesDecipherSpec::Gcm { auth_tag, .. } => Some(auth_tag),
        }
    }

    pub fn cipher(self, key: SecretKey) -> CryptoResult<AesDecipher> {
        let mut cipher = ossl::cipher::AesCipher::create_decryptor(
            &*self.algorithm(&key.size()),
            key.as_ref(),
            self.iv_bytes().unwrap_or(&[]),
        )?;

        if let Some(pad) = self.auto_padding() {
            cipher.set_auto_padding(pad);
        }

        if let Some(aad) = self.aad_bytes() {
            cipher.set_aad(aad)?;
        }

        if let Some(tag) = self.auth_tag() {
            cipher.set_auth_tag(tag.as_ref())?;
        }

        Ok(AesDecipher {
            cipher: cipher,
            spec: self,
            key,
        })
    }
}

pub struct AesDecipher {
    cipher: ossl::cipher::AesCipher,
    spec: AesDecipherSpec,
    key: SecretKey,
}

/// Streaming cipher interface (encrypt/decrypt). Caller supplies output buffer.
/// `finalize` writes any remaining bytes and returns an optional auth tag (GCM encrypt only).
pub trait Cipher {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<usize>;
    fn finalize(&mut self, output: &mut Vec<u8>) -> CryptoResult<usize>;
    fn auth_tag(&self) -> CryptoResult<Option<Tag>>;
}

impl Cipher for AesCipher {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<usize> {
        let len = self.cipher.update(input, output)?;
        Ok(len)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> CryptoResult<usize> {
        let len = self.cipher.finalize(output)?;
        Ok(len)
    }

    fn auth_tag(&self) -> CryptoResult<Option<Tag>> {
        Ok(self
            .spec
            .tag_length()
            .map(|tag_length| Tag::new(self.cipher.get_auth_tag(tag_length.bytes() as usize).unwrap())))
    }
}

impl Cipher for AesDecipher {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<usize> {
        let len = self.cipher.update(input, output)?;
        Ok(len)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> CryptoResult<usize> {
        let len = self.cipher.finalize(output)?;
        Ok(len)
    }

    fn auth_tag(&self) -> CryptoResult<Option<Tag>> {
        Ok(self.spec.auth_tag().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::key::SecretKey;

    const KEY_16: &[u8] = b"1234567890123456";
    const IV_16: &[u8] = b"1234567890123456";

    const ECB_HEX: &str = "C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1";
    const CBC_HEX: &str = "67 23 83 A2 43 37 DC 8A 35 64 A2 00 F2 1E E8 C0";

    const GCM_CT_HEX: &str = "CE C1 89 D0 E8 4D EC A8 E6 08 DD";
    const GCM_TAG_HEX: &str = "0F 98 50 42 1A DA DC FF 64 5F 7E 79 79 E2 E6 8A";

    fn key() -> SecretKey {
        SecretKey::new(KEY_16)
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

    #[test]
    fn aes_ecb_128_encrypt() {
        let mut cipher = AesCipherSpec::Ecb {
            padding: Padding::Pkcs7,
        }
            .cipher(key())
            .unwrap();

        let mut ct = Vec::new();
        let l = cipher.update(b"Hello World", &mut ct).unwrap();
        cipher.finalize(&mut ct).unwrap();

        assert_eq!(to_hex(&ct), ECB_HEX);
    }

    #[test]
    fn aes_ecb_128_decrypt() {
        let mut decipher = AesDecipherSpec::Ecb {
            padding: Padding::Pkcs7,
        }
            .cipher(key())
            .unwrap();

        let mut pt = Vec::new();
        decipher.update(&hex_to_bytes(ECB_HEX), &mut pt).unwrap();
        decipher.finalize(&mut pt).unwrap();

        assert_eq!(pt, b"Hello World");
    }

    #[test]
    fn aes_cbc_128_encrypt() {
        let mut cipher = AesCipherSpec::Cbc {
            iv: Iv::new(IV_16),
            padding: Padding::Pkcs7,
        }
            .cipher(key())
            .unwrap();

        let mut ct = Vec::new();
        cipher.update(b"Hello World", &mut ct).unwrap();
        cipher.finalize(&mut ct).unwrap();

        assert_eq!(to_hex(&ct), CBC_HEX);
    }

    #[test]
    fn aes_cbc_128_decrypt() {
        let mut decipher = AesDecipherSpec::Cbc {
            iv: Iv::new(IV_16),
            padding: Padding::Pkcs7,
        }
            .cipher(key())
            .unwrap();

        let mut pt = Vec::new();
        decipher.update(&hex_to_bytes(CBC_HEX), &mut pt).unwrap();
        decipher.finalize(&mut pt).unwrap();

        assert_eq!(pt, b"Hello World");
    }

    #[test]
    fn aes_gcm_128_encrypt() {
        let mut cipher = AesCipherSpec::Gcm {
            iv: Iv::new(IV_16),
            aad: Aad::default(),
            tag_length: ByteUnit(16),
        }
            .cipher(key())
            .unwrap();

        let mut ct = Vec::new();
        cipher.update(b"Hello World", &mut ct).unwrap();
        cipher.finalize(&mut ct).unwrap();
        let tag = cipher.auth_tag().unwrap().unwrap();

        assert_eq!(to_hex(&ct), GCM_CT_HEX);
        assert_eq!(to_hex(tag.as_ref()), GCM_TAG_HEX);
    }

    #[test]
    fn aes_gcm_128_decrypt() {
        let mut decipher = AesDecipherSpec::Gcm {
            iv: Iv::new(IV_16),
            aad: Aad::default(),
            auth_tag: Tag::new(hex_to_bytes(GCM_TAG_HEX)),
        }
            .cipher(key())
            .unwrap();

        let mut pt = Vec::new();
        decipher.update(&hex_to_bytes(GCM_CT_HEX), &mut pt).unwrap();
        decipher.finalize(&mut pt).unwrap();

        assert_eq!(pt, b"Hello World");
    }

    #[test]
    fn round_trip_gcm() {
        let msg = b"The quick brown fox";

        // Encrypt
        let mut enc = AesCipherSpec::Gcm {
            iv: Iv::new(IV_16),
            aad: Aad::new(&b"AAD"[..]),
            tag_length: ByteUnit(16),
        }
            .cipher(key())
            .unwrap();

        let mut ct = Vec::new();
        enc.update(msg, &mut ct).unwrap();
        enc.finalize(&mut ct).unwrap();
        let tag = enc.auth_tag().unwrap().unwrap();

        // Decrypt
        let mut dec = AesDecipherSpec::Gcm {
            iv: Iv::new(IV_16),
            aad: Aad::new(&b"AAD"[..]),
            auth_tag: tag,
        }
            .cipher(key())
            .unwrap();

        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).unwrap();
        dec.finalize(&mut pt).unwrap();

        assert_eq!(pt, msg);
    }
}
