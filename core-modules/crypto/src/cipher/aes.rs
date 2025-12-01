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

use crate::error::CryptoError;
use crate::ossl;
use crate::utils::byte_unit::{ByteUnit, BytesExt};

pub use crate::error::CryptoResult;
use crate::key::SecretKey;

/// 16-byte IV for CBC mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbcIv {
    bytes: [u8; 16],
}

impl CbcIv {
    pub fn new(iv: [u8; 16]) -> Self {
        Self { bytes: iv }
    }

    pub fn from_slice(iv: impl AsRef<[u8]>) -> CryptoResult<Self> {
        let iv = iv.as_ref();
        if iv.len() != 16 {
            return Err(CryptoError::InvalidIvLength { mode: "CBC", expected: &[16], actual: iv.len() });
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(iv);
        Ok(Self { bytes })
    }
}

pub type Iv = CbcIv;

impl AsRef<[u8]> for CbcIv {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Nonce/IV for AES-GCM (12 or 16 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcmNonce {
    bytes: Vec<u8>,
}

impl GcmNonce {
    pub fn new(iv: impl Into<Vec<u8>>) -> CryptoResult<Self> {
        let iv = iv.into();
        match iv.len() {
            12 | 16 => Ok(Self { bytes: iv }),
            other => Err(CryptoError::InvalidIvLength { mode: "GCM", expected: &[12, 16], actual: other }),
        }
    }
}

impl AsRef<[u8]> for GcmNonce {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Additional authenticated data for AEAD ciphers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Aad {
    bytes: Vec<u8>,
}

// #[cfg(feature = "uniffi")]
// uniffi::custom_newtype!(Aad, Vec<u8>);

impl Aad {
    pub fn new(aad: impl Into<Vec<u8>>) -> CryptoResult<Self> {
        Ok(Self { bytes: aad.into() })
    }
}

impl AsRef<[u8]> for Aad {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Authentication tag produced or consumed by GCM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AeadTag {
    bytes: Vec<u8>,
}

impl AeadTag {
    pub fn new(tag: impl Into<Vec<u8>>) -> CryptoResult<Self> {
        let tag = tag.into();
        if !(12..=16).contains(&tag.len()) {
            return Err(CryptoError::InvalidTagLength { expected_min: 12, expected_max: 16, actual: tag.len() });
        }
        Ok(Self { bytes: tag })
    }
}

impl AsRef<[u8]> for AeadTag {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Padding switch for block modes (PKCS#7 on/off).
#[derive(Copy, Clone, Eq, PartialEq)]
// #[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum Padding {
    Pkcs7,
    None,
}

/// Specification for AES encryption.
///
/// - `Ecb`/`Cbc` support optional PKCS#7 padding.
/// - `Gcm` is an AEAD mode requiring an IV (nonce), optional AAD, and a tag length (12–16 bytes).
#[derive(Clone)]
pub enum AesCipherSpec {
    Ecb { padding: Padding },
    Cbc { iv: CbcIv, padding: Padding },
    Gcm { iv: GcmNonce, aad: Aad, tag_length: ByteUnit },
}

impl AesCipherSpec {
    pub fn ecb(padding: Padding) -> Self {
        Self::Ecb { padding }
    }

    pub fn cbc(iv: [u8; 16], padding: Padding) -> Self {
        Self::Cbc { iv: CbcIv::new(iv), padding }
    }

    pub fn gcm(iv: impl Into<Vec<u8>>, aad: impl Into<Vec<u8>>) -> CryptoResult<Self> {
        Self::gcm_with_tag(iv, aad, 16.bytes())
    }

    pub fn gcm_with_tag(iv: impl Into<Vec<u8>>, aad: impl Into<Vec<u8>>, tag_length: ByteUnit) -> CryptoResult<Self> {
        Ok(Self::Gcm { iv: GcmNonce::new(iv)?, aad: Aad::new(aad)?, tag_length })
    }

    fn validate_params(&self, key: &SecretKey) -> CryptoResult<()> {
        const VALID_KEY_SIZES: [usize; 3] = [16, 24, 32];
        match key.len() {
            16 | 24 | 32 => Ok(()),
            other => Err(CryptoError::InvalidKeyLength { expected: &VALID_KEY_SIZES, actual: other }),
        }?;

        if let AesCipherSpec::Gcm { tag_length, .. } = self {
            let tag_len = tag_length.bytes() as usize;
            if !(12..=16).contains(&tag_len) {
                return Err(CryptoError::InvalidTagLength { expected_min: 12, expected_max: 16, actual: tag_len });
            }
        }
        Ok(())
    }

    fn algorithm(&self, key_size: &ByteUnit) -> String {
        match self {
            Self::Ecb { .. } => format!("aes-{}-ecb", key_size.bits()),
            Self::Cbc { .. } => format!("aes-{}-cbc", key_size.bits()),
            Self::Gcm { .. } => format!("aes-{}-gcm", key_size.bits()),
        }
    }

    fn iv_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Ecb { .. } => None,
            Self::Cbc { iv, .. } => Some(iv.as_ref()),
            Self::Gcm { iv, .. } => Some(iv.as_ref()),
        }
    }

    fn aad_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Ecb { .. } | Self::Cbc { .. } => None,
            Self::Gcm { aad, .. } => Some(aad.as_ref()),
        }
    }

    fn auto_padding(&self) -> Option<bool> {
        match self {
            Self::Ecb { padding, .. } | Self::Cbc { padding, .. } => Some(*padding == Padding::Pkcs7),
            Self::Gcm { .. } => None,
        }
    }

    /// Create an encryptor for the given key and spec.
    pub fn cipher(self, key: SecretKey) -> CryptoResult<AesCipher> {
        self.validate_params(&key)?;
        let algorithm = self.algorithm(&key.size());
        let mut cipher =
            ossl::cipher::AesCipher::create_encryptor(&algorithm, key.as_ref(), self.iv_bytes().unwrap_or(&[]))?;

        if let Some(padding_enabled) = self.auto_padding() {
            cipher.set_auto_padding(padding_enabled);
        }

        if let Some(aad) = self.aad_bytes() {
            cipher.set_aad(aad)?;
        }

        Ok(AesCipher { cipher, spec: self, key })
    }
}

/// Streaming AES encryptor.
///
/// - Feed plaintext via `update` and finalize with `finalize`.
/// - For GCM, retrieve the authentication tag via `Cipher::auth_tag()`.
pub struct AesCipher {
    cipher: ossl::cipher::AesCipher,
    spec: AesCipherSpec,
    key: SecretKey,
}

/// Specification for AES decryption.
#[derive(Clone)]
pub enum AesDecipherSpec {
    Ecb { padding: Padding },
    Cbc { iv: CbcIv, padding: Padding },
    Gcm { iv: GcmNonce, aad: Aad, auth_tag: AeadTag },
}

impl AesDecipherSpec {
    pub fn ecb(padding: Padding) -> Self {
        Self::Ecb { padding }
    }

    pub fn cbc(iv: [u8; 16], padding: Padding) -> Self {
        Self::Cbc { iv: CbcIv::new(iv), padding }
    }

    pub fn gcm(iv: impl Into<Vec<u8>>, aad: impl Into<Vec<u8>>, auth_tag: AeadTag) -> CryptoResult<Self> {
        Ok(Self::Gcm { iv: GcmNonce::new(iv)?, aad: Aad::new(aad)?, auth_tag })
    }

    fn validate_params(&self, key: &SecretKey) -> CryptoResult<()> {
        const VALID_KEY_SIZES: [usize; 3] = [16, 24, 32];
        match key.len() {
            16 | 24 | 32 => Ok(()),
            other => Err(CryptoError::InvalidKeyLength { expected: &VALID_KEY_SIZES, actual: other }),
        }
    }

    fn algorithm(&self, key_size: &ByteUnit) -> String {
        match self {
            Self::Ecb { .. } => format!("aes-{}-ecb", key_size.bits()),
            Self::Cbc { .. } => format!("aes-{}-cbc", key_size.bits()),
            Self::Gcm { .. } => format!("aes-{}-gcm", key_size.bits()),
        }
    }

    fn iv_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Ecb { .. } => None,
            Self::Cbc { iv, .. } => Some(iv.as_ref()),
            Self::Gcm { iv, .. } => Some(iv.as_ref()),
        }
    }

    fn aad_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Ecb { .. } | Self::Cbc { .. } => None,
            Self::Gcm { aad, .. } => Some(aad.as_ref()),
        }
    }

    fn auto_padding(&self) -> Option<bool> {
        match self {
            Self::Ecb { padding, .. } | Self::Cbc { padding, .. } => Some(*padding == Padding::Pkcs7),
            Self::Gcm { .. } => None,
        }
    }

    fn auth_tag(&self) -> Option<&AeadTag> {
        match self {
            Self::Ecb { .. } | Self::Cbc { .. } => None,
            Self::Gcm { auth_tag, .. } => Some(auth_tag),
        }
    }

    /// Create a decryptor for the given key and spec.
    pub fn cipher(self, key: SecretKey) -> CryptoResult<AesDecipher> {
        self.validate_params(&key)?;
        let algorithm = self.algorithm(&key.size());
        let mut cipher =
            ossl::cipher::AesCipher::create_decryptor(&algorithm, key.as_ref(), self.iv_bytes().unwrap_or(&[]))?;

        if let Some(padding_enabled) = self.auto_padding() {
            cipher.set_auto_padding(padding_enabled);
        }

        if let Some(aad) = self.aad_bytes() {
            cipher.set_aad(aad)?;
        }

        if let Some(tag) = self.auth_tag() {
            cipher.set_auth_tag(tag.as_ref())?;
        }

        Ok(AesDecipher { cipher, spec: self, key })
    }
}

/// Streaming AES decryptor.
///
/// Feed ciphertext via `update`, then call `finalize`.
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
    fn auth_tag(&self) -> CryptoResult<Option<AeadTag>>;
}

impl Cipher for AesCipher {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<usize> {
        self.cipher.update(input, output).map_err(Into::into)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> CryptoResult<usize> {
        self.cipher.finalize(output).map_err(Into::into)
    }

    fn auth_tag(&self) -> CryptoResult<Option<AeadTag>> {
        match self.spec {
            AesCipherSpec::Gcm { ref tag_length, .. } => {
                let len = tag_length.bytes() as usize;
                AeadTag::new(self.cipher.get_auth_tag(len)?).map(Some)
            }
            _ => Ok(None),
        }
    }
}

impl Cipher for AesDecipher {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<usize> {
        self.cipher.update(input, output).map_err(Into::into)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> CryptoResult<usize> {
        self.cipher.finalize(output).map_err(Into::into)
    }

    fn auth_tag(&self) -> CryptoResult<Option<AeadTag>> {
        Ok(self.spec.auth_tag().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::SecretKey;
    use crate::utils::byte_unit::BytesExt;
    use crate::utils::test_utils::{hex_to_bytes, to_hex_string};
    use std::convert::TryInto;

    const KEY_16: &[u8] = b"1234567890123456";
    const IV_16: &[u8] = b"1234567890123456";

    const ECB_HEX: &str = "C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1";
    const CBC_HEX: &str = "67 23 83 A2 43 37 DC 8A 35 64 A2 00 F2 1E E8 C0";

    const GCM_CT_HEX: &str = "CE C1 89 D0 E8 4D EC A8 E6 08 DD";
    const GCM_TAG_HEX: &str = "0F 98 50 42 1A DA DC FF 64 5F 7E 79 79 E2 E6 8A";

    fn key() -> SecretKey {
        SecretKey::new_secret(KEY_16)
    }

    #[test]
    fn aes_ecb_128_encrypt() {
        let mut cipher = AesCipherSpec::Ecb { padding: Padding::Pkcs7 }.cipher(key()).unwrap();

        let mut ct = Vec::new();
        let l = cipher.update(b"Hello World", &mut ct).unwrap();
        cipher.finalize(&mut ct).unwrap();

        assert_eq!(to_hex_string(&ct), ECB_HEX);
    }

    #[test]
    fn aes_ecb_128_decrypt() {
        let mut decipher = AesDecipherSpec::Ecb { padding: Padding::Pkcs7 }.cipher(key()).unwrap();

        let mut pt = Vec::new();
        decipher.update(&hex_to_bytes(ECB_HEX), &mut pt).unwrap();
        decipher.finalize(&mut pt).unwrap();

        assert_eq!(pt, b"Hello World");
    }

    #[test]
    fn aes_cbc_128_encrypt() {
        let iv_bytes: [u8; 16] = IV_16.try_into().unwrap();
        let mut cipher =
            AesCipherSpec::Cbc { iv: CbcIv::new(iv_bytes), padding: Padding::Pkcs7 }.cipher(key()).unwrap();

        let mut ct = Vec::new();
        cipher.update(b"Hello World", &mut ct).unwrap();
        cipher.finalize(&mut ct).unwrap();

        assert_eq!(to_hex_string(&ct), CBC_HEX);
    }

    #[test]
    fn aes_cbc_128_decrypt() {
        let iv_bytes: [u8; 16] = IV_16.try_into().unwrap();
        let mut decipher =
            AesDecipherSpec::Cbc { iv: CbcIv::new(iv_bytes), padding: Padding::Pkcs7 }.cipher(key()).unwrap();

        let mut pt = Vec::new();
        decipher.update(&hex_to_bytes(CBC_HEX), &mut pt).unwrap();
        decipher.finalize(&mut pt).unwrap();

        assert_eq!(pt, b"Hello World");
    }

    #[test]
    fn aes_gcm_128_encrypt() {
        let mut cipher =
            AesCipherSpec::Gcm { iv: GcmNonce::new(IV_16).unwrap(), aad: Aad::default(), tag_length: 16.bytes() }
                .cipher(key())
                .unwrap();

        let mut ct = Vec::new();
        cipher.update(b"Hello World", &mut ct).unwrap();
        cipher.finalize(&mut ct).unwrap();
        let tag = cipher.auth_tag().unwrap().unwrap();

        assert_eq!(to_hex_string(&ct), GCM_CT_HEX);
        assert_eq!(to_hex_string(tag.as_ref()), GCM_TAG_HEX);
    }

    #[test]
    fn aes_gcm_128_decrypt() {
        let mut decipher = AesDecipherSpec::Gcm {
            iv: GcmNonce::new(IV_16).unwrap(),
            aad: Aad::default(),
            auth_tag: AeadTag::new(hex_to_bytes(GCM_TAG_HEX)).unwrap(),
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
        let mut enc =
            AesCipherSpec::Gcm { iv: GcmNonce::new(IV_16).unwrap(), aad: Aad::new(&b"AAD"[..]).unwrap(), tag_length: 16.bytes() }
                .cipher(key())
                .unwrap();

        let mut ct = Vec::new();
        enc.update(msg, &mut ct).unwrap();
        enc.finalize(&mut ct).unwrap();
        let tag = enc.auth_tag().unwrap().unwrap();

        // Decrypt
        let mut dec = AesDecipherSpec::Gcm {
            iv: GcmNonce::new(IV_16).unwrap(),
            aad: Aad::new(&b"AAD"[..]).unwrap(),
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
