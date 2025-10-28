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

use crate::key::PrivateKey;
use crate::ossl;
use crate::utils::byte_unit::ByteUnit;

pub use crate::error::CryptoResult;

/// Initialization vector for AES-based operations.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Additional authenticated data for AEAD ciphers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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

/// Authentication tag produced or consumed by AEAD modes.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Specification for AES encryption.
///
/// - `Ecb`/`Cbc` support optional PKCS#7 padding.
/// - `Gcm` is an AEAD mode requiring an IV (nonce), optional AAD and a tag length.
#[derive(Clone, uniffi::Enum)]
pub enum AesCipherSpec {
    Ecb { padding: Padding },
    Cbc { iv: Iv, padding: Padding },
    Gcm { iv: Iv, aad: Aad, tag_length: ByteUnit },
}

impl AesCipherSpec {
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
            Self::Cbc { iv, .. } | Self::Gcm { iv, .. } => Some(iv.as_ref()),
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

    fn tag_length(&self) -> Option<ByteUnit> {
        match self {
            Self::Ecb { .. } | Self::Cbc { .. } => None,
            Self::Gcm { tag_length, .. } => Some(*tag_length),
        }
    }

    /// Create an encryptor for the given key and spec.
    pub fn cipher(self, key: PrivateKey) -> CryptoResult<AesCipher> {
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
    key: PrivateKey,
}

/// Specification for AES decryption.
#[derive(Clone)]
pub enum AesDecipherSpec {
    Ecb { padding: Padding },
    Cbc { iv: Iv, padding: Padding },
    Gcm { iv: Iv, aad: Aad, auth_tag: Tag },
}

impl AesDecipherSpec {
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
            Self::Cbc { iv, .. } | Self::Gcm { iv, .. } => Some(iv.as_ref()),
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

    fn auth_tag(&self) -> Option<&Tag> {
        match self {
            Self::Ecb { .. } | Self::Cbc { .. } => None,
            Self::Gcm { auth_tag, .. } => Some(auth_tag),
        }
    }

    /// Create a decryptor for the given key and spec.
    pub fn cipher(self, key: PrivateKey) -> CryptoResult<AesDecipher> {
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
    key: PrivateKey,
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
        self.cipher.update(input, output).map_err(Into::into)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> CryptoResult<usize> {
        self.cipher.finalize(output).map_err(Into::into)
    }

    fn auth_tag(&self) -> CryptoResult<Option<Tag>> {
        self.spec
            .tag_length()
            .map(|tag_length| {
                let len = tag_length.bytes() as usize;
                Ok(Tag::new(self.cipher.get_auth_tag(len)?))
            })
            .transpose()
    }
}

impl Cipher for AesDecipher {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<usize> {
        self.cipher.update(input, output).map_err(Into::into)
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> CryptoResult<usize> {
        self.cipher.finalize(output).map_err(Into::into)
    }

    fn auth_tag(&self) -> CryptoResult<Option<Tag>> {
        Ok(self.spec.auth_tag().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::PrivateKey;
    use crate::utils::byte_unit::BytesExt;
    use crate::utils::test_utils::{hex_to_bytes, to_hex_string};

    const KEY_16: &[u8] = b"1234567890123456";
    const IV_16: &[u8] = b"1234567890123456";

    const ECB_HEX: &str = "C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1";
    const CBC_HEX: &str = "67 23 83 A2 43 37 DC 8A 35 64 A2 00 F2 1E E8 C0";

    const GCM_CT_HEX: &str = "CE C1 89 D0 E8 4D EC A8 E6 08 DD";
    const GCM_TAG_HEX: &str = "0F 98 50 42 1A DA DC FF 64 5F 7E 79 79 E2 E6 8A";

    fn key() -> PrivateKey {
        PrivateKey::new_secret(KEY_16)
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
        let mut cipher = AesCipherSpec::Cbc { iv: Iv::new(IV_16), padding: Padding::Pkcs7 }.cipher(key()).unwrap();

        let mut ct = Vec::new();
        cipher.update(b"Hello World", &mut ct).unwrap();
        cipher.finalize(&mut ct).unwrap();

        assert_eq!(to_hex_string(&ct), CBC_HEX);
    }

    #[test]
    fn aes_cbc_128_decrypt() {
        let mut decipher = AesDecipherSpec::Cbc { iv: Iv::new(IV_16), padding: Padding::Pkcs7 }.cipher(key()).unwrap();

        let mut pt = Vec::new();
        decipher.update(&hex_to_bytes(CBC_HEX), &mut pt).unwrap();
        decipher.finalize(&mut pt).unwrap();

        assert_eq!(pt, b"Hello World");
    }

    #[test]
    fn aes_gcm_128_encrypt() {
        let mut cipher = AesCipherSpec::Gcm { iv: Iv::new(IV_16), aad: Aad::default(), tag_length: 16.bytes() }
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
        let mut enc = AesCipherSpec::Gcm { iv: Iv::new(IV_16), aad: Aad::new(&b"AAD"[..]), tag_length: 16.bytes() }
            .cipher(key())
            .unwrap();

        let mut ct = Vec::new();
        enc.update(msg, &mut ct).unwrap();
        enc.finalize(&mut ct).unwrap();
        let tag = enc.auth_tag().unwrap().unwrap();

        // Decrypt
        let mut dec = AesDecipherSpec::Gcm { iv: Iv::new(IV_16), aad: Aad::new(&b"AAD"[..]), auth_tag: tag }
            .cipher(key())
            .unwrap();

        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).unwrap();
        dec.finalize(&mut pt).unwrap();

        assert_eq!(pt, msg);
    }
}
