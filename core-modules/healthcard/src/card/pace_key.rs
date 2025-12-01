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

use std::fmt;

use crypto::digest::DigestSpec;
use crypto::error::CryptoError;
use crypto::key::SecretKey;
use crypto::utils::constant_time::content_constant_time_equals;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// PACE key derivation modes as defined in BSI TR-03110.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Derive the encryption key (`K_enc`).
    Enc,
    /// Derive the MAC key (`K_mac`).
    Mac,
    /// Derive the password key (`K_pwd`).
    Password,
}

impl Mode {
    fn counter(self) -> u32 {
        match self {
            Mode::Enc => 0x0000_0001,
            Mode::Mac => 0x0000_0002,
            Mode::Password => 0x0000_0003,
        }
    }
}

/// Derives an AES-128 key for the given [Mode] using the shared secret `k`.
///
/// The derivation uses SHA-1 as specified in BSI TR-03110:
/// `K_mode = SHA-1(k || counter_mode)` truncated to 16 bytes.
pub fn get_aes128_key(shared_secret: &[u8], mode: Mode) -> Result<SecretKey, CryptoError> {
    let mut digest = DigestSpec::Sha1.create()?;
    digest.update(shared_secret)?;
    digest.update(&mode.counter().to_be_bytes())?;
    let mut derived: Zeroizing<Vec<u8>> = Zeroizing::new(digest.finalize()?);
    derived.truncate(16);
    Ok(SecretKey::new_secret(derived.to_vec()))
}

/// Holds the symmetric keys derived during PACE.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PaceSessionKeys {
    encryption: SecretKey,
    mac: SecretKey,
}

impl PaceSessionKeys {
    /// Construct a new PACE key set.
    pub fn new(encryption: SecretKey, mac: SecretKey) -> Self {
        Self { encryption, mac }
    }

    /// Access the encryption key (`K_enc`).
    pub fn encryption(&self) -> &SecretKey {
        &self.encryption
    }

    /// Access the MAC key (`K_mac`).
    pub fn mac(&self) -> &SecretKey {
        &self.mac
    }
}

impl PartialEq for PaceSessionKeys {
    fn eq(&self, other: &Self) -> bool {
        let enc_eq = content_constant_time_equals(self.encryption.as_ref(), other.encryption.as_ref());
        let mac_eq = content_constant_time_equals(self.mac.as_ref(), other.mac.as_ref());
        enc_eq && mac_eq
    }
}

impl Eq for PaceSessionKeys {}

impl fmt::Debug for PaceSessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaceSessionKeys")
            .field("enc_len", &self.encryption.len())
            .field("mac_len", &self.mac.len())
            .finish_non_exhaustive()
    }
}

/// Backwards compatibility alias for the previous name.
pub type PaceKey = PaceSessionKeys;

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_K: &str = "2ECA74E72CD6C1E0DA235093569984987C34A9F4D34E4E60FB0AD87B983CDC62";

    fn hex(bytes: &[u8]) -> String {
        hex::encode(bytes).to_uppercase()
    }

    #[test]
    fn derive_aes128_key_enc() {
        let secret = hex::decode(SECRET_K).unwrap();
        let key = get_aes128_key(&secret, Mode::Enc).unwrap();
        assert_eq!(hex(key.as_ref()), "AB5541629D18E5F33EE2B13DBDCDBE84");
    }

    #[test]
    fn derive_aes128_key_mac() {
        let secret = hex::decode(SECRET_K).unwrap();
        let key = get_aes128_key(&secret, Mode::Mac).unwrap();
        assert_eq!(hex(key.as_ref()), "E13D3757C7D9073794A3D7CA94B22D30");
    }

    #[test]
    fn derive_aes128_key_password() {
        let secret = hex::decode(SECRET_K).unwrap();
        let key = get_aes128_key(&secret, Mode::Password).unwrap();
        assert_eq!(hex(key.as_ref()), "74C1F5E712B53BAAA3B02B182E0961B9");
    }

    #[test]
    fn pace_key_equality() {
        let secret = hex::decode(SECRET_K).unwrap();
        let k_enc = get_aes128_key(&secret, Mode::Enc).unwrap();
        let k_mac = get_aes128_key(&secret, Mode::Mac).unwrap();
        let pace_key_1 = PaceKey::new(k_enc, k_mac);

        let secret = hex::decode(SECRET_K).unwrap();
        let k_enc_2 = get_aes128_key(&secret, Mode::Enc).unwrap();
        let k_mac_2 = get_aes128_key(&secret, Mode::Mac).unwrap();
        let pace_key_2 = PaceKey::new(k_enc_2, k_mac_2);

        assert_eq!(pace_key_1, pace_key_2);
    }
}
