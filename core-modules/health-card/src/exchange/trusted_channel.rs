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

use super::error::ExchangeError;
use super::ids;
use super::pace_info::parse_pace_info;
use super::session::{CardChannel, CardChannelExt};
use crate::asn1::decoder::Asn1Decoder;
use crate::asn1::encoder::Asn1Encoder;
use crate::asn1::error::Asn1DecoderError;
use crate::asn1::tag::{Asn1Class, Asn1Id};
use crate::card::health_card_version2::parse_health_card_version2;
use crate::card::pace_key::{get_aes128_key, Mode, PaceKey};
use crate::command::apdu::{
    CardCommandApdu, CardResponseApdu, EXPECTED_LENGTH_WILDCARD_EXTENDED, EXPECTED_LENGTH_WILDCARD_SHORT,
};
use crate::command::general_authenticate_command::GeneralAuthenticateCommand;
use crate::command::health_card_command::HealthCardCommand;
use crate::command::manage_security_environment_command::ManageSecurityEnvironmentCommand;
use crate::command::read_command::ReadCommand;
use crate::command::select_command::SelectCommand;
use asn1::error::Asn1EncoderError;
use crypto::cipher::aes::{AesCipherSpec, AesDecipherSpec, Cipher, Iv, Padding};
use crypto::ec::ec_key::{EcCurve, EcKeyPairSpec, EcPrivateKey, EcPublicKey};
use crypto::error::CryptoError;
use crypto::key::SecretKey;
use crypto::mac::{CmacAlgorithm, MacSpec};
use num_bigint::{BigInt, Sign};
use std::convert::{TryFrom, TryInto};
use thiserror::Error;

/// Trusted channel scope holding the negotiated PACE keys.
pub struct TrustedChannel<S: CardChannel> {
    channel: S,
    pace_key: PaceKey,
    ssc: [u8; 16],
}

/// Error type returned by the trusted-channel session wrapper.
#[derive(Debug, Error)]
pub enum TrustedChannelError {
    /// Errors originating from the secure messaging layer.
    #[error(transparent)]
    Secure(#[from] ExchangeError),
    /// Errors bubbled up from the underlying transport session.
    #[error("transport session error: {0}")]
    Transport(ExchangeError),
}

impl TrustedChannelError {
    fn transport<E: Into<ExchangeError>>(err: E) -> Self {
        Self::Transport(err.into())
    }
}

impl From<TrustedChannelError> for ExchangeError {
    fn from(err: TrustedChannelError) -> Self {
        match err {
            TrustedChannelError::Secure(inner) | TrustedChannelError::Transport(inner) => inner,
        }
    }
}

impl<S: CardChannel> TrustedChannel<S> {
    /// Access the established PACE keys.
    pub fn pace_key(&self) -> &PaceKey {
        &self.pace_key
    }

    pub fn channel(&mut self) -> &S {
        &self.channel
    }

    /// Encrypt a plain APDU command using secure messaging.
    pub fn encrypt(&mut self, command: &CardCommandApdu) -> Result<CardCommandApdu, ExchangeError> {
        ensure_not_secure(command)?;

        let ssc = self.increment_ssc();
        let header = secure_header(command);

        let mut command_body = Vec::new();
        if let Some(data) = command.data_ref() {
            let ciphertext = encrypt_data(self.pace_key.encryption(), &ssc, data)?;
            let mut value = Vec::with_capacity(ciphertext.len() + 1);
            value.push(0x01);
            value.extend_from_slice(&ciphertext);
            let do87 = encode_context_specific(0x07, &value)?;
            command_body.extend_from_slice(&do87);
        }

        let expected_length = command.expected_length();
        if let Some(ne) = expected_length {
            let length_value = encode_length_object(ne);
            let do97 = encode_context_specific(0x17, &length_value)?;
            command_body.extend_from_slice(&do97);
        }

        let mac = compute_mac(self.pace_key.mac(), &ssc, &header, &command_body)?;
        let do8e = encode_context_specific(0x0E, &mac)?;
        command_body.extend_from_slice(&do8e);

        let mut builder =
            CardCommandApdu::builder().cla(header[0]).ins(header[1]).p1(header[2]).p2(header[3]).data(command_body);

        let ne =
            if expected_length.is_some() { EXPECTED_LENGTH_WILDCARD_EXTENDED } else { EXPECTED_LENGTH_WILDCARD_SHORT };

        builder = builder.expected_length(ne);
        builder.build().map_err(ExchangeError::Apdu)
    }

    /// Decrypt and verify a secure messaging response.
    pub fn decrypt(&mut self, response: CardResponseApdu) -> Result<CardResponseApdu, ExchangeError> {
        let bytes = response.bytes();
        if bytes.len() < 4 {
            return Err(ExchangeError::InvalidArgument("response apdu too short"));
        }

        let (body, sw_bytes) = bytes.split_at(bytes.len() - 2);
        if body.is_empty() {
            return Err(ExchangeError::InvalidArgument("response apdu missing secure messaging data objects"));
        }

        let ssc = self.increment_ssc();
        let response_objects = parse_response_objects(body)?;
        if response_objects.status_bytes != [sw_bytes[0], sw_bytes[1]] {
            return Err(ExchangeError::InvalidArgument("status mismatch between DO99 and response"));
        }

        let ResponseObjects { data_object, status_bytes, mac_bytes } = response_objects;

        let mut mac_payload = Vec::new();
        if let Some(data_object) = data_object.as_ref() {
            mac_payload.extend_from_slice(&data_object.encoded()?);
        }
        let do99 = encode_context_specific(0x19, &status_bytes)?;
        mac_payload.extend_from_slice(&do99);

        let mac = compute_mac(self.pace_key.mac(), &ssc, &[], &mac_payload)?;
        if mac != mac_bytes {
            return Err(ExchangeError::MutualAuthenticationFailed);
        }

        let mut plaintext = Vec::new();
        if let Some(data_object) = data_object {
            if data_object.is_encrypted() {
                let data = data_object.data();
                if data.is_empty() || data[0] != 0x01 {
                    return Err(ExchangeError::InvalidArgument("invalid DO87 value"));
                }
                let ciphertext = &data[1..];
                let decrypted = decrypt_data(self.pace_key.encryption(), &ssc, ciphertext)?;
                let unpadded = unpad_iso9797_1(&decrypted)?;
                plaintext.extend_from_slice(&unpadded);
            } else {
                plaintext.extend_from_slice(data_object.data());
            }
        }

        plaintext.extend_from_slice(&status_bytes);
        CardResponseApdu::new(&plaintext).map_err(ExchangeError::Apdu)
    }

    fn increment_ssc(&mut self) -> [u8; 16] {
        for byte in self.ssc.iter_mut().rev() {
            let (new, carry) = byte.overflowing_add(1);
            *byte = new;
            if !carry {
                break;
            }
        }
        self.ssc
    }
}

impl<S: CardChannel> CardChannel for TrustedChannel<S> {
    type Error = TrustedChannelError;

    fn supports_extended_length(&self) -> bool {
        self.channel.supports_extended_length()
    }

    fn transmit(&mut self, command: &CardCommandApdu) -> Result<CardResponseApdu, TrustedChannelError> {
        let encrypted = self.encrypt(command).map_err(TrustedChannelError::Secure)?;
        let response = self.channel.transmit(&encrypted).map_err(TrustedChannelError::transport)?;
        self.decrypt(response).map_err(TrustedChannelError::Secure)
    }
}

/// Establish a PACE channel using random key material generated via `EcKeyPairSpec`.
pub fn establish_trusted_channel<S>(session: S, card_access_number: &str) -> Result<TrustedChannel<S>, ExchangeError>
where
    S: CardChannelExt,
{
    establish_trusted_channel_with(session, card_access_number, |curve| EcKeyPairSpec { curve }.generate_keypair())
}

/// Establish a PACE channel with a custom key-pair generator (useful for testing).
pub fn establish_trusted_channel_with<S, F>(
    mut channel: S,
    card_access_number: &str,
    mut key_generator: F,
) -> Result<TrustedChannel<S>, ExchangeError>
where
    S: CardChannelExt,
    F: FnMut(EcCurve) -> Result<(EcPublicKey, EcPrivateKey), CryptoError>,
{
    // Ensure the basic operational environment is as required (eGK v2.1 with DF.CardAccess present)
    channel.execute_command_success(&HealthCardCommand::select(false, true))?;
    let read_version = HealthCardCommand::read_sfi_with_offset(ids::ef_version2_sfid(), 0)?;
    let version_response = channel.execute_command_success(&read_version)?;
    let version =
        parse_health_card_version2(version_response.apdu.data_ref()).map_err(|_| ExchangeError::InvalidCardVersion)?;
    if !version.is_health_card_version_21() {
        return Err(ExchangeError::InvalidCardVersion);
    }

    channel.execute_command_success(&HealthCardCommand::select_fid(&ids::ef_card_access_fid(), false))?;
    let read_card_access = HealthCardCommand::read()?;
    let pace_info_response = channel.execute_command_success(&read_card_access)?;
    let pace_info = parse_pace_info(pace_info_response.apdu.data_ref())?;

    channel.execute_command_success(&HealthCardCommand::manage_sec_env_without_curves(
        &crate::card::card_key::CardKey::new(ids::SECRET_KEY_REFERENCE),
        false,
        &pace_info.protocol_id_bytes(),
    )?)?;

    // Step 1: obtain nonce Z from the card and compute S
    let nonce_z_response = channel.execute_command_success(&HealthCardCommand::general_authenticate(true)?)?;
    let nonce_z = decode_general_authenticate(nonce_z_response.apdu.data_ref())?;
    let can_key = get_aes128_key(card_access_number.as_bytes(), Mode::Password)?;
    let nonce_s_bytes = decrypt_nonce(&can_key, &nonce_z)?;
    let nonce_s = BigInt::from_bytes_be(Sign::Plus, &nonce_s_bytes);

    // Step 2: generate the PCD ephemeral key pair and exchange with the PICC
    let (_, pcd_private) = key_generator(pace_info.curve.clone())?;
    let pcd_scalar = big_int_from_secret(&pcd_private);
    let pcd_shared_secret = pace_info.curve.g().mul(&pcd_scalar)?;
    let pcd_shared_bytes = pcd_shared_secret.uncompressed()?;
    let picc_pk_response = channel.execute_command_success(&HealthCardCommand::general_authenticate_with_data(
        true,
        &pcd_shared_bytes,
        1,
    )?)?;
    let mut picc_public_key = EcPublicKey::from_uncompressed(
        pace_info.curve.clone(),
        decode_general_authenticate(picc_pk_response.apdu.data_ref())?,
    )?;

    let (_, ep_private) = key_generator(pace_info.curve.clone())?;
    let ep_shared_secret = picc_public_key.to_ec_point().mul(&pcd_scalar)?;
    let nonce_point = pace_info.curve.g().mul(&nonce_s)?;
    let gs_shared_secret = nonce_point.add(&ep_shared_secret)?;
    let ep_scalar = big_int_from_secret(&ep_private);
    let ep_gs_shared_secret = gs_shared_secret.mul(&ep_scalar)?;
    let ep_gs_bytes = ep_gs_shared_secret.uncompressed()?;

    let picc_pk_response =
        channel.execute_command_success(&HealthCardCommand::general_authenticate_with_data(true, &ep_gs_bytes, 3)?)?;
    picc_public_key = EcPublicKey::from_uncompressed(
        pace_info.curve.clone(),
        decode_general_authenticate(picc_pk_response.apdu.data_ref())?,
    )?;

    let shared_secret_point = picc_public_key.to_ec_point().mul(&ep_scalar)?;
    let shared_secret_bytes = shared_secret_point.uncompressed()?;
    let coord_len = coordinate_size(&pace_info.curve);
    if shared_secret_bytes.len() < 1 + coord_len {
        return Err(ExchangeError::Crypto(CryptoError::InvalidEcPoint(
            "shared secret shorter than coordinate length".into(),
        )));
    }
    let shared_secret_x = &shared_secret_bytes[1..1 + coord_len];

    let encryption_key = get_aes128_key(shared_secret_x, Mode::Enc)?;
    let mac_key = get_aes128_key(shared_secret_x, Mode::Mac)?;
    let pace_key = PaceKey::new(encryption_key, mac_key);

    let mac = derive_mac(pace_key.mac(), &picc_public_key, &pace_info.protocol_id)?;
    let derived_mac = derive_mac(pace_key.mac(), &ep_gs_shared_secret.to_ec_public_key()?, &pace_info.protocol_id)?;

    let picc_mac_response =
        channel.execute_command_success(&HealthCardCommand::general_authenticate_with_data(false, &mac, 5)?)?;
    let picc_mac = decode_general_authenticate(picc_mac_response.apdu.data_ref())?;
    if picc_mac != derived_mac {
        return Err(ExchangeError::MutualAuthenticationFailed);
    }

    Ok(TrustedChannel { channel, pace_key, ssc: [0u8; 16] })
}

fn big_int_from_secret(key: &EcPrivateKey) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, key.as_bytes())
}

fn coordinate_size(curve: &EcCurve) -> usize {
    match curve {
        EcCurve::BrainpoolP256r1 => 32,
        EcCurve::BrainpoolP384r1 => 48,
        EcCurve::BrainpoolP512r1 => 64,
    }
}

fn decrypt_nonce(key: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, ExchangeError> {
    let mut decipher = AesDecipherSpec::Cbc { iv: Iv::new(vec![0u8; 16]), padding: Padding::None }
        .cipher(SecretKey::new_secret(key.as_ref().to_vec()))?;
    let mut out = Vec::with_capacity(ciphertext.len());
    decipher.update(ciphertext, &mut out)?;
    decipher.finalize(&mut out)?;
    Ok(out)
}

fn decode_general_authenticate(data: &[u8]) -> Result<Vec<u8>, ExchangeError> {
    if data.len() < 4 || data[0] != 0x7C {
        return Err(ExchangeError::Asn1DecoderError(Asn1DecoderError::custom(
            "GENERAL AUTHENTICATE response missing application tag",
        )));
    }
    let total_len = data[1] as usize;
    if data.len() < 2 + total_len {
        return Err(ExchangeError::Asn1DecoderError(Asn1DecoderError::InvalidLength { length: total_len }));
    }
    let inner = &data[2..2 + total_len];
    if inner.len() < 2 {
        return Err(ExchangeError::Asn1DecoderError(Asn1DecoderError::InvalidLength { length: inner.len() }));
    }
    let value_len = inner[1] as usize;
    if inner.len() < 2 + value_len {
        return Err(ExchangeError::Asn1DecoderError(Asn1DecoderError::InvalidLength { length: value_len }));
    }
    Ok(inner[2..2 + value_len].to_vec())
}

fn create_asn1_auth_token(public_key: &EcPublicKey, protocol_id: &str) -> Result<Vec<u8>, ExchangeError> {
    Asn1Encoder::write::<Asn1EncoderError>(|writer| {
        writer.write_tagged_object(Asn1Id::app(0x49).constructed(), |outer| {
            outer.write_object_identifier(protocol_id)?;
            outer.write_tagged_object(Asn1Id::ctx(0x06).primitive(), |inner| -> Result<(), Asn1EncoderError> {
                inner.write_bytes(public_key.as_ref());
                Ok(())
            })?;
            Ok(())
        })
    })
    .map_err(ExchangeError::from)
}

fn derive_mac(mac_key: &SecretKey, public_key: &EcPublicKey, protocol_id: &str) -> Result<Vec<u8>, ExchangeError> {
    let auth_token = create_asn1_auth_token(public_key, protocol_id)?;
    let mut mac =
        MacSpec::Cmac { algorithm: CmacAlgorithm::Aes }.create(SecretKey::new_secret(mac_key.as_ref().to_vec()))?;
    mac.update(&auth_token)?;
    let tag = mac.finalize()?;
    Ok(tag.into_iter().take(8).collect())
}

fn ensure_not_secure(command: &CardCommandApdu) -> Result<(), ExchangeError> {
    if command.cla() & 0x0C == 0x0C {
        return Err(ExchangeError::InvalidArgument("command already secured"));
    }
    Ok(())
}

fn secure_header(command: &CardCommandApdu) -> [u8; 4] {
    [command.cla() | 0x0C, command.ins(), command.p1(), command.p2()]
}

fn encrypt_data(key: &SecretKey, ssc: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, ExchangeError> {
    let iv = derive_iv(key, ssc)?;
    let mut cipher = AesCipherSpec::Cbc { iv: Iv::new(iv), padding: Padding::None }
        .cipher(SecretKey::new_secret(key.as_ref().to_vec()))?;
    let padded = iso9797_1_pad(data);
    let mut out = Vec::with_capacity(padded.len());
    cipher.update(&padded, &mut out)?;
    cipher.finalize(&mut out)?;
    Ok(out)
}

fn decrypt_data(key: &SecretKey, ssc: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, ExchangeError> {
    let iv = derive_iv(key, ssc)?;
    let mut cipher = AesDecipherSpec::Cbc { iv: Iv::new(iv), padding: Padding::None }
        .cipher(SecretKey::new_secret(key.as_ref().to_vec()))?;
    let mut out = Vec::with_capacity(data.len());
    cipher.update(data, &mut out)?;
    cipher.finalize(&mut out)?;
    Ok(out)
}

fn derive_iv(key: &SecretKey, ssc: &[u8; 16]) -> Result<Vec<u8>, ExchangeError> {
    let mut cipher =
        AesCipherSpec::Ecb { padding: Padding::None }.cipher(SecretKey::new_secret(key.as_ref().to_vec()))?;
    let mut out = Vec::with_capacity(ssc.len());
    cipher.update(ssc, &mut out)?;
    cipher.finalize(&mut out)?;
    Ok(out)
}

fn iso9797_1_pad(data: &[u8]) -> Vec<u8> {
    let pad_len = 16 - (data.len() % 16);
    let mut out = Vec::with_capacity(data.len() + pad_len);
    out.extend_from_slice(data);
    out.push(0x80);
    out.extend(std::iter::repeat(0x00).take(pad_len - 1));
    out
}

fn unpad_iso9797_1(data: &[u8]) -> Result<Vec<u8>, ExchangeError> {
    for i in (0..data.len()).rev() {
        match data[i] {
            0x80 => return Ok(data[..i].to_vec()),
            0x00 => continue,
            _ => break,
        }
    }
    Err(ExchangeError::InvalidArgument("invalid iso9797 padding"))
}

fn encode_length_object(le: usize) -> Vec<u8> {
    if le == EXPECTED_LENGTH_WILDCARD_SHORT {
        vec![0x00]
    } else if le > EXPECTED_LENGTH_WILDCARD_SHORT {
        vec![((le >> 8) & 0xFF) as u8, (le & 0xFF) as u8]
    } else {
        vec![le as u8]
    }
}

fn encode_context_specific(tag_number: u32, value: &[u8]) -> Result<Vec<u8>, ExchangeError> {
    Asn1Encoder::write::<Asn1EncoderError>(|writer| {
        writer.write_tagged_object(Asn1Id::ctx(tag_number).primitive(), |scope| {
            scope.write_bytes(value);
            Ok(())
        })
    })
    .map_err(ExchangeError::from)
}

fn compute_mac(
    mac_key: &SecretKey,
    ssc: &[u8; 16],
    header: &[u8],
    command_output: &[u8],
) -> Result<[u8; 8], ExchangeError> {
    let mut mac =
        MacSpec::Cmac { algorithm: CmacAlgorithm::Aes }.create(SecretKey::new_secret(mac_key.as_ref().to_vec()))?;
    mac.update(ssc)?;
    if !header.is_empty() {
        mac.update(&iso9797_1_pad(header))?;
    }
    if !command_output.is_empty() {
        mac.update(&iso9797_1_pad(command_output))?;
    }
    let tag = mac.finalize()?;
    Ok(<[u8; 8]>::try_from(&tag[..8]).unwrap())
}

fn parse_response_objects(data: &[u8]) -> Result<ResponseObjects, ExchangeError> {
    let decoder = Asn1Decoder::new(data);
    let objects = decoder.read(|reader| -> Result<ResponseObjects, Asn1DecoderError> {
        let mut data_object: Option<SecureDataObject> = None;
        let mut status_bytes: Option<[u8; 2]> = None;
        let mut mac_bytes: Option<[u8; 8]> = None;

        while reader.remaining_length() > 0 {
            let tag = reader.read_tag()?;
            if tag.class != Asn1Class::ContextSpecific {
                return Err(Asn1DecoderError::custom("unexpected tag class in secure response"));
            }
            let length = reader.read_length()?;
            if length < 0 {
                return Err(Asn1DecoderError::custom("indefinite length not supported in secure response"));
            }
            let value = reader.read_bytes(length as usize)?;

            match tag.number {
                0x01 | 0x07 => {
                    if data_object.is_some() {
                        return Err(Asn1DecoderError::custom("multiple data objects in secure response"));
                    }
                    data_object = Some(SecureDataObject { tag_number: tag.number, value });
                }
                0x19 => {
                    let length = value.len();
                    let array: [u8; 2] =
                        value.try_into().map_err(|_| Asn1DecoderError::InvalidLength { length })?;
                    status_bytes = Some(array);
                }
                0x0E => {
                    let length = value.len();
                    let array: [u8; 8] =
                        value.try_into().map_err(|_| Asn1DecoderError::InvalidLength { length })?;
                    mac_bytes = Some(array);
                }
                other => {
                    return Err(Asn1DecoderError::custom(format!(
                        "unexpected secure messaging tag 0x{other:02X}"
                    )))
                }
            }
        }

        let status_bytes = status_bytes.ok_or_else(|| Asn1DecoderError::custom("missing DO99 in secure response"))?;
        let mac_bytes = mac_bytes.ok_or_else(|| Asn1DecoderError::custom("missing DO8E in secure response"))?;
        Ok(ResponseObjects { data_object, status_bytes, mac_bytes })
    })?;

    Ok(objects)
}

struct SecureDataObject {
    tag_number: u32,
    value: Vec<u8>,
}

impl SecureDataObject {
    fn encoded(&self) -> Result<Vec<u8>, ExchangeError> {
        encode_context_specific(self.tag_number, &self.value)
    }

    fn data(&self) -> &[u8] {
        &self.value
    }

    fn is_encrypted(&self) -> bool {
        self.tag_number == 0x07
    }
}

struct ResponseObjects {
    data_object: Option<SecureDataObject>,
    status_bytes: [u8; 2],
    mac_bytes: [u8; 8],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::apdu::{CardCommandApdu, CardResponseApdu};
    use crate::exchange::session::CardChannel;
    use hex::encode;

    #[test]
    fn create_auth_token_matches_reference() {
        let curve = EcCurve::BrainpoolP256r1;
        let public_key = curve.g().to_ec_public_key().unwrap();
        let token = create_asn1_auth_token(&public_key, "1.2.3.4.5").unwrap();
        assert_eq!(
            encode(token).to_uppercase(),
            "7F494906042A0304058641048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"
        );
    }

    fn pace_key_fixture() -> PaceKey {
        let enc = SecretKey::new_secret(hex::decode("68406B4162100563D9C901A6154D2901").unwrap());
        let mac = SecretKey::new_secret(hex::decode("73FF268784F72AF833FDC9464049AFC9").unwrap());
        PaceKey::new(enc, mac)
    }

    struct DummySession;

    impl CardChannel for DummySession {
        type Error = ExchangeError;

        fn supports_extended_length(&self) -> bool {
            true
        }

        fn transmit(&mut self, _command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
            Err(ExchangeError::InvalidArgument("dummy session cannot transmit"))
        }
    }

    fn make_channel() -> TrustedChannel<DummySession> {
        let channel = DummySession;
        TrustedChannel { channel, pace_key: pace_key_fixture(), ssc: [0u8; 16] }
    }

    fn to_hex(apdu: &CardCommandApdu) -> String {
        hex::encode_upper(apdu.apdu())
    }

    #[test]
    fn encrypt_case1_header_only() {
        let command = CardCommandApdu::new_without_data(0x01, 0x02, 0x03, 0x04, None).unwrap();
        let mut scope = make_channel();
        let secured = scope.encrypt(&command).unwrap();
        assert_eq!(to_hex(&secured), "0D0203040A8E08D92B4FDDC2BBED8C00");
        // Double encryption should be rejected
        assert!(scope.encrypt(&secured).is_err());
    }

    #[test]
    fn encrypt_case2_short_le() {
        let command = CardCommandApdu::new_without_data(0x01, 0x02, 0x03, 0x04, Some(127)).unwrap();
        let mut scope = make_channel();
        let secured = scope.encrypt(&command).unwrap();
        assert_eq!(to_hex(&secured), "0D02030400000D97017F8E0871D8E0418DAE20F30000");
    }

    #[test]
    fn encrypt_case2_extended_le() {
        let command = CardCommandApdu::new_without_data(0x01, 0x02, 0x03, 0x04, Some(257)).unwrap();
        let mut scope = make_channel();
        let secured = scope.encrypt(&command).unwrap();
        assert_eq!(to_hex(&secured), "0D02030400000E970201018E089F3EDDFBB1D3971D0000");
    }

    #[test]
    fn encrypt_case3_short_data() {
        let data = vec![0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
        let command = CardCommandApdu::new(0x01, 0x02, 0x03, 0x04, Some(data), None).unwrap();
        let mut scope = make_channel();
        let secured = scope.encrypt(&command).unwrap();
        assert_eq!(to_hex(&secured), "0D0203041D871101496C26D36306679609665A385C54DB378E08E7AAD918F260D8EF00");
    }

    #[test]
    fn encrypt_case4_short_data_with_le() {
        let data = vec![0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
        let command = CardCommandApdu::new(0x01, 0x02, 0x03, 0x04, Some(data), Some(127)).unwrap();
        let mut scope = make_channel();
        let secured = scope.encrypt(&command).unwrap();
        assert_eq!(
            to_hex(&secured),
            "0D020304000020871101496C26D36306679609665A385C54DB3797017F8E0863D541F262BD445A0000"
        );
    }

    #[test]
    fn encrypt_case4_extended_data_with_le() {
        let data = vec![0u8; 256];
        let command = CardCommandApdu::new(0x01, 0x02, 0x03, 0x04, Some(data), Some(127)).unwrap();
        let mut scope = make_channel();
        let secured = scope.encrypt(&command).unwrap();
        assert_eq!(
            to_hex(&secured),
            "0D02030400012287820111013297D4AA774AB26AF8AD539C0A829BCA4D222D3EE2DB100CF86D7DB5A1FAC12B7623328DEFE3F6FDD41A993AC917BC17B364C3DD24740079DE60A3D0231A7185D36A77D37E147025913ADA00CD07736CFDE0DB2E0BB09B75C5773607E54A9D84181ACBC6F7726762A8BCE324C0B330548114154A13EDDBFF6DCBC3773DCA9A8494404BE4A5654273F9C2B9EBE1BD615CB39FFD0D3F2A0EEA29AA10B810D53EDB550FB741A68CC6B0BDF928F9EB6BC238416AACB4CF3002E865D486CF42D762C86EEBE6A2B25DECE2E88D569854A07D3F146BC134BAF08B6EDCBEBDFF47EBA6AC7B441A1642B03253B588C49B69ABBEC92BA1723B7260DE8AD6158873141AFA7C70CFCF125BA1DF77CA48025D049FCEE497017F8E0856332C83EABDF93C0000"
        );
    }

    fn scope_with_ssc(value: u8) -> TrustedChannel<DummySession> {
        let mut scope = make_channel();
        scope.ssc[15] = value;
        scope
    }

    #[test]
    fn decrypt_do99_only() {
        let response = CardResponseApdu::new(&hex::decode("990290008E08087631D746F872729000").unwrap()).unwrap();
        let mut scope = scope_with_ssc(1);
        let plain = scope.decrypt(response).unwrap();
        assert_eq!(hex::encode_upper(plain.bytes()), "9000");
    }

    #[test]
    fn decrypt_do87_and_do99() {
        let response = CardResponseApdu::new(
            &hex::decode("871101496C26D36306679609665A385C54DB37990290008E08B7E9ED2A0C89FB3A9000").unwrap(),
        )
        .unwrap();
        let mut scope = scope_with_ssc(1);
        let plain = scope.decrypt(response).unwrap();
        assert_eq!(hex::encode_upper(plain.bytes()), "05060708090A9000");
    }
}
