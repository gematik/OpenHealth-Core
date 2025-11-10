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
use super::session::{CardSession, CardSessionExt};
use crate::asn1::error::Asn1DecoderError;
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
use asn1::encoder::Asn1Encoder;
use asn1::error::Asn1EncoderError;
use crypto::cipher::aes::{AesCipherSpec, AesDecipherSpec, Cipher, Iv, Padding};
use crypto::ec::ec_key::{EcCurve, EcKeyPairSpec, EcPrivateKey, EcPublicKey};
use crypto::ec::ec_point::EcPoint;
use crypto::error::CryptoError;
use crypto::key::SecretKey;
use crypto::mac::{CmacAlgorithm, MacSpec};
use num_bigint::{BigInt, Sign};
use std::convert::TryFrom;

/// Trusted channel scope holding the negotiated PACE keys.
pub struct TrustedChannelScope<'a, S: CardSession> {
    session: &'a mut S,
    pace_key: PaceKey,
    ssc: [u8; 16],
}

impl<'a, S: CardSession> TrustedChannelScope<'a, S> {
    /// Access the established PACE keys.
    pub fn pace_key(&self) -> &PaceKey {
        &self.pace_key
    }

    /// Borrow the underlying transport mutably.
    pub fn session(&mut self) -> &mut S {
        self.session
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
            command_body.extend_from_slice(&encode_tlv(0x87, &value));
        }

        let expected_length = command.expected_length();
        if let Some(ne) = expected_length {
            let length_value = encode_length_object(ne);
            command_body.extend_from_slice(&encode_tlv(0x97, &length_value));
        }

        let mac = compute_mac(self.pace_key.mac(), &ssc, &header, &command_body)?;
        command_body.extend_from_slice(&encode_tlv(0x8E, &mac));

        let mut builder =
            CardCommandApdu::builder().cla(header[0]).ins(header[1]).p1(header[2]).p2(header[3]).data(command_body);

        let ne =
            if expected_length.is_some() { EXPECTED_LENGTH_WILDCARD_EXTENDED } else { EXPECTED_LENGTH_WILDCARD_SHORT };

        builder = builder.expected_length(ne);
        builder.build().map_err(ExchangeError::apdu)
    }

    /// Decrypt and verify a secure messaging response.
    pub fn decrypt(&mut self, response: CardResponseApdu) -> Result<CardResponseApdu, ExchangeError> {
        let bytes = response.bytes();
        if bytes.len() < 4 {
            return Err(ExchangeError::InvalidArgument("response apdu too short"));
        }

        let (body, sw_bytes) = bytes.split_at(bytes.len() - 2);
        let mut cursor = body;

        let mut do87_raw: Option<&[u8]> = None;
        let mut do87_value: Option<&[u8]> = None;
        let mut do99_raw: Option<&[u8]> = None;
        let mut status: Option<[u8; 2]> = None;
        let mut mac_value: Option<[u8; 8]> = None;

        while !cursor.is_empty() {
            let (tag, value, rest) = parse_tlv(cursor)?;
            match tag {
                0x87 => {
                    do87_raw = Some(&cursor[..cursor.len() - rest.len()]);
                    do87_value = Some(value);
                }
                0x99 => {
                    if value.len() != 2 {
                        return Err(ExchangeError::InvalidArgument("DO99 must contain SW1 SW2"));
                    }
                    do99_raw = Some(&cursor[..cursor.len() - rest.len()]);
                    status = Some([value[0], value[1]]);
                }
                0x8E => {
                    if value.len() != 8 {
                        return Err(ExchangeError::InvalidArgument("DO8E must contain 8 bytes"));
                    }
                    mac_value = Some(<[u8; 8]>::try_from(value).unwrap());
                }
                _ => return Err(ExchangeError::InvalidArgument("unexpected tag in secure response")),
            }
            cursor = rest;
        }

        let status = status.ok_or(ExchangeError::InvalidArgument("missing DO99 in response"))?;
        if status != [sw_bytes[0], sw_bytes[1]] {
            return Err(ExchangeError::InvalidArgument("status mismatch between DO99 and response"));
        }

        let mac_expected = mac_value.ok_or(ExchangeError::InvalidArgument("missing DO8E in response"))?;

        let mut mac_payload = Vec::new();
        if let Some(raw) = do87_raw {
            mac_payload.extend_from_slice(raw);
        }
        let do99_raw = do99_raw.ok_or(ExchangeError::InvalidArgument("missing DO99 raw bytes"))?;
        mac_payload.extend_from_slice(do99_raw);

        let mac = compute_mac(self.pace_key.mac(), &self.ssc, &[], &mac_payload)?;
        if mac.as_slice() != mac_expected {
            return Err(ExchangeError::MutualAuthenticationFailed);
        }

        let mut plaintext = Vec::new();
        if let Some(value) = do87_value {
            if value.is_empty() || value[0] != 0x01 {
                return Err(ExchangeError::InvalidArgument("invalid DO87 value"));
            }
            let ciphertext = &value[1..];
            let decrypted = decrypt_data(self.pace_key.encryption(), &self.ssc, ciphertext)?;
            let unpadded = unpad_iso9797_1(&decrypted)?;
            plaintext.extend_from_slice(&unpadded);
        }

        plaintext.extend_from_slice(sw_bytes);
        CardResponseApdu::new(&plaintext).map_err(ExchangeError::apdu)
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

impl<'a, S: CardSession> CardSession for TrustedChannelScope<'a, S> {
    type Error = ExchangeError;

    fn supports_extended_length(&self) -> bool {
        self.session.supports_extended_length()
    }

    fn transmit(&mut self, command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
        let encrypted = self.encrypt(command)?;
        let response = self.session.transmit(&encrypted).map_err(|err| ExchangeError::Transport(Box::new(err)))?;
        self.decrypt(response)
    }
}

/// Establish a PACE channel using random key material generated via `EcKeyPairSpec`.
pub fn establish_trusted_channel<'a, S>(
    session: &'a mut S,
    card_access_number: &str,
) -> Result<TrustedChannelScope<'a, S>, ExchangeError>
where
    S: CardSessionExt,
{
    establish_trusted_channel_with(session, card_access_number, |curve| EcKeyPairSpec { curve }.generate_keypair())
}

/// Establish a PACE channel with a custom key-pair generator (useful for testing).
pub fn establish_trusted_channel_with<'a, S, F>(
    session: &'a mut S,
    card_access_number: &str,
    mut key_generator: F,
) -> Result<TrustedChannelScope<'a, S>, ExchangeError>
where
    S: CardSessionExt,
    F: FnMut(EcCurve) -> Result<(EcPublicKey, EcPrivateKey), CryptoError>,
{
    // Ensure the basic operational environment is as required (eGK v2.1 with DF.CardAccess present)
    session.execute_command_success(&HealthCardCommand::select(false, true))?;
    let version_response =
        session.execute_command_success(&HealthCardCommand::read_sfi_with_offset(ids::ef_version2_sfid(), 0))?;
    let version =
        parse_health_card_version2(version_response.apdu.data_ref()).map_err(|_| ExchangeError::InvalidCardVersion)?;
    if !version.is_health_card_version_21() {
        return Err(ExchangeError::InvalidCardVersion);
    }

    session.execute_command_success(&HealthCardCommand::select_fid(&ids::ef_card_access_fid(), false))?;
    let pace_info_response = session.execute_command_success(&HealthCardCommand::read())?;
    let pace_info = parse_pace_info(pace_info_response.apdu.data_ref())?;

    session.execute_command_success(&HealthCardCommand::manage_sec_env_without_curves(
        &crate::card::card_key::CardKey::new(ids::SECRET_KEY_REFERENCE),
        false,
        &pace_info.protocol_id_bytes(),
    )?)?;

    // Step 1: obtain nonce Z from the card and compute S
    let nonce_z_response = session.execute_command_success(&HealthCardCommand::general_authenticate(true)?)?;
    let nonce_z = decode_general_authenticate(nonce_z_response.apdu.data_ref())?;
    let can_key = get_aes128_key(card_access_number.as_bytes(), Mode::Password)?;
    let nonce_s_bytes = decrypt_nonce(&can_key, &nonce_z)?;
    let nonce_s = BigInt::from_bytes_be(Sign::Plus, &nonce_s_bytes);

    // Step 2: generate the PCD ephemeral key pair and exchange with the PICC
    let (_, pcd_private) = key_generator(pace_info.curve.clone())?;
    let pcd_scalar = big_int_from_secret(&pcd_private);
    let pcd_shared_secret = pace_info.curve.g().mul(&pcd_scalar)?;
    let pcd_shared_bytes = pcd_shared_secret.uncompressed()?;
    let picc_pk_response = session.execute_command_success(&HealthCardCommand::general_authenticate_with_data(
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
        session.execute_command_success(&HealthCardCommand::general_authenticate_with_data(true, &ep_gs_bytes, 3)?)?;
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
        session.execute_command_success(&HealthCardCommand::general_authenticate_with_data(false, &mac, 5)?)?;
    let picc_mac = decode_general_authenticate(picc_mac_response.apdu.data_ref())?;
    if picc_mac != derived_mac {
        return Err(ExchangeError::MutualAuthenticationFailed);
    }

    Ok(TrustedChannelScope { session, pace_key, ssc: [0u8; 16] })
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
    use crate::asn1::encoder::Asn1Encoder;
    use crate::asn1::tag::Asn1Id;

    Asn1Encoder::write(|writer| {
        writer.write_tagged_object(Asn1Id::app(0x49).constructed(), |outer| {
            outer.write_object_identifier(protocol_id)?;
            outer.write_tagged_object(Asn1Id::ctx(0x06).primitive(), |inner| -> Result<(), Asn1EncoderError> {
                inner.write_bytes(public_key.as_ref());
                Ok(())
            })?;
            Ok(())
        })
    })
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

fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 3 + value.len());
    out.push(tag);
    encode_length(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
    }
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

fn parse_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), ExchangeError> {
    if input.len() < 2 {
        return Err(ExchangeError::InvalidArgument("tlv too short"));
    }
    let tag = input[0];
    let first_len = input[1];
    let (length, offset) = if first_len & 0x80 == 0 {
        (first_len as usize, 2)
    } else {
        let count = (first_len & 0x7F) as usize;
        if input.len() < 2 + count {
            return Err(ExchangeError::InvalidArgument("invalid tlv length"));
        }
        let mut len = 0usize;
        for &b in &input[2..2 + count] {
            len = (len << 8) | (b as usize);
        }
        (len, 2 + count)
    };

    if input.len() < offset + length {
        return Err(ExchangeError::InvalidArgument("truncated tlv value"));
    }
    Ok((tag, &input[offset..offset + length], &input[offset + length..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::apdu::{CardCommandApdu, CardResponseApdu};
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

    impl CardSession for DummySession {
        type Error = ExchangeError;

        fn supports_extended_length(&self) -> bool {
            true
        }

        fn transmit(&mut self, _command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
            Err(ExchangeError::InvalidArgument("dummy session cannot transmit"))
        }
    }

    fn make_scope() -> TrustedChannelScope<'static, DummySession> {
        let session = Box::leak(Box::new(DummySession));
        TrustedChannelScope { session, pace_key: pace_key_fixture(), ssc: [0u8; 16] }
    }

    fn to_hex(apdu: &CardCommandApdu) -> String {
        hex::encode_upper(apdu.apdu())
    }

    #[test]
    fn encrypt_case1_header_only() {
        let command = CardCommandApdu::of_options_without_data(0x01, 0x02, 0x03, 0x04, None).unwrap();
        let mut scope = make_scope();
        let secured = scope.encrypt(&command).unwrap();
        assert_eq!(to_hex(&secured), "0D0203040A8E08D92B4FDDC2BBED8C00");
        // Double encryption should be rejected
        assert!(scope.encrypt(&secured).is_err());
    }

    #[test]
    fn encrypt_case2_short_le() {
        let command = CardCommandApdu::of_options_without_data(0x01, 0x02, 0x03, 0x04, Some(127)).unwrap();
        let mut scope = make_scope();
        let secured = scope.encrypt(&command).unwrap();
        assert_eq!(to_hex(&secured), "0D02030400000D97017F8E0871D8E0418DAE20F30000");
    }

    #[test]
    fn encrypt_case2_extended_le() {
        let command = CardCommandApdu::of_options_without_data(0x01, 0x02, 0x03, 0x04, Some(257)).unwrap();
        let mut scope = make_scope();
        let secured = scope.encrypt(&command).unwrap();
        assert_eq!(to_hex(&secured), "0D02030400000E970201018E089F3EDDFBB1D3971D0000");
    }

    #[test]
    fn encrypt_case3_short_data() {
        let data = vec![0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
        let command = CardCommandApdu::of_options(0x01, 0x02, 0x03, 0x04, Some(data), None).unwrap();
        let mut scope = make_scope();
        let secured = scope.encrypt(&command).unwrap();
        assert_eq!(to_hex(&secured), "0D0203041D871101496C26D36306679609665A385C54DB378E08E7AAD918F260D8EF00");
    }

    #[test]
    fn encrypt_case4_short_data_with_le() {
        let data = vec![0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
        let command = CardCommandApdu::of_options(0x01, 0x02, 0x03, 0x04, Some(data), Some(127)).unwrap();
        let mut scope = make_scope();
        let secured = scope.encrypt(&command).unwrap();
        assert_eq!(
            to_hex(&secured),
            "0D020304000020871101496C26D36306679609665A385C54DB3797017F8E0863D541F262BD445A0000"
        );
    }

    #[test]
    fn encrypt_case4_extended_data_with_le() {
        let data = vec![0u8; 256];
        let command = CardCommandApdu::of_options(0x01, 0x02, 0x03, 0x04, Some(data), Some(127)).unwrap();
        let mut scope = make_scope();
        let secured = scope.encrypt(&command).unwrap();
        assert_eq!(
            to_hex(&secured),
            "0D02030400012287820111013297D4AA774AB26AF8AD539C0A829BCA4D222D3EE2DB100CF86D7DB5A1FAC12B7623328DEFE3F6FDD41A993AC917BC17B364C3DD24740079DE60A3D0231A7185D36A77D37E147025913ADA00CD07736CFDE0DB2E0BB09B75C5773607E54A9D84181ACBC6F7726762A8BCE324C0B330548114154A13EDDBFF6DCBC3773DCA9A8494404BE4A5654273F9C2B9EBE1BD615CB39FFD0D3F2A0EEA29AA10B810D53EDB550FB741A68CC6B0BDF928F9EB6BC238416AACB4CF3002E865D486CF42D762C86EEBE6A2B25DECE2E88D569854A07D3F146BC134BAF08B6EDCBEBDFF47EBA6AC7B441A1642B03253B588C49B69ABBEC92BA1723B7260DE8AD6158873141AFA7C70CFCF125BA1DF77CA48025D049FCEE497017F8E0856332C83EABDF93C0000"
        );
    }

    fn scope_with_ssc(value: u8) -> TrustedChannelScope<'static, DummySession> {
        let mut scope = make_scope();
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
