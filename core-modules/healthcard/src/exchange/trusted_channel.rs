// SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
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

use asn1::cv_certificate::CVCertificate;
use asn1::decoder::{extract_context_values, Asn1Decoder};
use asn1::tag::TagNumberExt;

use crate::command::general_authenticate_command::GeneralAuthenticateCommand;
use crate::command::health_card_command::HealthCardCommand;
use crate::command::list_public_key_command::ListPublicKeyCommand;
use crate::command::manage_security_environment_command::ManageSecurityEnvironmentCommand;
use crate::command::pso_compute_digital_signature_command::PsoComputeDigitalSignatureCommand;
use crate::command::select_command::SelectCommand;
use crate::exchange::certificate::{retrieve_certificate_from, CertificateFile};
use crate::exchange::channel::{CardChannel, CardChannelExt};
use crate::exchange::elc;
use crate::exchange::error::ExchangeError;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Result of establishing a trusted (contact-based) channel.
#[derive(Debug, Clone)]
pub struct TrustedChannelResult {
    /// Raw response data from GENERAL AUTHENTICATE step 1 (card ephemeral public key).
    pub step1_response_data: Vec<u8>,
    /// CVCs used for MSE/PSO in order.
    pub cvcs: Vec<TrustedChannelCvcInfo>,
    /// CHR used as key reference for mutual authentication.
    pub end_entity_chr: Vec<u8>,
    /// Optional trace of raw APDU exchanges.
    pub trace: Vec<TrustedChannelStep>,
}

#[derive(Debug, Clone)]
pub struct TrustedChannelCvcInfo {
    pub car: Vec<u8>,
    pub chr: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TrustedChannelStep {
    pub label: String,
    pub apdu: Vec<u8>,
    pub sw: u16,
}

#[derive(Debug)]
pub struct TrustedChannelError {
    pub error: ExchangeError,
    pub cvcs: Vec<TrustedChannelCvcInfo>,
    pub end_entity_chr: Vec<u8>,
    pub trace: Vec<TrustedChannelStep>,
}

/// Options for the trusted channel flow.
#[derive(Debug, Clone, Copy)]
pub struct TrustedChannelOptions {
    pub select_private_key: bool,
    pub collect_trace: bool,
    pub key_ref_override: Option<[u8; 12]>,
}

impl Default for TrustedChannelOptions {
    fn default() -> Self {
        Self { select_private_key: false, collect_trace: false, key_ref_override: None }
    }
}

/// Establish a trusted channel using the CVC read from the card (end-entity).
///
/// This runs:
/// 1) Read CVC from MF/EF.C.eGK.AUT_CVC.E256
/// 2) MSE (CAR -> key reference)
/// 3) PSO (CVC value field)
/// 4) GENERAL AUTHENTICATE step 1
/// 5) GENERAL AUTHENTICATE step 2 (with freshly generated ephemeral key)
pub fn establish_trusted_channel<S>(session: &mut S) -> Result<TrustedChannelResult, ExchangeError>
where
    S: CardChannel + CardChannelExt,
{
    let cvc_bytes = retrieve_certificate_from(session, CertificateFile::EgkAutCvcE256)?;
    establish_trusted_channel_with_cvcs_and_options(session, &[cvc_bytes], TrustedChannelOptions::default())
}

/// Establish a trusted channel using the provided CV certificates.
///
/// Certificates should be ordered from Sub-CA to End-Entity. The last certificate is used
/// for the mutual authentication key reference (CHR).
pub fn establish_trusted_channel_with_cvcs<S>(
    session: &mut S,
    cvcs: &[Vec<u8>],
) -> Result<TrustedChannelResult, ExchangeError>
where
    S: CardChannel + CardChannelExt,
{
    establish_trusted_channel_with_cvcs_and_options(session, cvcs, TrustedChannelOptions::default())
}

/// Establish a trusted channel using the provided CV certificates and options.
pub fn establish_trusted_channel_with_cvcs_and_options<S>(
    session: &mut S,
    cvcs: &[Vec<u8>],
    options: TrustedChannelOptions,
) -> Result<TrustedChannelResult, ExchangeError>
where
    S: CardChannel + CardChannelExt,
{
    match establish_trusted_channel_with_cvcs_and_options_detailed(session, cvcs, options) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.error),
    }
}

/// Same as `establish_trusted_channel_with_cvcs_and_options`, but returns trace on error.
pub fn establish_trusted_channel_with_cvcs_and_options_detailed<S>(
    session: &mut S,
    cvcs: &[Vec<u8>],
    options: TrustedChannelOptions,
) -> Result<TrustedChannelResult, TrustedChannelError>
where
    S: CardChannel + CardChannelExt,
{
    if cvcs.is_empty() {
        return Err(TrustedChannelError {
            error: ExchangeError::invalid_argument("no CVCs provided"),
            cvcs: Vec::new(),
            end_entity_chr: Vec::new(),
            trace: Vec::new(),
        });
    }

    let mut trace = Vec::new();
    let mut cvc_infos = Vec::new();
    let mut end_entity_chr = Vec::new();
    let mut parsed = Vec::with_capacity(cvcs.len());
    for cvc in cvcs {
        parsed.push(CVCertificate::parse(cvc).map_err(|err| TrustedChannelError {
            error: err.into(),
            cvcs: cvc_infos.clone(),
            end_entity_chr: end_entity_chr.clone(),
            trace: trace.clone(),
        })?);
    }

    let select_mf = HealthCardCommand::select(false, false);
    let response = session.execute_command(&select_mf).map_err(|error| TrustedChannelError {
        error,
        cvcs: cvc_infos.clone(),
        end_entity_chr: end_entity_chr.clone(),
        trace: trace.clone(),
    })?;
    if options.collect_trace {
        trace.push(TrustedChannelStep {
            label: "select-mf".to_string(),
            apdu: select_mf
                .command_apdu(session.supports_extended_length())
                .map_err(|error| TrustedChannelError {
                    error: error.into(),
                    cvcs: cvc_infos.clone(),
                    end_entity_chr: end_entity_chr.clone(),
                    trace: trace.clone(),
                })?
                .as_bytes()
                .to_vec(),
            sw: response.apdu.sw(),
        });
    }
    if !response.status.is_success() {
        return Err(TrustedChannelError {
            error: ExchangeError::status(response.status),
            cvcs: cvc_infos.clone(),
            end_entity_chr: end_entity_chr.clone(),
            trace,
        });
    }

    if options.select_private_key {
        let select_private_key =
            HealthCardCommand::manage_sec_env_select_private_key(0x09, 0x54).map_err(|err| TrustedChannelError {
                error: err.into(),
                cvcs: cvc_infos.clone(),
                end_entity_chr: end_entity_chr.clone(),
                trace: trace.clone(),
            })?;
        execute_command_expect_success(
            session,
            &select_private_key,
            "select-private-key",
            options.collect_trace.then_some(&mut trace),
        )
        .map_err(|error| TrustedChannelError {
            error,
            cvcs: cvc_infos.clone(),
            end_entity_chr: end_entity_chr.clone(),
            trace: trace.clone(),
        })?;
    }

    for (idx, (cvc, raw)) in parsed.iter().zip(cvcs.iter()).enumerate() {
        let info = TrustedChannelCvcInfo {
            car: cvc.body.certification_authority_reference.clone(),
            chr: cvc.body.certificate_holder_reference.clone(),
        };
        cvc_infos.push(info);
        end_entity_chr = cvc.body.certificate_holder_reference.clone();
        let mse =
            HealthCardCommand::manage_sec_env_set_signature_key_reference(&cvc.body.certification_authority_reference)
                .map_err(|err| TrustedChannelError {
                    error: err.into(),
                    cvcs: cvc_infos.clone(),
                    end_entity_chr: end_entity_chr.clone(),
                    trace: trace.clone(),
                })?;
        execute_command_expect_success(
            session,
            &mse,
            &format!("mse-{idx}"),
            options.collect_trace.then_some(&mut trace),
        )
        .map_err(|error| TrustedChannelError {
            error,
            cvcs: cvc_infos.clone(),
            end_entity_chr: end_entity_chr.clone(),
            trace: trace.clone(),
        })?;

        let cvc_value = extract_cvc_value_field(raw).map_err(|error| TrustedChannelError {
            error,
            cvcs: cvc_infos.clone(),
            end_entity_chr: end_entity_chr.clone(),
            trace: trace.clone(),
        })?;
        let pso = HealthCardCommand::pso_compute_digital_signature_cvc(&cvc_value);
        execute_command_expect_success(
            session,
            &pso,
            &format!("pso-{idx}"),
            options.collect_trace.then_some(&mut trace),
        )
        .map_err(|error| TrustedChannelError {
            error,
            cvcs: cvc_infos.clone(),
            end_entity_chr: end_entity_chr.clone(),
            trace: trace.clone(),
        })?;
    }

    let end_entity = parsed.last().expect("non-empty");
    let (key_ref, key_ref_label) = if let Some(override_ref) = options.key_ref_override {
        (override_ref, override_ref.to_vec())
    } else {
        let key_ref: [u8; 12] =
            end_entity.body.certificate_holder_reference.as_slice().try_into().map_err(|_| TrustedChannelError {
                error: ExchangeError::invalid_argument("CHR must be 12 bytes"),
                cvcs: cvc_infos.clone(),
                end_entity_chr: end_entity_chr.clone(),
                trace: trace.clone(),
            })?;
        (key_ref, end_entity.body.certificate_holder_reference.clone())
    };
    let step1 = HealthCardCommand::general_authenticate_mutual_authentication_step1(&key_ref).map_err(|error| {
        TrustedChannelError {
            error: error.into(),
            cvcs: cvc_infos.clone(),
            end_entity_chr: end_entity_chr.clone(),
            trace: trace.clone(),
        }
    })?;
    let response = session.execute_command(&step1).map_err(|error| TrustedChannelError {
        error,
        cvcs: cvc_infos.clone(),
        end_entity_chr: end_entity_chr.clone(),
        trace: trace.clone(),
    })?;
    if options.collect_trace {
        trace.push(TrustedChannelStep {
            label: "ga-step1".to_string(),
            apdu: step1
                .command_apdu(session.supports_extended_length())
                .map_err(|error| TrustedChannelError {
                    error: error.into(),
                    cvcs: cvc_infos.clone(),
                    end_entity_chr: end_entity_chr.clone(),
                    trace: trace.clone(),
                })?
                .as_bytes()
                .to_vec(),
            sw: response.apdu.sw(),
        });
    }
    if !response.status.is_success() {
        return Err(TrustedChannelError {
            error: ExchangeError::status(response.status),
            cvcs: cvc_infos.clone(),
            end_entity_chr: end_entity_chr.clone(),
            trace,
        });
    }
    let step1_data = response.apdu.to_data();

    let ephemeral_pk = elc::generate_elc_ephemeral_public_key_from_cvc_from_parsed(end_entity).map_err(|error| {
        TrustedChannelError {
            error: error.into(),
            cvcs: cvc_infos.clone(),
            end_entity_chr: end_entity_chr.clone(),
            trace: trace.clone(),
        }
    })?;
    let step2 =
        HealthCardCommand::general_authenticate_elc_step2(&ephemeral_pk).map_err(|error| TrustedChannelError {
            error: error.into(),
            cvcs: cvc_infos.clone(),
            end_entity_chr: end_entity_chr.clone(),
            trace: trace.clone(),
        })?;
    let response = session.execute_command(&step2).map_err(|error| TrustedChannelError {
        error,
        cvcs: cvc_infos.clone(),
        end_entity_chr: end_entity_chr.clone(),
        trace: trace.clone(),
    })?;
    if options.collect_trace {
        trace.push(TrustedChannelStep {
            label: "ga-step2".to_string(),
            apdu: step2
                .command_apdu(session.supports_extended_length())
                .map_err(|error| TrustedChannelError {
                    error: error.into(),
                    cvcs: cvc_infos.clone(),
                    end_entity_chr: end_entity_chr.clone(),
                    trace: trace.clone(),
                })?
                .as_bytes()
                .to_vec(),
            sw: response.apdu.sw(),
        });
    }
    if !response.status.is_success() {
        return Err(TrustedChannelError {
            error: ExchangeError::status(response.status),
            cvcs: cvc_infos,
            end_entity_chr: end_entity_chr.clone(),
            trace,
        });
    }

    Ok(TrustedChannelResult { step1_response_data: step1_data, cvcs: cvc_infos, end_entity_chr: key_ref_label, trace })
}

/// Build a CVC chain from a directory by following CHR/CAR references.
///
/// Returns certificates ordered from issuer to end-entity (last element).
pub fn load_cvc_chain_from_dir(end_entity: &[u8], dir: &Path) -> Result<Vec<Vec<u8>>, ExchangeError> {
    let end_entity_cert = CVCertificate::parse(end_entity)?;
    let mut map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

    for entry in collect_files_with_extension(dir, "cvc")? {
        let bytes =
            fs::read(&entry).map_err(|err| ExchangeError::invalid_argument(format!("read CVC {entry:?}: {err}")))?;
        let cert = CVCertificate::parse(&bytes)?;
        map.entry(cert.body.certificate_holder_reference.clone()).or_insert(bytes);
    }

    let mut chain = Vec::new();
    let mut current = end_entity_cert;
    let mut visited = std::collections::HashSet::new();
    loop {
        let car = current.body.certification_authority_reference.clone();
        if !visited.insert(car.clone()) {
            break;
        }
        if let Some(issuer_bytes) = map.get(&car) {
            chain.push(issuer_bytes.clone());
            current = CVCertificate::parse(issuer_bytes)?;
        } else {
            break;
        }
    }

    chain.reverse();
    chain.push(end_entity.to_vec());
    Ok(chain)
}

/// Build a CVC chain from a directory based on available CAR references.
///
/// The first certificate is chosen by matching its CAR to one of the provided references.
/// The chain is then extended by following CAR == previous CHR.
pub fn load_cvc_chain_from_dir_for_cars(available_cars: &[Vec<u8>], dir: &Path) -> Result<Vec<Vec<u8>>, ExchangeError> {
    if available_cars.is_empty() {
        return Err(ExchangeError::invalid_argument("no CAR references provided"));
    }

    let mut certs = Vec::new();
    for entry in collect_files_with_extension(dir, "cvc")? {
        let bytes =
            fs::read(&entry).map_err(|err| ExchangeError::invalid_argument(format!("read CVC {entry:?}: {err}")))?;
        let cert = CVCertificate::parse(&bytes)?;
        certs.push((
            cert.body.certification_authority_reference.clone(),
            cert.body.certificate_holder_reference.clone(),
            bytes,
        ));
    }

    let mut candidates: Vec<_> =
        certs.iter().filter(|(car, _, _)| available_cars.iter().any(|allowed| allowed == car)).cloned().collect();
    candidates.sort_by(|a, b| a.1.cmp(&b.1));

    for (_car, chr, bytes) in candidates {
        let mut chain = vec![bytes];
        let mut current_chr = chr;
        let mut visited = std::collections::HashSet::new();
        loop {
            if !visited.insert(current_chr.clone()) {
                break;
            }
            if let Some((_, next_chr, next_bytes)) = certs.iter().find(|(next_car, _, _)| *next_car == current_chr) {
                chain.push(next_bytes.clone());
                current_chr = next_chr.clone();
            } else {
                break;
            }
        }
        return Ok(chain);
    }

    Err(ExchangeError::invalid_argument("no CVC chain found for available CARs"))
}

/// Establish a trusted channel using a directory of CVCs and the card's public key identifiers.
///
/// The card is queried via LIST PUBLIC KEY (gemSpec_COS_3.14.0#14.9.7) to obtain
/// available CARs and a key reference list.
/// The CVC chain is then resolved from `cvc_dir`, and GA step 1 uses the key reference from the card.
pub fn establish_trusted_channel_with_cvc_dir<S>(
    session: &mut S,
    cvc_dir: &Path,
) -> Result<TrustedChannelResult, ExchangeError>
where
    S: CardChannel + CardChannelExt,
{
    let (cars, key_refs) = read_public_key_identifiers(session)?;
    if cars.is_empty() {
        return Err(ExchangeError::invalid_argument("no CAR entries found in LIST PUBLIC KEY response"));
    }
    let key_ref = key_refs
        .first()
        .ok_or_else(|| ExchangeError::invalid_argument("no 12-byte key reference found in LIST PUBLIC KEY response"))?;
    let cvcs = load_cvc_chain_from_dir_for_cars(&cars, cvc_dir)?;
    let options =
        TrustedChannelOptions { select_private_key: true, collect_trace: false, key_ref_override: Some(*key_ref) };
    establish_trusted_channel_with_cvcs_and_options(session, &cvcs, options)
}

fn read_public_key_identifiers<S>(session: &mut S) -> Result<(Vec<Vec<u8>>, Vec<[u8; 12]>), ExchangeError>
where
    S: CardChannelExt,
{
    let command = HealthCardCommand::list_public_keys();
    let response = session.execute_command(&command)?;
    if !response.status.is_success() {
        return Err(ExchangeError::status(response.status));
    }
    let data = response.apdu.to_data();
    let values = extract_context_values(&data, 3).map_err(ExchangeError::from)?;
    let cars = values.iter().filter(|value| value.len() == 8).cloned().collect::<Vec<_>>();
    let key_refs_raw = values.iter().filter(|value| value.len() == 12).cloned().collect::<Vec<_>>();
    let mut key_refs = Vec::new();
    for raw in key_refs_raw {
        if let Ok(arr) = <[u8; 12]>::try_from(raw.as_slice()) {
            key_refs.push(arr);
        }
    }
    Ok((cars, key_refs))
}

fn execute_command_expect_success<S>(
    session: &mut S,
    command: &HealthCardCommand,
    label: &str,
    trace: Option<&mut Vec<TrustedChannelStep>>,
) -> Result<(), ExchangeError>
where
    S: CardChannelExt,
{
    let apdu = command.command_apdu(session.supports_extended_length()).map_err(ExchangeError::Apdu)?;
    let response = session.execute_command(command)?;
    let sw = response.apdu.sw();
    if let Some(trace) = trace {
        trace.push(TrustedChannelStep { label: label.to_string(), apdu: apdu.as_bytes().to_vec(), sw });
    }
    if response.status.is_success() {
        Ok(())
    } else {
        Err(ExchangeError::status(response.status))
    }
}

fn extract_cvc_value_field(data: &[u8]) -> Result<Vec<u8>, ExchangeError> {
    Asn1Decoder::new(data)
        .read(|scope| {
            scope.advance_with_tag(33u8.application_tag().constructed(), |inner| {
                let remaining = inner.remaining_length();
                inner.read_bytes(remaining)
            })
        })
        .map_err(Into::into)
}

fn collect_files_with_extension(dir: &Path, extension: &str) -> Result<Vec<PathBuf>, ExchangeError> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries =
            fs::read_dir(&path).map_err(|err| ExchangeError::invalid_argument(format!("read dir {path:?}: {err}")))?;
        for entry in entries {
            let entry = entry.map_err(|err| ExchangeError::invalid_argument(format!("read dir entry: {err}")))?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                stack.push(entry_path);
                continue;
            }
            if entry_path.extension().and_then(|ext| ext.to_str()) == Some(extension) {
                files.push(entry_path);
            }
        }
    }
    Ok(files)
}
