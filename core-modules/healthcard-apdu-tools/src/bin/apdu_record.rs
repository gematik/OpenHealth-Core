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

#[cfg(not(feature = "pcsc"))]
fn main() {
    eprintln!("This binary requires --features pcsc");
}

#[cfg(feature = "pcsc")]
fn main() {
    use clap::Parser;
    use crypto::ec::ec_key::{EcCurve, EcKeyPairSpec};
    #[cfg(feature = "trusted-channel")]
    use healthcard::command::apdu::{
        CardCommandApdu, LengthClass, EXPECTED_LENGTH_WILDCARD_EXTENDED, EXPECTED_LENGTH_WILDCARD_SHORT,
    };
    use healthcard::exchange::certificate::{retrieve_certificate_from, CertificateFile};
    #[cfg(feature = "trusted-channel")]
    use healthcard::exchange::channel::CardChannel;
    use healthcard::exchange::secure_channel::{establish_secure_channel_with, CardAccessNumber};
    use healthcard::exchange::{
        change_pin, change_pin_with_puk, get_random, read_vsd, sign_challenge, unlock_egk_with_puk, verify_pin,
        CardPin, HealthCardVerifyPinResult,
    };
    #[cfg(feature = "trusted-channel")]
    use healthcard_apdu_tools::trusted_channel::{
        establish_trusted_channel, establish_trusted_channel_with_cvcs,
        establish_trusted_channel_with_cvcs_and_options_detailed, load_cvc_chain_from_dir,
        load_cvc_chain_from_dir_for_cars, TrustedChannelOptions, TrustedChannelResult,
    };
    use healthcard_apdu_tools::{PcscChannel, RecordingChannel};

    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }

    #[derive(Debug, Parser)]
    #[command(name = "apdu_record")]
    #[command(about = "Record APDU input/output for PACE establish", long_about = None)]
    struct Args {
        /// PC/SC reader name
        #[arg(long, required_unless_present = "list_readers")]
        reader: Option<String>,
        /// Card Access Number (6 digits)
        #[arg(long)]
        can: Option<String>,
        /// Output transcript path (JSONL)
        #[arg(long, required_unless_present = "list_readers")]
        out: Option<String>,
        /// Use short APDUs only
        #[arg(long)]
        no_extended: bool,
        /// List available PC/SC readers and exit
        #[arg(long)]
        list_readers: bool,
        /// Read certificates and print them as hex to stdout
        #[arg(long)]
        read_certificates: bool,
        /// Verify the home PIN (MRPIN.H)
        #[arg(long, value_name = "PIN")]
        verify_pin: Option<String>,
        /// Unlock the eGK using the PUK (reset retry counter)
        #[arg(long, value_name = "PUK")]
        unlock_egk_with_puk: Option<String>,
        /// Change the home PIN using the PUK (reset retry counter + set new PIN)
        #[arg(long, value_names = ["PUK", "PIN"], num_args = 2)]
        change_pin_with_puk: Option<Vec<String>>,
        /// Change the home PIN using the old PIN
        #[arg(long, value_names = ["OLD_PIN", "NEW_PIN"], num_args = 2)]
        change_pin: Option<Vec<String>>,
        /// Sign a challenge (hex) with the card holder authentication key
        #[arg(long, value_name = "HEX")]
        sign_challenge: Option<String>,
        /// Get random bytes from the card
        #[arg(long, value_name = "LEN")]
        get_random: Option<usize>,
        /// Read the VSD container and print it as hex
        #[arg(long)]
        read_vsd: bool,
        /// Run the contact-based trusted channel flow (ELC mutual authentication)
        #[cfg(feature = "trusted-channel")]
        #[arg(long)]
        trusted_channel: bool,
        /// CVC file(s) to use for trusted channel (repeatable)
        #[cfg(feature = "trusted-channel")]
        #[arg(long, value_name = "PATH")]
        cvc: Vec<String>,
        /// Directory containing PKI_CVC input CVCs (will resolve chain automatically)
        #[cfg(feature = "trusted-channel")]
        #[arg(long, value_name = "DIR", default_value = "test-vectors/cvc-chain/pki_cvc_g2_input")]
        cvc_dir: Option<String>,
        /// Select private key before trusted channel (MSE Set)
        #[cfg(feature = "trusted-channel")]
        #[arg(long)]
        select_private_key: bool,
        /// Print detailed trusted channel steps (APDU + SW)
        #[cfg(feature = "trusted-channel")]
        #[arg(long)]
        trusted_channel_verbose: bool,
    }

    fn run() -> Result<(), String> {
        let args = Args::parse();

        if args.list_readers {
            list_pcsc_readers()?;
            return Ok(());
        }

        let reader = args.reader.ok_or_else(|| "missing --reader".to_string())?;
        let out = args.out.ok_or_else(|| "missing --out".to_string())?;
        let supports_extended_length = !args.no_extended;

        let channel = PcscChannel::connect(&reader, supports_extended_length)
            .map_err(|err| format!("pcsc connect failed: {err}"))?;
        let mut recorder = RecordingChannel::new(channel);
        #[cfg(feature = "trusted-channel")]
        let use_trusted_channel = args.trusted_channel;
        #[cfg(not(feature = "trusted-channel"))]
        let use_trusted_channel = false;

        if use_trusted_channel {
            #[cfg(feature = "trusted-channel")]
            {
                if args.can.is_some()
                    || args.read_certificates
                    || args.verify_pin.is_some()
                    || args.unlock_egk_with_puk.is_some()
                    || args.change_pin_with_puk.is_some()
                    || args.change_pin.is_some()
                    || args.sign_challenge.is_some()
                    || args.get_random.is_some()
                    || args.read_vsd
                {
                    return Err("trusted-channel mode is exclusive and does not use PACE options".to_string());
                }
                let mut cvcs = Vec::new();
                let use_options = args.select_private_key || args.trusted_channel_verbose;
                let mut options = TrustedChannelOptions {
                    select_private_key: args.select_private_key,
                    collect_trace: args.trusted_channel_verbose,
                    key_ref_override: None,
                };

                let (available_cars, key_refs) =
                    match read_public_key_identifiers(&mut recorder, args.trusted_channel_verbose) {
                        Ok((cars, refs)) => (cars, refs),
                        Err(err) => {
                            println!("TrustedChannel: retrieve public key identifiers failed: {err}");
                            (Vec::new(), Vec::new())
                        }
                    };
                if let Some(key_ref) = key_refs.first() {
                    options.key_ref_override = Some(*key_ref);
                    if args.trusted_channel_verbose {
                        println!("TrustedChannel: selected GA keyRef={}", hex::encode_upper(key_ref));
                    }
                } else if use_options {
                    return Err(
                        "trusted channel failed: no 12-byte key reference found in GET DATA (0x80CA0100)".to_string()
                    );
                }

                if let Some(dir) = args.cvc_dir.as_deref() {
                    if !available_cars.is_empty() {
                        cvcs = load_cvc_chain_from_dir_for_cars(&available_cars, std::path::Path::new(dir))
                            .map_err(|err| format!("load CVC chain for CARs failed: {err}"))?;
                    } else {
                        let end_entity = retrieve_certificate_from(&mut recorder, CertificateFile::EgkAutCvcE256)
                            .map_err(|err| format!("read MF/EF.C.eGK.AUT_CVC.E256 failed: {err}"))?;
                        cvcs = load_cvc_chain_from_dir(&end_entity, std::path::Path::new(dir))
                            .map_err(|err| format!("load CVC chain failed: {err}"))?;
                    }
                } else if !args.cvc.is_empty() {
                    for path in &args.cvc {
                        let bytes = std::fs::read(path).map_err(|err| format!("read CVC {path}: {err}"))?;
                        cvcs.push(bytes);
                    }
                }

                let result = if cvcs.is_empty() {
                    if use_options {
                        let end_entity = retrieve_certificate_from(&mut recorder, CertificateFile::EgkAutCvcE256)
                            .map_err(|err| format!("read MF/EF.C.eGK.AUT_CVC.E256 failed: {err}"))?;
                        cvcs.push(end_entity);
                        match establish_trusted_channel_with_cvcs_and_options_detailed(&mut recorder, &cvcs, options) {
                            Ok(result) => result,
                            Err(err) => {
                                print_trusted_channel_info(&TrustedChannelResult {
                                    step1_response_data: Vec::new(),
                                    cvcs: err.cvcs,
                                    end_entity_chr: err.end_entity_chr,
                                    trace: err.trace,
                                });
                                return Err(format!("trusted channel failed: {}", err.error));
                            }
                        }
                    } else {
                        establish_trusted_channel(&mut recorder)
                            .map_err(|err| format!("trusted channel failed: {err}"))?
                    }
                } else if use_options {
                    match establish_trusted_channel_with_cvcs_and_options_detailed(&mut recorder, &cvcs, options) {
                        Ok(result) => result,
                        Err(err) => {
                            print_trusted_channel_info(&TrustedChannelResult {
                                step1_response_data: Vec::new(),
                                cvcs: err.cvcs,
                                end_entity_chr: err.end_entity_chr,
                                trace: err.trace,
                            });
                            return Err(format!("trusted channel failed: {}", err.error));
                        }
                    }
                } else {
                    establish_trusted_channel_with_cvcs(&mut recorder, &cvcs)
                        .map_err(|err| format!("trusted channel failed: {err}"))?
                };
                print_trusted_channel_info(&result);
            }
        } else {
            let can = args.can.ok_or_else(|| "missing --can".to_string())?;
            let card_access_number = CardAccessNumber::new(&can).map_err(|err| err.to_string())?;
            recorder.set_can(can.clone());

            let mut generated_keys = Vec::new();
            let mut secure_channel =
                establish_secure_channel_with(&mut recorder, &card_access_number, |curve: EcCurve| {
                    let (public_key, private_key) = EcKeyPairSpec { curve: curve.clone() }.generate_keypair()?;
                    generated_keys.push(hex::encode_upper(private_key.as_bytes()));
                    Ok((public_key, private_key))
                })
                .map_err(|err| format!("PACE failed: {err}"))?;

            if let Some(pin) = args.verify_pin.as_deref() {
                let pin = CardPin::new(pin).map_err(|err| format!("invalid PIN: {err}"))?;
                match verify_pin(&mut secure_channel, &pin).map_err(|err| format!("verify PIN failed: {err}"))? {
                    HealthCardVerifyPinResult::Success(_) => println!("PIN verification: success"),
                    HealthCardVerifyPinResult::WrongSecretWarning { retries_left, .. } => {
                        return Err(format!("PIN verification failed, retries left: {retries_left}"));
                    }
                    HealthCardVerifyPinResult::CardBlocked(_) => {
                        return Err("PIN verification failed: card blocked".to_string());
                    }
                }
            }

            if let Some(puk) = args.unlock_egk_with_puk.as_deref() {
                let puk = CardPin::new(puk).map_err(|err| format!("invalid PUK: {err}"))?;
                unlock_egk_with_puk(&mut secure_channel, &puk).map_err(|err| format!("unlock eGK failed: {err}"))?;
                println!("eGK unlock: success");
            }

            if let Some(values) = args.change_pin_with_puk.as_deref() {
                let (puk, new_pin) = match values {
                    [puk, new_pin] => (puk.as_str(), new_pin.as_str()),
                    _ => return Err("change-pin-with-puk requires PUK and PIN".to_string()),
                };
                let puk = CardPin::new(puk).map_err(|err| format!("invalid PUK: {err}"))?;
                let new_pin = CardPin::new(new_pin).map_err(|err| format!("invalid new PIN: {err}"))?;
                change_pin_with_puk(&mut secure_channel, &puk, &new_pin)
                    .map_err(|err| format!("change PIN with PUK failed: {err}"))?;
                println!("PIN change (PUK): success");
            }

            if let Some(values) = args.change_pin.as_deref() {
                let (old_pin, new_pin) = match values {
                    [old_pin, new_pin] => (old_pin.as_str(), new_pin.as_str()),
                    _ => return Err("change-pin requires OLD_PIN and NEW_PIN".to_string()),
                };
                let old_pin = CardPin::new(old_pin).map_err(|err| format!("invalid old PIN: {err}"))?;
                let new_pin = CardPin::new(new_pin).map_err(|err| format!("invalid new PIN: {err}"))?;
                change_pin(&mut secure_channel, &old_pin, &new_pin)
                    .map_err(|err| format!("change PIN failed: {err}"))?;
                println!("PIN change: success");
            }

            if args.read_certificates {
                let cert = retrieve_certificate_from(&mut secure_channel, CertificateFile::ChAutE256)
                    .map_err(|err| format!("read DF.ESIGN/EF.C.CH.AUT.E256 failed: {err}"))?;
                print_hex("DF.ESIGN/EF.C.CH.AUT.E256", &cert);

                let cert = retrieve_certificate_from(&mut secure_channel, CertificateFile::EgkAutCvcE256)
                    .map_err(|err| format!("read MF/EF.C.eGK.AUT_CVC.E256 failed: {err}"))?;
                print_hex("MF/EF.C.eGK.AUT_CVC.E256", &cert);
            }

            if args.read_vsd {
                let vsd = read_vsd(&mut secure_channel).map_err(|err| format!("read VSD failed: {err}"))?;
                print_hex("VSD", &vsd);
            }

            if let Some(length) = args.get_random {
                if length == 0 {
                    return Err("random length must be greater than 0".to_string());
                }
                let random = get_random(&mut secure_channel, length)
                    .map_err(|err| format!("get random ({length}) failed: {err}"))?;
                print_hex(&format!("Random ({length} bytes)"), &random);
            }

            if let Some(challenge_hex) = args.sign_challenge.as_deref() {
                let challenge = parse_hex("challenge", challenge_hex)?;
                let signature = sign_challenge(&mut secure_channel, &challenge)
                    .map_err(|err| format!("sign challenge failed: {err}"))?;
                print_hex("Signature", &signature);
            }

            drop(secure_channel);

            if !generated_keys.is_empty() {
                recorder.set_keys(generated_keys);
            }
        }

        let transcript = recorder.into_transcript();
        transcript.write_jsonl(out).map_err(|err| format!("write transcript failed: {err}"))?;
        Ok(())
    }

    fn parse_hex(label: &str, input: &str) -> Result<Vec<u8>, String> {
        let trimmed = input.trim();
        let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        let cleaned =
            without_prefix.chars().filter(|c| !matches!(c, ' ' | '_' | ':' | '\n' | '\r' | '\t')).collect::<String>();
        if cleaned.is_empty() {
            return Err(format!("{label} hex input is empty"));
        }
        hex::decode(&cleaned).map_err(|err| format!("invalid {label} hex: {err}"))
    }

    fn print_hex(label: &str, data: &[u8]) {
        println!("{label} ({} bytes):", data.len());
        for chunk in data.chunks(32) {
            println!("  {}", hex::encode_upper(chunk));
        }
    }

    #[cfg(feature = "trusted-channel")]
    fn print_trusted_channel_info(result: &TrustedChannelResult) {
        println!("TrustedChannel: CVCs used");
        for (idx, info) in result.cvcs.iter().enumerate() {
            println!("  [{}] CAR={} CHR={}", idx, hex::encode_upper(&info.car), hex::encode_upper(&info.chr));
        }
        println!("TrustedChannel: GA keyRef CHR={}", hex::encode_upper(&result.end_entity_chr));
        if !result.trace.is_empty() {
            println!("TrustedChannel: steps");
            for step in &result.trace {
                println!("  {}: APDU={} SW=0x{:04X}", step.label, hex::encode_upper(&step.apdu), step.sw);
            }
        }
    }

    #[cfg(feature = "trusted-channel")]
    type PublicKeyIdentifiers = (Vec<Vec<u8>>, Vec<[u8; 12]>);

    #[cfg(feature = "trusted-channel")]
    fn read_public_key_identifiers(
        channel: &mut RecordingChannel<PcscChannel>,
        verbose: bool,
    ) -> Result<PublicKeyIdentifiers, String> {
        let length_class = if channel.supports_extended_length() { LengthClass::Extended } else { LengthClass::Short };
        let ne = if length_class == LengthClass::Extended {
            EXPECTED_LENGTH_WILDCARD_EXTENDED
        } else {
            EXPECTED_LENGTH_WILDCARD_SHORT
        };
        let apdu =
            CardCommandApdu::with_expect(0x80, 0xCA, 0x01, 0x00, length_class, ne).map_err(|err| err.to_string())?;
        let response = channel.transmit(&apdu).map_err(|err| format!("{err:?}"))?;
        if verbose {
            println!("TrustedChannel: public key identifiers response (SW=0x{:04X})", response.sw());
            let data = response.to_data();
            if data.is_empty() {
                println!("  <empty>");
            } else {
                for chunk in data.chunks(32) {
                    println!("  {}", hex::encode_upper(chunk));
                }
            }
        }
        let data = response.to_data();
        let cars = extract_tagged_values(&data, 0x83, 8);
        let key_refs_raw = extract_tagged_values(&data, 0x83, 12);
        let mut key_refs = Vec::new();
        for raw in key_refs_raw {
            if let Ok(arr) = <[u8; 12]>::try_from(raw.as_slice()) {
                key_refs.push(arr);
            }
        }
        if verbose && !cars.is_empty() {
            println!("TrustedChannel: available CARs");
            for car in &cars {
                println!("  {}", hex::encode_upper(car));
            }
        }
        if verbose && !key_refs.is_empty() {
            println!("TrustedChannel: available key refs");
            for key_ref in &key_refs {
                println!("  {}", hex::encode_upper(key_ref));
            }
        }
        Ok((cars, key_refs))
    }

    #[cfg(feature = "trusted-channel")]
    fn extract_tagged_values(data: &[u8], tag: u8, expected_len: usize) -> Vec<Vec<u8>> {
        let mut values = Vec::new();
        let mut idx = 0;
        while idx + 2 <= data.len() {
            if data[idx] == tag {
                let len = data[idx + 1] as usize;
                if len == expected_len && idx + 2 + len <= data.len() {
                    values.push(data[idx + 2..idx + 2 + len].to_vec());
                    idx += 2 + len;
                    continue;
                }
            }
            idx += 1;
        }
        values.sort();
        values.dedup();
        values
    }

    fn list_pcsc_readers() -> Result<(), String> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)
            .map_err(|err| format!("pcsc context establish failed: {err}"))?;
        let readers = ctx.list_readers_owned().map_err(|err| format!("pcsc list readers failed: {err}"))?;
        if readers.is_empty() {
            println!("no pcsc readers found");
            return Ok(());
        }
        println!("pcsc readers:");
        for reader in readers {
            println!("  {}", reader.to_string_lossy());
        }
        Ok(())
    }
}
