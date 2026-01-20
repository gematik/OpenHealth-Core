// SPDX-FileCopyrightText: Copyright 2025 - 2026 gematik GmbH
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
    use healthcard::exchange::certificate::{retrieve_certificate_from, CertificateFile};
    use healthcard::exchange::secure_channel::{establish_secure_channel_with, CardAccessNumber};
    use healthcard::exchange::{get_random, read_vsd, sign_challenge, verify_pin, CardPin, HealthCardVerifyPinResult};
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
        #[arg(long, required_unless_present = "list_readers")]
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
        /// Sign a challenge (hex) with the card holder authentication key
        #[arg(long, value_name = "HEX")]
        sign_challenge: Option<String>,
        /// Get random bytes from the card
        #[arg(long, value_name = "LEN")]
        get_random: Option<usize>,
        /// Read the VSD container and print it as hex
        #[arg(long)]
        read_vsd: bool,
    }

    fn run() -> Result<(), String> {
        let args = Args::parse();

        if args.list_readers {
            list_pcsc_readers()?;
            return Ok(());
        }

        let reader = args.reader.ok_or_else(|| "missing --reader".to_string())?;
        let out = args.out.ok_or_else(|| "missing --out".to_string())?;
        let can = args.can.ok_or_else(|| "missing --can".to_string())?;
        let supports_extended_length = !args.no_extended;

        let channel = PcscChannel::connect(&reader, supports_extended_length)
            .map_err(|err| format!("pcsc connect failed: {err}"))?;
        let mut recorder = RecordingChannel::new(channel);
        let card_access_number = CardAccessNumber::new(&can).map_err(|err| err.to_string())?;
        recorder.set_can(can.clone());

        let mut generated_keys = Vec::new();
        let mut secure_channel = establish_secure_channel_with(&mut recorder, &card_access_number, |curve: EcCurve| {
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
