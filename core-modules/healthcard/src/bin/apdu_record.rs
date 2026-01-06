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

#[cfg(not(feature = "apdu-tools"))]
fn main() {
    eprintln!("This binary requires --features apdu-tools");
}

#[cfg(feature = "apdu-tools")]
fn main() {
    use clap::Parser;
    use crypto::ec::ec_key::{EcCurve, EcKeyPairSpec};
    use healthcard::exchange::apdu_tools::{PcscChannel, RecordingChannel};
    use healthcard::exchange::secure_channel::{establish_secure_channel_with, CardAccessNumber};

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
        #[arg(long, conflicts_with = "extended")]
        no_extended: bool,
        /// Use extended-length APDUs
        #[arg(long, conflicts_with = "no_extended")]
        extended: bool,
        /// List available PC/SC readers and exit
        #[arg(long)]
        list_readers: bool,
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
        establish_secure_channel_with(&mut recorder, &card_access_number, |curve: EcCurve| {
            let (public_key, private_key) = EcKeyPairSpec { curve: curve.clone() }.generate_keypair()?;
            generated_keys.push(hex::encode_upper(private_key.as_bytes()));
            Ok((public_key, private_key))
        })
        .map_err(|err| format!("PACE failed: {err}"))?;

        if !generated_keys.is_empty() {
            recorder.set_keys(generated_keys);
        }

        let transcript = recorder.into_transcript();
        transcript.write_jsonl(out).map_err(|err| format!("write transcript failed: {err}"))?;
        Ok(())
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
