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
        use healthcard::exchange::apdu_tools::{FixedKeyGenerator, PcscChannel, RecordingChannel};
        use healthcard::exchange::secure_channel::{establish_secure_channel, establish_secure_channel_with, CardAccessNumber};

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
        /// Fixed private key(s) for deterministic PACE (hex, big endian). Can be passed multiple times.
        #[arg(long, value_name = "HEX", num_args(1..))]
        fixed_key: Vec<String>,
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

        let channel =
            PcscChannel::connect(&reader, supports_extended_length).map_err(|err| format!("pcsc connect failed: {err}"))?;
        let mut recorder = RecordingChannel::new(channel);
        let card_access_number = CardAccessNumber::new(&can).map_err(|err| err.to_string())?;

        let fixed_keys = if args.fixed_key.is_empty() {
            None
        } else {
            Some(
                args.fixed_key
                    .iter()
                    .map(|k| hex::decode(k).map_err(|err| format!("invalid --fixed-key hex: {err}")))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        };

        match fixed_keys {
            Some(keys) => {
                let generator = FixedKeyGenerator::new(keys).generator();
                establish_secure_channel_with(&mut recorder, &card_access_number, generator)
            }
            None => establish_secure_channel(&mut recorder, &card_access_number),
        }
        .map_err(|err| format!("PACE failed: {err}"))?;

        let transcript = recorder.into_transcript();
        transcript.write_jsonl(out).map_err(|err| format!("write transcript failed: {err}"))?;
        Ok(())
    }

    fn list_pcsc_readers() -> Result<(), String> {
        let ctx =
            pcsc::Context::establish(pcsc::Scope::User).map_err(|err| format!("pcsc context establish failed: {err}"))?;
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
