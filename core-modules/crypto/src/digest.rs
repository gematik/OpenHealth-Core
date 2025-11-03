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

use crate::error::CryptoResult;
use crate::ossl;
use crate::utils::byte_unit::ByteUnit;

/// Supported hash algorithms (and XOFs) for streaming digests.
#[derive(Clone)]
pub enum DigestSpec {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_512,
    Blake2b512,
    /// SHAKE128 with caller-specified output length (in bytes).
    Shake128 {
        output_length: ByteUnit,
    },
    /// SHAKE256 with caller-specified output length (in bytes).
    Shake256 {
        output_length: ByteUnit,
    },
}

impl DigestSpec {
    fn algorithm(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_512 => "SHA3-512",
            Self::Blake2b512 => "BLAKE2b512",
            Self::Shake128 { .. } => "SHAKE128",
            Self::Shake256 { .. } => "SHAKE256",
        }
    }

    fn xof_output_len(&self) -> Option<usize> {
        match self {
            Self::Shake128 { output_length } | Self::Shake256 { output_length } => Some(output_length.bytes() as usize),
            _ => None,
        }
    }

    /// Create a new streaming digest for this algorithm.
    pub fn create(self) -> CryptoResult<Digest> {
        let digest = ossl::digest::Digest::create(self.algorithm())?;
        Ok(Digest { digest, spec: self })
    }
}

/// Streaming digest computation.
///
/// - Feed data with `update`.
/// - Call `finalize` to get the digest (or XOF) output.
pub struct Digest {
    digest: ossl::digest::Digest,
    spec: DigestSpec,
}

impl Digest {
    /// Feed more message bytes into the digest.
    pub fn update(&mut self, input: &[u8]) -> CryptoResult<()> {
        self.digest.update(input).map_err(Into::into)
    }

    /// Finalize and return the digest/XOF output.
    /// For SHAKE, the output length is taken from the `DigestSpec`.
    pub fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        let output_len = self.spec.xof_output_len().unwrap_or(0);
        self.digest.finalize(output_len).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::byte_unit::BytesExt;
    use crate::utils::test_utils::{hex_to_bytes, to_hex_string};

    fn digest_hex(spec: DigestSpec, msg: &[u8]) -> String {
        let mut d = spec.create().unwrap();
        d.update(msg).unwrap();
        let out = d.finalize().unwrap();
        to_hex_string(&out)
    }

    #[test]
    fn sha1_abc() {
        // NIST FIPS 180-4
        let expected =
            "A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D";
        let got = digest_hex(DigestSpec::Sha1, b"abc");
        assert_eq!(got, expected);
    }

    #[test]
    fn sha256_abc() {
        // NIST FIPS 180-4
        let expected =
            "BA 78 16 BF 8F 01 CF EA 41 41 40 DE 5D AE 22 23 B0 03 61 A3 96 17 7A 9C B4 10 FF 61 F2 00 15 AD";
        let got = digest_hex(DigestSpec::Sha256, b"abc");
        assert_eq!(got, expected);
    }

    #[test]
    fn sha384_abc() {
        // NIST FIPS 180-4
        let expected = "CB 00 75 3F 45 A3 5E 8B B5 A0 3D 69 9A C6 50 07 27 2C 32 AB 0E DE D1 63 1A 8B 60 5A 43 FF 5B ED 80 86 07 2B A1 E7 CC 23 58 BA EC A1 34 C8 25 A7";
        let got = digest_hex(DigestSpec::Sha384, b"abc");
        assert_eq!(got, expected);
    }

    #[test]
    fn sha512_abc() {
        // NIST FIPS 180-4
        let expected = "DD AF 35 A1 93 61 7A BA CC 41 73 49 AE 20 41 31 12 E6 FA 4E 89 A9 7E A2 0A 9E EE E6 4B 55 D3 9A 21 92 99 2A 27 4F C1 A8 36 BA 3C 23 A3 FE EB BD 45 4D 44 23 64 3C E8 0E 2A 9A C9 4F A5 4C A4 9F";
        let got = digest_hex(DigestSpec::Sha512, b"abc");
        assert_eq!(got, expected);
    }

    #[test]
    fn sha3_256_abc() {
        // NIST FIPS 202
        let expected =
            "3A 98 5D A7 4F E2 25 B2 04 5C 17 2D 6B D3 90 BD 85 5F 08 6E 3E 9D 52 5B 46 BF E2 45 11 43 15 32";
        let got = digest_hex(DigestSpec::Sha3_256, b"abc");
        assert_eq!(got, expected);
    }

    #[test]
    fn sha3_512_abc() {
        // NIST FIPS 202
        let expected = "B7 51 85 0B 1A 57 16 8A 56 93 CD 92 4B 6B 09 6E 08 F6 21 82 74 44 F7 0D 88 4F 5D 02 40 D2 71 2E 10 E1 16 E9 19 2A F3 C9 1A 7E C5 76 47 E3 93 40 57 34 0B 4C F4 08 D5 A5 65 92 F8 27 4E EC 53 F0";
        let got = digest_hex(DigestSpec::Sha3_512, b"abc");
        assert_eq!(got, expected);
    }

    #[test]
    fn blake2b_512_abc() {
        // RFC 7693
        let expected = "BA 80 A5 3F 98 1C 4D 0D 6A 27 97 B6 9F 12 F6 E9 4C 21 2F 14 68 5A C4 B7 4B 12 BB 6F DB FF A2 D1 7D 87 C5 39 2A AB 79 2D C2 52 D5 DE 45 33 CC 95 18 D3 8A A8 DB F1 92 5A B9 23 86 ED D4 00 99 23";
        let got = digest_hex(DigestSpec::Blake2b512, b"abc");
        assert_eq!(got, expected);
    }

    #[test]
    fn shake128_empty_32_bytes() {
        // NIST FIPS 202 - SHAKE128("", 256 bits) -> 32 bytes
        let expected =
            "7F 9C 2B A4 E8 8F 82 7D 61 60 45 50 76 05 85 3E D7 3B 80 93 F6 EF BC 88 EB 1A 6E AC FA 66 EF 26";
        let spec = DigestSpec::Shake128 { output_length: 32.bytes() };
        let got = digest_hex(spec, b"");
        assert_eq!(got, expected);
    }

    #[test]
    fn shake256_empty_64_bytes() {
        // NIST FIPS 202 - SHAKE256("", 512 bits) -> 64 bytes
        let expected = "46 B9 DD 2B 0B A8 8D 13 23 3B 3F EB 74 3E EB 24 3F CD 52 EA 62 B8 1B 82 B5 0C 27 64 6E D5 76 2F D7 5D C4 DD D8 C0 F2 00 CB 05 01 9D 67 B5 92 F6 FC 82 1C 49 47 9A B4 86 40 29 2E AC B3 B7 C4 BE";
        let spec = DigestSpec::Shake256 { output_length: 64.bytes() };
        let got = digest_hex(spec, b"");
        assert_eq!(got, expected);
    }
}
