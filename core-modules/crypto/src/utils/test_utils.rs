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

pub fn hex_to_bytes(s: &str) -> Vec<u8> {
    s.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

pub(crate) trait ResultTestExt<E> {
    fn expect_err_no_debug(self, msg: &str) -> E;
}

impl<T, E> ResultTestExt<E> for Result<T, E> {
    fn expect_err_no_debug(self, msg: &str) -> E {
        match self {
            Ok(_) => panic!("{msg}"),
            Err(err) => err,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_conversion_roundtrip() {
        let hex = "0A 0B 0C";
        let bytes = hex_to_bytes(hex);
        assert_eq!(bytes, vec![0x0A, 0x0B, 0x0C]);
        assert_eq!(to_hex_string(&bytes), hex);
    }

    #[test]
    fn expect_err_no_debug_returns_err() {
        let result: Result<(), u32> = Err(7);
        assert_eq!(result.expect_err_no_debug("expected err"), 7);
    }
}
