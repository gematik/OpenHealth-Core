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

use crate::ec::ec_key::{EcCurve, EcKeyPairSpec};
use crate::error::CryptoResult;
use openhealth_asn1::cv_certificate::CvCertificate;
use openhealth_asn1::extraction::extract_context_values;

/// Generates the host-side ephemeral public key for ELC GA step 2, derived from the curve in the CVC.
pub fn generate_elc_ephemeral_public_key_from_cvc(cvc: &[u8]) -> CryptoResult<Vec<u8>> {
    let certificate = CvCertificate::parse(cvc)?;
    let curve = infer_curve_from_cvc(&certificate).unwrap_or(EcCurve::BrainpoolP256r1);
    let (ephemeral_pk, _ephemeral_sk) = EcKeyPairSpec { curve }.generate_keypair()?;
    Ok(ephemeral_pk.as_bytes().to_vec())
}

fn infer_curve_from_cvc(cvc: &CvCertificate) -> Option<EcCurve> {
    let key_data = &cvc.body.public_key.key_data;
    let point = extract_context_values(key_data, 6).ok().and_then(|mut values| values.pop())?;
    match point.len() {
        65 => Some(EcCurve::BrainpoolP256r1),
        97 => Some(EcCurve::BrainpoolP384r1),
        129 => Some(EcCurve::BrainpoolP512r1),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn load_fixture(name: &str) -> Vec<u8> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.push("test-vectors");
        path.push("cvc-chain");
        path.push("pki_cvc_g2_input");
        path.push("Atos_CVC-Root-CA");
        path.push(name);
        fs::read(&path).expect("fixture should be readable")
    }

    fn expected_point_len(cvc: &CvCertificate) -> usize {
        let key_data = &cvc.body.public_key.key_data;
        let mut values = extract_context_values(key_data, 6).expect("context tag 6 present");
        values.pop().expect("public key point").len()
    }

    #[test]
    fn generate_elc_ephemeral_public_key_matches_curve_length() {
        let cvc_bytes = load_fixture("DEGXX820214.cvc");
        let certificate = CvCertificate::parse(&cvc_bytes).expect("valid CVC");

        let expected_len = expected_point_len(&certificate);
        let pk = generate_elc_ephemeral_public_key_from_cvc(&cvc_bytes).expect("key generation succeeds");

        assert_eq!(pk.len(), expected_len);
    }

    #[test]
    fn generate_elc_ephemeral_public_key_rejects_invalid_cvc() {
        let result = generate_elc_ephemeral_public_key_from_cvc(&[]);
        assert!(result.is_err());
    }
}
