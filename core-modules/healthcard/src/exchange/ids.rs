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

//! Helper constructors for well-known file identifiers on the eGK.

use crate::card::card_key::CardKey;
use crate::card::password_reference::PasswordReference;
use crate::identifier::{ApplicationIdentifier, FileIdentifier, ShortFileIdentifier};

fn application_identifier(bytes: &[u8]) -> ApplicationIdentifier {
    ApplicationIdentifier::new(bytes.to_vec()).expect("constant application identifier must be valid")
}

fn file_identifier(fid: u16) -> FileIdentifier {
    FileIdentifier::new(fid).expect("constant file identifier must be valid")
}

fn short_file_identifier(value: u8) -> ShortFileIdentifier {
    ShortFileIdentifier::new(value).expect("constant short file identifier must be valid")
}

/// AID for `DF.HCA` (gemSpec_ObjSys Section 5.4).
pub fn df_hca_aid() -> ApplicationIdentifier {
    application_identifier(&[0xD2, 0x76, 0x00, 0x00, 0x01, 0x02])
}

/// AID for `DF.ESIGN` (gemSpec_ObjSys Section 5.5).
pub fn df_esign_aid() -> ApplicationIdentifier {
    application_identifier(&[0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E])
}

/// File identifier of `MF/EF.CardAccess` (gemSpec_ObjSys Section 5.3.2).
pub fn ef_card_access_fid() -> FileIdentifier {
    file_identifier(0x011C)
}

/// Short file identifier of `MF/EF.CardAccess` (gemSpec_ObjSys Section 5.3.2).
pub fn ef_card_access_sfid() -> ShortFileIdentifier {
    short_file_identifier(0x1C)
}

/// File identifier of `MF/EF.Version2` (gemSpec_ObjSys Section 5.3.8).
pub fn ef_version2_fid() -> FileIdentifier {
    file_identifier(0x2F11)
}

/// Short file identifier for `MF/EF.Version2` (gemSpec_ObjSys Section 5.3.8).
pub fn ef_version2_sfid() -> ShortFileIdentifier {
    short_file_identifier(0x11)
}

/// File identifier for `DF.HCA/EF.PD` (gemSpec_ObjSys Section 5.4.4).
pub fn ef_pd_fid() -> FileIdentifier {
    file_identifier(0xD001)
}

/// Short file identifier for `DF.HCA/EF.PD` (gemSpec_ObjSys Section 5.4.4).
pub fn ef_pd_sfid() -> ShortFileIdentifier {
    short_file_identifier(0x01)
}

/// File identifier for `DF.HCA/EF.VD` (gemSpec_ObjSys Section 5.4.9).
pub fn ef_vd_fid() -> FileIdentifier {
    file_identifier(0xD002)
}

/// File identifier for `DF.HCA/EF.StatusVD` (gemSpec_ObjSys Section 5.4.7).
pub fn ef_status_vd_fid() -> FileIdentifier {
    file_identifier(0xD00C)
}

/// Short file identifier for `DF.HCA/EF.StatusVD` (gemSpec_ObjSys Section 5.4.7).
pub fn ef_status_vd_sfid() -> ShortFileIdentifier {
    short_file_identifier(0x0C)
}

/// File identifier for `DF.ESIGN/EF.C.CH.AUT.E256` (gemSpec_ObjSys Section 5.5.9).
pub fn ef_cch_aut_e256_fid() -> FileIdentifier {
    file_identifier(0xC504)
}

/// Short file identifier for `DF.ESIGN/EF.C.CH.AUT.E256` (gemSpec_ObjSys Section 5.5.9).
pub fn ef_cch_aut_e256_sfid() -> ShortFileIdentifier {
    short_file_identifier(0x04)
}

/// Key identifier for the `PrK.CH.AUT.E256` private key in `DF.ESIGN`.
pub fn prk_ch_aut_e256() -> CardKey {
    CardKey::new(0x04).expect("constant key id must be valid")
}

/// Password reference for "MRPIN.home" stored in the master file (gemSpec_ObjSys Section 5.3.10).
pub fn mr_pin_home_reference() -> PasswordReference {
    PasswordReference::new(0x02).expect("constant password id must be valid")
}

/// Secret key reference used during PACE (CAN key).
pub const SECRET_KEY_REFERENCE: u8 = 0x02;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_identifiers_match_expected_values() {
        assert_eq!(df_hca_aid().as_bytes(), &[0xD2, 0x76, 0x00, 0x00, 0x01, 0x02]);
        assert_eq!(df_esign_aid().as_bytes(), &[0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E]);

        assert_eq!(ef_card_access_fid().to_bytes(), [0x01, 0x1C]);
        assert_eq!(ef_card_access_sfid().value(), 0x1C);
        assert_eq!(ef_version2_fid().to_bytes(), [0x2F, 0x11]);
        assert_eq!(ef_version2_sfid().value(), 0x11);
        assert_eq!(ef_pd_fid().to_bytes(), [0xD0, 0x01]);
        assert_eq!(ef_pd_sfid().value(), 0x01);
        assert_eq!(ef_vd_fid().to_bytes(), [0xD0, 0x02]);
        assert_eq!(ef_status_vd_fid().to_bytes(), [0xD0, 0x0C]);
        assert_eq!(ef_status_vd_sfid().value(), 0x0C);
        assert_eq!(ef_cch_aut_e256_fid().to_bytes(), [0xC5, 0x04]);
        assert_eq!(ef_cch_aut_e256_sfid().value(), 0x04);

        assert_eq!(prk_ch_aut_e256().key_id(), 0x04);
        assert_eq!(mr_pin_home_reference().pwd_id(), 0x02);
        assert_eq!(SECRET_KEY_REFERENCE, 0x02);
    }
}
