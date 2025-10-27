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

/// Represents a specific PSO (Perform Security Operation) Algorithm
///
/// ISO/IEC7816-4
/// gemSpec_COS_3.14.0#14.8 PSO Algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsoAlgorithm {
    /// Algorithm for ECDSA sign/verify operations
    SignVerifyEcdsa,
}

impl PsoAlgorithm {
    /// Returns the identifier value for this algorithm
    pub fn identifier(&self) -> u8 {
        match self {
            PsoAlgorithm::SignVerifyEcdsa => 0x00,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pso_algorithm_identifier() {
        assert_eq!(PsoAlgorithm::SignVerifyEcdsa.identifier(), 0x00);
    }
}
