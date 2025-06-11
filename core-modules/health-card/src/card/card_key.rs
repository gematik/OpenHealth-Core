/*
 * Copyright 2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::card::card_key_reference::CardKeyReference;

const MIN_KEY_ID: u8 = 2;
const MAX_KEY_ID: u8 = 28;

/// Class applies for symmetric keys and private keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardKey {
    /// The ID of the key.
    key_id: u8,
}

impl CardKey {
    /// Creates a new CardKey with the given key ID.
    ///
    /// # Arguments
    /// * `key_id` - The ID of the key.
    ///
    /// # Returns
    /// A new CardKey instance.
    ///
    /// # Panics
    /// Panics if the key ID is not in the range [2, 28].
    pub fn new(key_id: u8) -> Self {
        assert!(
            (MIN_KEY_ID..=MAX_KEY_ID).contains(&key_id),
            "Key ID out of range [{},{}]",
            MIN_KEY_ID,
            MAX_KEY_ID
        );
        Self { key_id }
    }

    /// Returns the key ID.
    pub fn get_key_id(&self) -> u8 {
        self.key_id
    }
}

impl CardKeyReference for CardKey {
    /// Calculates the key reference based on whether it's DF-specific.
    /// gemSpec_COS_3.14.0#N099.600
    ///
    /// # Arguments
    /// * `df_specific` - Indicates if the key reference is DF-specific.
    ///
    /// # Returns
    /// The calculated key reference.
    fn calculate_key_reference(&self, df_specific: bool) -> u8 {
        let mut key_reference = self.key_id;
        if df_specific {
            key_reference += Self::DF_SPECIFIC_PWD_MARKER;
        }
        key_reference
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_card_key_creation() {
        let card_key = CardKey::new(10);
        assert_eq!(card_key.get_key_id(), 10);
    }

    #[test]
    #[should_panic(expected = "Key ID out of range")]
    fn test_card_key_out_of_range_low() {
        CardKey::new(1);
    }

    #[test]
    #[should_panic(expected = "Key ID out of range")]
    fn test_card_key_out_of_range_high() {
        CardKey::new(29);
    }

    #[test]
    fn test_calculate_key_reference() {
        let card_key = CardKey::new(15);

        // Test with df_specific = false
        assert_eq!(card_key.calculate_key_reference(false), 15);

        // Test with df_specific = true
        assert_eq!(
            card_key.calculate_key_reference(true),
            15 + CardKey::DF_SPECIFIC_PWD_MARKER
        );
    }
}