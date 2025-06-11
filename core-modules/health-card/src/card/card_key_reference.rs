/// Trait for objects that can serve as references to keys on a card.
pub trait CardKeyReference {
    /// Marker for DF-specific password references
    const DF_SPECIFIC_PWD_MARKER: u8 = 0x80;

    /// Calculates the key reference based on whether it's DF-specific.
    ///
    /// # Arguments
    /// * `df_specific` - Indicates if the key reference is DF-specific.
    ///
    /// # Returns
    /// The calculated key reference.
    fn calculate_key_reference(&self, df_specific: bool) -> u8;
}