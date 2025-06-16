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