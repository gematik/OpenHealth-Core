use crate::utils::constant_time::content_constant_time_equals;

/// Supported Key Encapsulation Mechanism algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KemAlgorithm {
    MlKem768,
    Kyber768,
}

/// Result of a KEM encapsulation operation containing the shared secret and wrapped key.
#[derive(Debug, Clone)]
pub struct KemEncapsulationResult {
    pub shared_secret: Vec<u8>,
    pub wrapped_key: Vec<u8>,
}

impl PartialEq for KemEncapsulationResult {
    fn eq(&self, other: &Self) -> bool {
        content_constant_time_equals(&self.shared_secret, &other.shared_secret)
            && content_constant_time_equals(&self.wrapped_key, &other.wrapped_key)
    }
}

impl Eq for KemEncapsulationResult {}

impl std::hash::Hash for KemEncapsulationResult {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Replace with a constant-time hash if needed
        self.shared_secret.hash(state);
        self.wrapped_key.hash(state);
    }
}

/// Result of a KEM decapsulation operation containing the shared secret.
#[derive(Debug, Clone)]
pub struct KemDecapsulationResult {
    pub shared_secret: Vec<u8>,
}

impl KemDecapsulationResult {
    /// Returns `true` if both secrets are equal.
    pub fn is_valid(&self, encapsulation: &KemEncapsulationResult) -> bool {
        !self.shared_secret.is_empty()
            && !encapsulation.shared_secret.is_empty()
            && content_constant_time_equals(&self.shared_secret, &encapsulation.shared_secret)
    }
}

impl PartialEq for KemDecapsulationResult {
    fn eq(&self, other: &Self) -> bool {
        content_constant_time_equals(&self.shared_secret, &other.shared_secret)
    }
}

impl Eq for KemDecapsulationResult {}

impl std::hash::Hash for KemDecapsulationResult {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Replace with a constant-time hash if needed
        self.shared_secret.hash(state);
    }
}

/// Interface for KEM encapsulation operations.
pub trait KemEncapsulation {
    fn spec(&self) -> &KemSpec;

    /// Encapsulates a key and returns the shared secret and wrapped key.
    fn encapsulate(&self) -> KemEncapsulationResult;
}

/// Interface for KEM decapsulation operations.
pub trait KemDecapsulation {
    fn spec(&self) -> &KemSpec;

    /// Returns the encapsulation key.
    fn encapsulation_key(&self) -> Vec<u8>;

    /// Decapsulates the wrapped key and returns the shared secret.
    fn decapsulate(&self, wrapped_key: &[u8]) -> KemDecapsulationResult;
}

/// Specification for KEM operations.
#[derive(Debug, Clone)]
pub struct KemSpec {
    pub algorithm: KemAlgorithm,
}

impl KemSpec {
    pub fn new(algorithm: KemAlgorithm) -> Self {
        Self { algorithm }
    }
}

/// Creates a native KEM encapsulation instance.
pub(crate) fn native_create_encapsulation(
    spec: &KemSpec,
    encapsulation_key: &[u8],
) -> Box<dyn KemEncapsulation> {
    unimplemented!()
}

/// Creates a native KEM decapsulation instance.
pub(crate) fn native_create_decapsulation(
    spec: &KemSpec,
) -> Box<dyn KemDecapsulation> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec1() -> Vec<u8> { vec![1, 2, 3] }
    fn vec2() -> Vec<u8> { vec![1, 2, 3] }
    fn vec3() -> Vec<u8> { vec![4, 5, 6] }
    fn wrap1() -> Vec<u8> { vec![7, 8, 9] }
    fn wrap2() -> Vec<u8> { vec![7, 8, 9] }
    fn wrap3() -> Vec<u8> { vec![10, 11, 12] }

    #[test]
    fn kem_encapsulation_result_equality() {
        let result1 = KemEncapsulationResult { shared_secret: vec1(), wrapped_key: wrap1() };
        let result2 = KemEncapsulationResult { shared_secret: vec2(), wrapped_key: wrap2() };
        let result3 = KemEncapsulationResult { shared_secret: vec3(), wrapped_key: wrap1() };
        let result4 = KemEncapsulationResult { shared_secret: vec1(), wrapped_key: wrap3() };

        assert_eq!(result1, result2);
        assert_ne!(result1, result3);
        assert_ne!(result1, result4);
    }

    #[test]
    fn kem_decapsulation_result_equality() {
        let result1 = KemDecapsulationResult { shared_secret: vec1() };
        let result2 = KemDecapsulationResult { shared_secret: vec2() };
        let result3 = KemDecapsulationResult { shared_secret: vec3() };

        assert_eq!(result1, result2);
        assert_ne!(result1, result3);
    }

    #[test]
    fn kem_decapsulation_is_valid_compares_shared_secret() {
        let decap = KemDecapsulationResult { shared_secret: vec1() };
        let encap1 = KemEncapsulationResult { shared_secret: vec2(), wrapped_key: wrap1() };
        let encap2 = KemEncapsulationResult { shared_secret: vec3(), wrapped_key: wrap1() };

        assert!(decap.is_valid(&encap1));
        assert!(!decap.is_valid(&encap2));
    }

    #[test]
    fn kem_encapsulation_reference_equality() {
        let result = KemEncapsulationResult { shared_secret: vec1(), wrapped_key: wrap1() };
        let result2 = KemEncapsulationResult { shared_secret: vec1(), wrapped_key: wrap1() };
        assert_eq!(result, result);
        assert_eq!(result, result2);
    }

    #[test]
    fn kem_encapsulation_hash_code_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let result1 = KemEncapsulationResult { shared_secret: vec1(), wrapped_key: wrap1() };
        let result2 = KemEncapsulationResult { shared_secret: vec1(), wrapped_key: wrap1() };

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        result1.hash(&mut hasher1);
        result2.hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn kem_decapsulation_reference_equality() {
        let result = KemDecapsulationResult { shared_secret: vec1() };
        assert_eq!(result, result); // Same instance
    }

    #[test]
    fn kem_decapsulation_hash_code_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let result1 = KemDecapsulationResult { shared_secret: vec1() };
        let result2 = KemDecapsulationResult { shared_secret: vec1() };

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        result1.hash(&mut hasher1);
        result2.hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn kem_decapsulation_is_valid_with_empty_secret() {
        let decap = KemDecapsulationResult { shared_secret: vec![] };
        let encap = KemEncapsulationResult { shared_secret: vec1(), wrapped_key: wrap1() };
        assert!(!decap.is_valid(&encap));

        let decap2 = KemDecapsulationResult { shared_secret: vec1() };
        let encap2 = KemEncapsulationResult { shared_secret: vec![], wrapped_key: wrap1() };
        assert!(!decap2.is_valid(&encap2));
    }
}