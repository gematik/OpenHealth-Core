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