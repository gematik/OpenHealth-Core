/// Base interface for cryptographic cipher operations.
pub trait Cipher {
    /// Processes the next chunk of data.
    fn update(&mut self, data: &[u8]) -> Vec<u8>;

    /// Completes the cipher operation and returns any remaining data.
    fn final_(&mut self) -> Vec<u8>;
}
