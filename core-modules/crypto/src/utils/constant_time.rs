/// Constant time equals for byte arrays.
pub fn content_constant_time_equals(a: &[u8], b: &[u8]) -> bool {
    native_constant_time_equals(a, b)
}

/// Constant time equals for byte arrays.
fn native_constant_time_equals(array_a: &[u8], array_b: &[u8]) -> bool {
    unimplemented!()
}
