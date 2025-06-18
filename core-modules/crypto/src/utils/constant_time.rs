/// Constant time equals for byte arrays.
pub fn content_constant_time_equals(a: &[u8], b: &[u8]) -> bool {
    native_constant_time_equals(a, b)
}

/// Constant time equals for byte arrays.
fn native_constant_time_equals(array_a: &[u8], array_b: &[u8]) -> bool {
    unimplemented!()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_arrays_should_return_true() {
        let array1 = [1u8, 2, 3, 4, 5];
        let array2 = [1u8, 2, 3, 4, 5];

        assert!(content_constant_time_equals(&array1, &array2));
    }

    #[test]
    fn different_arrays_should_return_false() {
        let array1 = [1u8, 2, 3, 4, 5];
        let array2 = [1u8, 2, 3, 4, 6];

        assert!(!content_constant_time_equals(&array1, &array2));
    }

    #[test]
    fn arrays_of_different_length_should_return_false() {
        let array1 = [1u8, 2, 3, 4, 5];
        let array2 = [1u8, 2, 3, 4];

        assert!(!content_constant_time_equals(&array1, &array2));
    }

    #[test]
    fn empty_arrays_should_return_true() {
        let array1: [u8; 0] = [];
        let array2: [u8; 0] = [];

        assert!(content_constant_time_equals(&array1, &array2));
    }

    #[test]
    fn same_array_reference_should_return_true() {
        let array = [1u8, 2, 3];

        assert!(content_constant_time_equals(&array, &array));
    }
}