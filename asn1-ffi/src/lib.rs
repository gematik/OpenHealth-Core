use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use asn1_core::{Asn1UtcTime, Asn1GeneralizedTime};

#[no_mangle]
pub extern "C" fn asn1_generalized_time_parse(input: *const c_char) -> *mut c_char {
    let c_str = unsafe {
        if input.is_null() {
            return std::ptr::null_mut();
        }
        CStr::from_ptr(input)
    };

    let input_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match Asn1GeneralizedTime::parse(input_str) {
        Ok(time) => {
            let result = format!("{:?}", time);
            match CString::new(result) {
                Ok(c_string) => c_string.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn asn1_utc_time_parse(input: *const c_char) -> *mut c_char {
    let c_str = unsafe {
        if input.is_null() {
            return std::ptr::null_mut();
        }
        CStr::from_ptr(input)
    };

    let input_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match Asn1UtcTime::parse(input_str) {
        Ok(time) => {
            let result = time.format();
            match CString::new(result) {
                Ok(c_string) => c_string.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_generalized_time_is_valid(input: *const c_char) -> i32 {
    let c_str = unsafe {
        if input.is_null() {
            return 0;
        }
        CStr::from_ptr(input)
    };

    let input_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    match Asn1GeneralizedTime::parse(input_str) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn asn1_utc_time_is_valid(input: *const c_char) -> i32 {
    let c_str = unsafe {
        if input.is_null() {
            return 0;
        }
        CStr::from_ptr(input)
    };

    let input_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    match Asn1UtcTime::parse(input_str) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn asn1_generalized_time_get_error(input: *const c_char) -> *mut c_char {
    let c_str = unsafe {
        if input.is_null() {
            return CString::new("Null input provided").unwrap().into_raw();
        }
        CStr::from_ptr(input)
    };

    let input_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return CString::new("Invalid UTF-8 in input").unwrap().into_raw(),
    };

    match Asn1GeneralizedTime::parse(input_str) {
        Ok(_) => std::ptr::null_mut(),
        Err(e) => match CString::new(e) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => CString::new("Error message contains invalid C string data").unwrap().into_raw(),
        },
    }
}

#[no_mangle]
pub extern "C" fn asn1_utc_time_get_error(input: *const c_char) -> *mut c_char {
    let c_str = unsafe {
        if input.is_null() {
            return CString::new("Null input provided").unwrap().into_raw();
        }
        CStr::from_ptr(input)
    };

    let input_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return CString::new("Invalid UTF-8 in input").unwrap().into_raw(),
    };

    match Asn1UtcTime::parse(input_str) {
        Ok(_) => std::ptr::null_mut(),
        Err(e) => match CString::new(e) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => CString::new("Error message contains invalid C string data").unwrap().into_raw(),
        },
    }
}