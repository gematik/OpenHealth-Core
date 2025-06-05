use std::ffi::{CStr, CString};
use std::os::raw::c_char;

fn c_str_to_string(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("Null pointer provided".to_string());
    }

    unsafe {
        match CStr::from_ptr(ptr).to_str() {
            Ok(s) => Ok(s.to_string()),
            Err(_) => Err("Invalid UTF-8 in input".to_string()),
        }
    }
}

#[no_mangle]
pub extern "C" fn crypto_openssl_sha256(data: *const c_char) -> *mut c_char {
    let data_str = match c_str_to_string(data) {
        Ok(s) => s,
        Err(e) => return CString::new(e).unwrap().into_raw(),
    };


    let hash_result = format!("sha256:{}", data_str);

    match CString::new(hash_result) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => CString::new("Error creating C string").unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "C" fn crypto_openssl_aes_encrypt(
    data: *const c_char,
    key: *const c_char,
    iv: *const c_char
) -> *mut c_char {
    let data_str = match c_str_to_string(data) {
        Ok(s) => s,
        Err(e) => return CString::new(e).unwrap().into_raw(),
    };

    let key_str = match c_str_to_string(key) {
        Ok(s) => s,
        Err(e) => return CString::new(e).unwrap().into_raw(),
    };

    let iv_str = match c_str_to_string(iv) {
        Ok(s) => s,
        Err(e) => return CString::new(e).unwrap().into_raw(),
    };

    let encrypted = format!("encrypted:{}:{}:{}", data_str, key_str, iv_str); // Platzhalter

    match CString::new(encrypted) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => CString::new("Error creating C string").unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "C" fn crypto_openssl_aes_decrypt(
    encrypted_data: *const c_char,
    key: *const c_char,
    iv: *const c_char
) -> *mut c_char {
    let encrypted_str = match c_str_to_string(encrypted_data) {
        Ok(s) => s,
        Err(e) => return CString::new(e).unwrap().into_raw(),
    };

    let key_str = match c_str_to_string(key) {
        Ok(s) => s,
        Err(e) => return CString::new(e).unwrap().into_raw(),
    };

    let iv_str = match c_str_to_string(iv) {
        Ok(s) => s,
        Err(e) => return CString::new(e).unwrap().into_raw(),
    };

    let decrypted = format!("decrypted:{}:{}:{}", encrypted_str, key_str, iv_str);

    match CString::new(decrypted) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => CString::new("Error creating C string").unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "C" fn crypto_openssl_rsa_sign(
    data: *const c_char,
    private_key: *const c_char
) -> *mut c_char {
    let data_str = match c_str_to_string(data) {
        Ok(s) => s,
        Err(e) => return CString::new(e).unwrap().into_raw(),
    };

    let key_str = match c_str_to_string(private_key) {
        Ok(s) => s,
        Err(e) => return CString::new(e).unwrap().into_raw(),
    };

    let signature = format!("signature:{}:{}", data_str, key_str);

    match CString::new(signature) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => CString::new("Error creating C string").unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "C" fn crypto_openssl_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn crypto_openssl_get_last_error() -> *mut c_char {
    CString::new("No error information available").unwrap().into_raw()
}