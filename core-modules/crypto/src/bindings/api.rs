use std::error::Error;
use std::ffi::CStr;
use std::{fmt, ptr};
use crypto_openssl_sys::*;

/// OpenSSL error type
#[derive(Debug)]
pub struct OsslError {
    msg: String,
}

impl fmt::Display for OsslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl Error for OsslError {}

/// Retrieve and wrap the latest OpenSSL error
pub fn throw_openssl_error(msg: &str) -> OsslError {
    // Fetch error code
    let err_code = unsafe { ERR_get_error() };
    // Get human-readable string
    let err_str = if err_code != 0 {
        unsafe {
            CStr::from_ptr(ERR_error_string(err_code, ptr::null_mut()))
                .to_string_lossy()
                .into_owned()
        }
    } else {
        String::new()
    };
    OsslError { msg: format!("{}: {}", msg, err_str) }
}

/// Check return code equals 1, else error
#[macro_export]
macro_rules! ossl_check {
    ($ret:expr, $msg:expr) => {
        if $ret != 1 {
            return Err(throw_openssl_error($msg));
        }
    };
}
