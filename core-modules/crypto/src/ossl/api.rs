use std::error;
use std::ffi::CStr;
use std::{fmt, ptr};
use crypto_openssl_sys::*;

/// OpenSSL error type
#[derive(Debug)]
pub struct OsslError(pub String);

impl error::Error for OsslError {}

impl fmt::Display for OsslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Retrieve and wrap the latest OpenSSL error
pub fn openssl_error(msg: &str) -> OsslError {
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
            return Err(openssl_error($msg));
        }
    };
}

/// Common result type for OpenSSL operations
pub type OsslResult<T> = Result<T, OsslError>;