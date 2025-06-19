use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::slice;

use asn1::{
    Asn1Encoder, Asn1Decoder, Asn1Tag,
    Asn1UtcTime, Asn1GeneralizedTime,
    read_boolean, read_int, read_bit_string, read_octet_string,
    read_utf8_string, read_visible_string, read_object_identifier,
    write_boolean, write_int, write_bit_string,
    write_octet_string, write_utf8_string,
    write_object_identifier, tag_class, asn1_type
};

// ============================================================================
// Type Definitions
// ============================================================================

/// Opaque handle for Asn1Encoder
#[repr(C)]
pub struct Asn1EncoderHandle {
    _private: [u8; 0],
}

/// Opaque handle for Asn1Decoder
#[repr(C)]
pub struct Asn1DecoderHandle {
    _private: [u8; 0],
}

/// Opaque handle for Asn1Tag
#[repr(C)]
pub struct Asn1TagHandle {
    _private: [u8; 0],
}

/// Opaque handle for Asn1UtcTime
#[repr(C)]
pub struct Asn1UtcTimeHandle {
    _private: [u8; 0],
}

/// Opaque handle for Asn1GeneralizedTime
#[repr(C)]
pub struct Asn1GeneralizedTimeHandle {
    _private: [u8; 0],
}

/// FFI-safe byte buffer
#[repr(C)]
pub struct ByteBuffer {
    pub data: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

impl ByteBuffer {
    fn from_vec(mut vec: Vec<u8>) -> Self {
        let data = vec.as_mut_ptr();
        let len = vec.len();
        let capacity = vec.capacity();
        std::mem::forget(vec);
        ByteBuffer { data, len, capacity }
    }

    unsafe fn into_vec(self) -> Vec<u8> {
        Vec::from_raw_parts(self.data, self.len, self.capacity)
    }
}

// ============================================================================
// Error Handling
// ============================================================================

#[no_mangle]
pub extern "C" fn asn1_get_last_error() -> *const c_char {
    ptr::null()
}

// ============================================================================
// Asn1Encoder FFI Functions
// ============================================================================

#[no_mangle]
pub extern "C" fn asn1_encoder_new() -> *mut Asn1EncoderHandle {
    let encoder = Box::new(Asn1Encoder::new());
    Box::into_raw(encoder) as *mut Asn1EncoderHandle
}

#[no_mangle]
pub extern "C" fn asn1_encoder_free(encoder: *mut Asn1EncoderHandle) {
    if !encoder.is_null() {
        unsafe {
            let _ = Box::from_raw(encoder as *mut Asn1Encoder);
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_encoder_get_buffer(encoder: *const Asn1EncoderHandle) -> ByteBuffer {
    if encoder.is_null() {
        return ByteBuffer { data: ptr::null_mut(), len: 0, capacity: 0 };
    }

    unsafe {
        let encoder = &*(encoder as *const Asn1Encoder);
        let buffer = encoder.get_buffer();
        let mut vec = buffer.to_vec();
        ByteBuffer::from_vec(vec)
    }
}

#[no_mangle]
pub extern "C" fn asn1_encoder_clear(encoder: *mut Asn1EncoderHandle) {
    if encoder.is_null() {
        return;
    }

    unsafe {
        let encoder = &mut *(encoder as *mut Asn1Encoder);
        encoder.clear();
    }
}

#[no_mangle]
pub extern "C" fn asn1_encoder_write_byte(encoder: *mut Asn1EncoderHandle, byte: u8) {
    if encoder.is_null() {
        return;
    }

    unsafe {
        let encoder = &mut *(encoder as *mut Asn1Encoder);
        encoder.write_byte(byte);
    }
}

#[no_mangle]
pub extern "C" fn asn1_encoder_write_bytes(
    encoder: *mut Asn1EncoderHandle,
    bytes: *const u8,
    len: usize
) {
    if encoder.is_null() || bytes.is_null() {
        return;
    }

    unsafe {
        let encoder = &mut *(encoder as *mut Asn1Encoder);
        let data = slice::from_raw_parts(bytes, len);
        encoder.write_bytes(data);
    }
}

#[no_mangle]
pub extern "C" fn asn1_encoder_write_int(encoder: *mut Asn1EncoderHandle, value: i32) {
    if encoder.is_null() {
        return;
    }

    unsafe {
        let encoder = &mut *(encoder as *mut Asn1Encoder);
        encoder.write_int(value);
    }
}

#[no_mangle]
pub extern "C" fn asn1_encoder_write_length(
    encoder: *mut Asn1EncoderHandle,
    length: usize
) -> c_int {
    if encoder.is_null() {
        return -1;
    }

    unsafe {
        let encoder = &mut *(encoder as *mut Asn1Encoder);
        match encoder.write_length(length) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_encoder_write_tag(
    encoder: *mut Asn1EncoderHandle,
    tag_number: u8,
    tag_class: u8
) -> c_int {
    if encoder.is_null() {
        return -1;
    }

    unsafe {
        let encoder = &mut *(encoder as *mut Asn1Encoder);
        match encoder.write_tag(tag_number, tag_class) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    }
}

// ============================================================================
// ASN.1 Write Functions
// ============================================================================

#[no_mangle]
pub extern "C" fn asn1_write_boolean(encoder: *mut Asn1EncoderHandle, value: bool) -> c_int {
    if encoder.is_null() {
        return -1;
    }

    unsafe {
        let encoder = &mut *(encoder as *mut Asn1Encoder);
        match write_boolean(encoder, value) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_write_int(encoder: *mut Asn1EncoderHandle, value: i32) -> c_int {
    if encoder.is_null() {
        return -1;
    }

    unsafe {
        let encoder = &mut *(encoder as *mut Asn1Encoder);
        match write_int(encoder, value) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_write_bit_string(
    encoder: *mut Asn1EncoderHandle,
    value: *const u8,
    len: usize,
    unused_bits: u8
) -> c_int {
    if encoder.is_null() || value.is_null() {
        return -1;
    }

    unsafe {
        let encoder = &mut *(encoder as *mut Asn1Encoder);
        let data = slice::from_raw_parts(value, len);
        match write_bit_string(encoder, data, unused_bits) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_write_octet_string(
    encoder: *mut Asn1EncoderHandle,
    value: *const u8,
    len: usize
) -> c_int {
    if encoder.is_null() || value.is_null() {
        return -1;
    }

    unsafe {
        let encoder = &mut *(encoder as *mut Asn1Encoder);
        let data = slice::from_raw_parts(value, len);
        match write_octet_string(encoder, data) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_write_utf8_string(
    encoder: *mut Asn1EncoderHandle,
    value: *const c_char
) -> c_int {
    if encoder.is_null() || value.is_null() {
        return -1;
    }

    unsafe {
        let encoder = &mut *(encoder as *mut Asn1Encoder);
        let c_str = CStr::from_ptr(value);
        if let Ok(string) = c_str.to_str() {
            match write_utf8_string(encoder, string) {
                Ok(()) => 0,
                Err(_) => -1,
            }
        } else {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_write_object_identifier(
    encoder: *mut Asn1EncoderHandle,
    oid: *const c_char
) -> c_int {
    if encoder.is_null() || oid.is_null() {
        return -1;
    }

    unsafe {
        let encoder = &mut *(encoder as *mut Asn1Encoder);
        let c_str = CStr::from_ptr(oid);
        if let Ok(oid_string) = c_str.to_str() {
            match write_object_identifier(encoder, oid_string) {
                Ok(()) => 0,
                Err(_) => -1,
            }
        } else {
            -1
        }
    }
}

// ============================================================================
// Asn1Decoder FFI Functions
// ============================================================================

#[no_mangle]
pub extern "C" fn asn1_decoder_new(data: *const u8, len: usize) -> *mut Asn1DecoderHandle {
    if data.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let slice = slice::from_raw_parts(data, len);
        match Asn1Decoder::new(slice) {
            Ok(decoder) => Box::into_raw(Box::new(decoder)) as *mut Asn1DecoderHandle,
            Err(_) => ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_decoder_free(decoder: *mut Asn1DecoderHandle) {
    if !decoder.is_null() {
        unsafe {
            let _ = Box::from_raw(decoder as *mut Asn1Decoder);
        }
    }
}

// ============================================================================
// ASN.1 Read Functions
// ============================================================================

#[no_mangle]
pub extern "C" fn asn1_read_boolean(decoder: *mut Asn1DecoderHandle, value: *mut bool) -> c_int {
    if decoder.is_null() || value.is_null() {
        return -1;
    }

    unsafe {
        let decoder = &mut *(decoder as *mut Asn1Decoder);
        match read_boolean(decoder) {
            Ok(result) => {
                *value = result;
                0
            }
            Err(_) => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_read_int(decoder: *mut Asn1DecoderHandle, value: *mut i32) -> c_int {
    if decoder.is_null() || value.is_null() {
        return -1;
    }

    unsafe {
        let decoder = &mut *(decoder as *mut Asn1Decoder);
        match read_int(decoder) {
            Ok(result) => {
                *value = result;
                0
            }
            Err(_) => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_read_bit_string(
    decoder: *mut Asn1DecoderHandle,
    unused_bits: *mut u8
) -> ByteBuffer {
    if decoder.is_null() || unused_bits.is_null() {
        return ByteBuffer { data: ptr::null_mut(), len: 0, capacity: 0 };
    }

    unsafe {
        let decoder = &mut *(decoder as *mut Asn1Decoder);
        match read_bit_string(decoder) {
            Ok((data)) => {
                ByteBuffer::from_vec(data)
            }
            Err(_) => ByteBuffer { data: ptr::null_mut(), len: 0, capacity: 0 },
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_read_octet_string(decoder: *mut Asn1DecoderHandle) -> ByteBuffer {
    if decoder.is_null() {
        return ByteBuffer { data: ptr::null_mut(), len: 0, capacity: 0 };
    }

    unsafe {
        let decoder = &mut *(decoder as *mut Asn1Decoder);
        match read_octet_string(decoder) {
            Ok(data) => ByteBuffer::from_vec(data),
            Err(_) => ByteBuffer { data: ptr::null_mut(), len: 0, capacity: 0 },
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_read_utf8_string(decoder: *mut Asn1DecoderHandle) -> *mut c_char {
    if decoder.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let decoder = &mut *(decoder as *mut Asn1Decoder);
        match read_utf8_string(decoder) {
            Ok(string) => {
                match CString::new(string) {
                    Ok(c_string) => c_string.into_raw(),
                    Err(_) => ptr::null_mut(),
                }
            }
            Err(_) => ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_read_visible_string(decoder: *mut Asn1DecoderHandle) -> *mut c_char {
    if decoder.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let decoder = &mut *(decoder as *mut Asn1Decoder);
        match read_visible_string(decoder) {
            Ok(string) => {
                match CString::new(string) {
                    Ok(c_string) => c_string.into_raw(),
                    Err(_) => ptr::null_mut(),
                }
            }
            Err(_) => ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_read_object_identifier(decoder: *mut Asn1DecoderHandle) -> *mut c_char {
    if decoder.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let decoder = &mut *(decoder as *mut Asn1Decoder);
        match read_object_identifier(decoder) {
            Ok(oid_string) => {
                match CString::new(oid_string) {
                    Ok(c_string) => c_string.into_raw(),
                    Err(_) => ptr::null_mut(),
                }
            }
            Err(_) => ptr::null_mut(),
        }
    }
}


// ============================================================================
// Asn1Tag FFI Functions
// ============================================================================

#[no_mangle]
pub extern "C" fn asn1_tag_new(
    tag_number: u8,
    tag_class: u8,
    constructed: bool
) -> *mut Asn1TagHandle {
    let tag = Box::new(Asn1Tag::new(tag_number, tag_class as u32));
    Box::into_raw(tag) as *mut Asn1TagHandle
}

#[no_mangle]
pub extern "C" fn asn1_tag_free(tag: *mut Asn1TagHandle) {
    if !tag.is_null() {
        unsafe {
            let _ = Box::from_raw(tag as *mut Asn1Tag);
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_tag_get_number(tag: *const Asn1TagHandle) -> u8 {
    if tag.is_null() {
        return 0;
    }

    unsafe {
        let tag = &*(tag as *const Asn1Tag);
        tag.tag_number as u8
    }
}

#[no_mangle]
pub extern "C" fn asn1_tag_get_class(tag: *const Asn1TagHandle) -> u8 {
    if tag.is_null() {
        return 0;
    }

    unsafe {
        let tag = &*(tag as *const Asn1Tag);
        tag.tag_class
    }
}

#[no_mangle]
pub extern "C" fn asn1_tag_is_constructed(tag: *const Asn1TagHandle) -> bool {
    if tag.is_null() {
        return false;
    }

    unsafe {
        let tag = &*(tag as *const Asn1Tag);
        (tag.tag_class & 0x20) != 0
    }
}


// ============================================================================
// Asn1UtcTime FFI Functions
// ============================================================================

#[no_mangle]
pub extern "C" fn asn1_utc_time_parse(value: *const c_char) -> *mut Asn1UtcTimeHandle {
    if value.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let c_str = CStr::from_ptr(value);
        if let Ok(string) = c_str.to_str() {
            match Asn1UtcTime::parse(string) {
                Ok(time) => Box::into_raw(Box::new(time)) as *mut Asn1UtcTimeHandle,
                Err(_) => ptr::null_mut(),
            }
        } else {
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_utc_time_free(time: *mut Asn1UtcTimeHandle) {
    if !time.is_null() {
        unsafe {
            let _ = Box::from_raw(time as *mut Asn1UtcTime);
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_utc_time_format(time: *const Asn1UtcTimeHandle) -> *mut c_char {
    if time.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let time = &*(time as *const Asn1UtcTime);
        let formatted = time.format();
        match CString::new(formatted) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }
}

// ============================================================================
// Asn1GeneralizedTime FFI Functions
// ============================================================================

#[no_mangle]
pub extern "C" fn asn1_generalized_time_parse(value: *const c_char) -> *mut Asn1GeneralizedTimeHandle {
    if value.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let c_str = CStr::from_ptr(value);
        if let Ok(string) = c_str.to_str() {
            match Asn1GeneralizedTime::parse(string) {
                Ok(time) => Box::into_raw(Box::new(time)) as *mut Asn1GeneralizedTimeHandle,
                Err(_) => ptr::null_mut(),
            }
        } else {
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_generalized_time_free(time: *mut Asn1GeneralizedTimeHandle) {
    if !time.is_null() {
        unsafe {
            let _ = Box::from_raw(time as *mut Asn1GeneralizedTime);
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_generalized_time_format(time: *const Asn1GeneralizedTimeHandle) -> *mut c_char {
    if time.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let time = &*(time as *const Asn1GeneralizedTime);
        let formatted = time.format();
        match CString::new(formatted) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }
}

// ============================================================================
// Constants
// ============================================================================

#[no_mangle]
pub extern "C" fn asn1_tag_class_application() -> u8 {
    tag_class::APPLICATION
}

#[no_mangle]
pub extern "C" fn asn1_tag_class_context_specific() -> u8 {
    tag_class::CONTEXT_SPECIFIC
}

#[no_mangle]
pub extern "C" fn asn1_tag_class_private() -> u8 {
    tag_class::PRIVATE
}

#[no_mangle]
pub extern "C" fn asn1_type_boolean() -> u8 {
    asn1_type::BOOLEAN
}

#[no_mangle]
pub extern "C" fn asn1_type_integer() -> u8 {
    asn1_type::INTEGER
}

#[no_mangle]
pub extern "C" fn asn1_type_bit_string() -> u8 {
    asn1_type::BIT_STRING
}

#[no_mangle]
pub extern "C" fn asn1_type_octet_string() -> u8 {
    asn1_type::OCTET_STRING
}

#[no_mangle]
pub extern "C" fn asn1_type_null() -> u8 {
    asn1_type::NULL
}

#[no_mangle]
pub extern "C" fn asn1_type_object_identifier() -> u8 {
    asn1_type::OBJECT_IDENTIFIER
}

#[no_mangle]
pub extern "C" fn asn1_type_sequence() -> u8 {
    asn1_type::SEQUENCE
}

#[no_mangle]
pub extern "C" fn asn1_type_set() -> u8 {
    asn1_type::SET
}

#[no_mangle]
pub extern "C" fn asn1_type_utf8_string() -> u8 {
    asn1_type::UTF8_STRING
}

#[no_mangle]
pub extern "C" fn asn1_type_visible_string() -> u8 {
    asn1_type::VISIBLE_STRING
}

#[no_mangle]
pub extern "C" fn asn1_type_utc_time() -> u8 {
    asn1_type::UTC_TIME
}

#[no_mangle]
pub extern "C" fn asn1_type_generalized_time() -> u8 {
    asn1_type::GENERALIZED_TIME
}

// ============================================================================
// Memory Management
// ============================================================================

#[no_mangle]
pub extern "C" fn asn1_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn asn1_free_byte_buffer(buffer: ByteBuffer) {
    if !buffer.data.is_null() {
        unsafe {
            let _ = buffer.into_vec();
        }
    }
}