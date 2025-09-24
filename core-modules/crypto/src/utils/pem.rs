use std::sync::OnceLock;

use base64::Engine;
use regex::Regex;

const PEM_DATA_MAX_LENGTH_PER_LINE: usize = 64;

static PEM_REGEX: OnceLock<Regex> = OnceLock::new();

/// Represents a Privacy Enhanced Mail (PEM) formatted cryptographic object.
pub struct Pem {
    pub r#type: String,
    pub data: Vec<u8>,
}

/// Encodes the PEM object into its string representation
/// with BEGIN/END markers and Base64-encoded data.
impl Pem {
    pub fn encode_to_string(&self) -> String {
        let mut result = String::new();
        result.push_str(&format!("-----BEGIN {}-----\n", self.r#type));
        let encoded = base64::engine::general_purpose::STANDARD.encode(&self.data);
        for chunk in encoded.as_bytes().chunks(PEM_DATA_MAX_LENGTH_PER_LINE) {
            result.push_str(&format!("{}\n", String::from_utf8_lossy(chunk)));
        }
        result.push_str(&format!("-----END {}-----\n", self.r#type));
        result
    }
}

/// Decodes a PEM-formatted string into a `Pem` object.
/// Panics if the string is not in valid PEM format.
pub trait DecodeToPem {
    fn decode_to_pem(&self) -> Pem;
}

impl DecodeToPem for str {
    fn decode_to_pem(&self) -> Pem {
        let s = self.replace('\n', "").trim().to_owned();
        let re = PEM_REGEX.get_or_init(|| {
            Regex::new(r"^-----BEGIN (.*)-----(.*)-----END (.*)-----$").expect("compile PEM regex")
        });
        let captures = re.captures(&s).expect("Invalid PEM format");
        let header_type = captures.get(1).unwrap().as_str();
        let data = captures.get(2).unwrap().as_str();
        let footer_type = captures.get(3).unwrap().as_str();
        assert_eq!(header_type, footer_type, "Invalid PEM type format");
        Pem {
            r#type: header_type.to_string(),
            data: base64::engine::general_purpose::STANDARD
                .decode(data)
                .expect("Base64 decoding failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_and_decode_pem_with_short_data() {
        let typ = "TEST CERTIFICATE";
        let data = b"Hello World".to_vec();
        let pem = Pem {
            r#type: typ.to_string(),
            data: data.clone(),
        };

        let encoded = pem.encode_to_string();
        let decoded = encoded.decode_to_pem();

        assert_eq!(typ, decoded.r#type);
        assert_eq!(data, decoded.data);
    }

    #[test]
    fn encode_and_decode_pem_with_long_data() {
        let typ = "LONG CERTIFICATE";
        let data: Vec<u8> = (0..100).collect();
        let pem = Pem {
            r#type: typ.to_string(),
            data: data.clone(),
        };

        let encoded = pem.encode_to_string();
        let decoded = encoded.decode_to_pem();

        assert_eq!(typ, decoded.r#type);
        assert_eq!(data, decoded.data);
        assert!(encoded.contains('\n'));
    }

    #[test]
    fn encode_pem_respects_line_length_limit() {
        let typ = "TEST";
        let data = vec![65u8; 100]; // 100 x 'A'
        let pem = Pem {
            r#type: typ.to_string(),
            data,
        };

        let encoded = pem.encode_to_string();
        let lines: Vec<&str> = encoded.lines().collect();

        for line in lines
            .iter()
            .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        {
            assert!(line.len() <= 64, "Line exceeds 64 characters: {line}");
        }
    }

    #[test]
    #[should_panic(expected = "Invalid PEM format")]
    fn decode_invalid_pem_format_throws_error() {
        let invalid_pem = "Not a PEM format";
        // will panic
        invalid_pem.decode_to_pem();
    }

    #[test]
    #[should_panic(expected = "Invalid PEM type format")]
    fn decode_pem_with_mismatched_types_throws_error() {
        let invalid_pem = "-----BEGIN CERT-----SGVsbG8gV29ybGQ=-----END DIFFERENT-----";
        // will panic
        invalid_pem.decode_to_pem();
    }

    #[test]
    fn decode_pem_with_whitespace_and_newlines() {
        let typ = "CERTIFICATE";
        let content = "Hello World";
        let encoded_content = base64::engine::general_purpose::STANDARD.encode(content.as_bytes());
        let pem_string = format!("-----BEGIN {typ}-----\n{encoded_content}\n-----END {typ}-----\n");

        let decoded = pem_string.decode_to_pem();
        assert_eq!(typ, decoded.r#type);
        assert_eq!(content, String::from_utf8(decoded.data).unwrap());
    }
}
