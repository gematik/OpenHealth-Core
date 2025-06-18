use base64::Engine;

const PEM_DATA_MAX_LENGTH_PER_LINE: usize = 64;

static PEM_REGEX: &str = r"^-----BEGIN (.*)-----(.*)-----END (.*)-----$";

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
        let re = regex::Regex::new(PEM_REGEX).unwrap();
        let captures = re.captures(&s).expect("Invalid PEM format");
        let header_type = captures.get(1).unwrap().as_str();
        let data = captures.get(2).unwrap().as_str();
        let footer_type = captures.get(3).unwrap().as_str();
        assert_eq!(header_type, footer_type, "Invalid PEM type format");
        Pem {
            r#type: header_type.to_string(),
            data: base64::engine::general_purpose::STANDARD.decode(data).expect("Base64 decoding failed"),
        }
    }
}