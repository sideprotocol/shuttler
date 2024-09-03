use base64::{engine::general_purpose::STANDARD, Engine};

pub fn to_base64(input: &[u8]) -> String {
    // base64::encode(data)
    STANDARD.encode(input)
}

pub fn from_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // base64::decode(data)
    STANDARD.decode(input)
}
