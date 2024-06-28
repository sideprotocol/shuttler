pub fn to_base64(data: &[u8]) -> String {
    base64::encode(data)
}

pub fn from_base64(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode(data)
}