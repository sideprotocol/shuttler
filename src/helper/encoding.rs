use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::hashes::{Hash, sha256};
use frost_adaptor_signature::keys::PublicKeyPackage;
use frost_adaptor_signature::Field;
use frost_adaptor_signature::Group;
use frost_adaptor_signature::Identifier;
use frost_adaptor_signature::Secp256K1Group;
use frost_adaptor_signature::Secp256K1ScalarField;
use k256::ProjectivePoint;
use libp2p::PeerId;

pub fn to_base64(input: &[u8]) -> String {
    // base64::encode(data)
    STANDARD.encode(input)
}

pub fn from_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // base64::decode(data)
    STANDARD.decode(input)
}

pub fn hash(bytes: &[u8]) -> String {
    let x = sha256::Hash::hash(bytes);
    x.to_string()
}

pub fn abbr(identifier: &Identifier) -> String {
    hex::encode(identifier.serialize())[..4].to_lowercase()
}

pub fn identifier_to_peer_id(identifier: &Identifier) -> PeerId {
    let xkey = libp2p::identity::ed25519::PublicKey::try_from_bytes(&identifier.serialize()).unwrap();
    libp2p::identity::PublicKey::from(xkey).to_peer_id()
}
pub fn identifier_to_base64(identifier: &Identifier) -> String {
    to_base64(&identifier.serialize())
}
pub fn pubkey_to_identifier(key_bytes: &[u8]) -> Identifier {
    let id = Secp256K1ScalarField::deserialize(key_bytes.try_into().unwrap()).unwrap();
    Identifier::new(id).unwrap()
}

pub fn pubkey_to_point(pubkey: PublicKeyPackage) -> anyhow::Result<ProjectivePoint>  {
   let b= pubkey.serialize()?;
   Ok(Secp256K1Group::deserialize(&b[..].try_into()?)?)
}

pub fn hex_to_projective_point(text: &String) -> anyhow::Result<ProjectivePoint> {
    let b = hex::decode(text)?;
    Ok(Secp256K1Group::deserialize(&b[..].try_into()?)?)
}

pub fn base64_to_projective_point(text: &String) -> anyhow::Result<ProjectivePoint> {
    let b = from_base64(text)?;
    Ok(Secp256K1Group::deserialize(&b[..].try_into()?)?)
}
