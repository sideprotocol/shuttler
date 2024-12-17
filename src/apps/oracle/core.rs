use crate::protocols::dkg::{KeyHander, DKG};


pub struct NonceHandler {}
pub type NonceGenerator = DKG<NonceHandler>;

impl KeyHander for NonceHandler {
    fn on_completed(&self, priv_key: frost_adaptor_signature::keys::KeyPackage, pubkey: frost_adaptor_signature::keys::PublicKeyPackage) {
        todo!()
    }
}

pub struct OracleKeyShareHandler{}
pub type OracleKeyShareGenerator = DKG<OracleKeyShareHandler>;

impl KeyHander for OracleKeyShareHandler {
    fn on_completed(&self, priv_key: frost_adaptor_signature::keys::KeyPackage, pubkey: frost_adaptor_signature::keys::PublicKeyPackage) {
        todo!()
    }
}