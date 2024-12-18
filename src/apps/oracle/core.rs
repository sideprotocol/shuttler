use crate::{apps::Context, config::VaultKeypair, helper::{bitcoin::{generate_tweak, get_group_address_by_tweak}, store::Store}, protocols::dkg::{KeyHander, DKG}};


pub struct NonceHandler {}
pub type NonceGenerator = DKG<NonceHandler>;

impl KeyHander for NonceHandler {
    fn on_completed(ctx: &mut Context, priv_key: frost_adaptor_signature::keys::KeyPackage, pub_key: frost_adaptor_signature::keys::PublicKeyPackage) {
        let tweak = None;
        let key = hex::encode(pub_key.verifying_key().serialize().unwrap());
        let keyshare = VaultKeypair {
            pub_key,
            priv_key,
            tweak,
        };
        ctx.keystore.save(&key, &keyshare);
        
    }
}

pub struct OracleKeyShareHandler{}
pub type OracleKeyShareGenerator = DKG<OracleKeyShareHandler>;

impl KeyHander for OracleKeyShareHandler {
    fn on_completed(ctx: &mut Context, priv_key: frost_adaptor_signature::keys::KeyPackage, pub_key: frost_adaptor_signature::keys::PublicKeyPackage) {
        // let tweak = generate_tweak(&pub_key, 0u16);
        // let key = get_group_address_by_tweak(pub_key.verifying_key(), tweak, ctx.conf.bitcoin.network);
        let tweak = None;
        let key = hex::encode(pub_key.verifying_key().serialize().unwrap());
        let keyshare = VaultKeypair {
            pub_key,
            priv_key,
            tweak,
        };
        ctx.keystore.save(&key.to_string(), &keyshare);
    }
}