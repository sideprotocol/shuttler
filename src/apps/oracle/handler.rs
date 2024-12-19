use libp2p::gossipsub::IdentTopic;

use crate::{apps::{Context, TopicAppHandle}, config::VaultKeypair, helper::store::Store, protocols::{dkg::{KeyHander, DKG}, sign::{SignatureHander, StandardSigner}}};

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

impl TopicAppHandle for NonceHandler {
    fn topic() -> IdentTopic {
        IdentTopic::new("nonce")
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

impl TopicAppHandle for OracleKeyShareHandler {
    fn topic() -> IdentTopic {
        IdentTopic::new("Oracle")
    }
}

pub struct NonceSignatureHandler{}
pub type NonceSigner = StandardSigner<NonceSignatureHandler>;

impl SignatureHander for NonceSignatureHandler {
    fn on_completed(ctx: &mut Context, signature: frost_adaptor_signature::Signature) {
        todo!()
    }
}