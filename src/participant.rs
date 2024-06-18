use std::{collections::BTreeMap, path::PathBuf};

use frost_core::{serde::{Serialize, Deserialize}, Ciphersuite, keys::KeyPackage};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant<C> where C: Ciphersuite{
    pub party_id: frost_core::Identifier<C>,
    pub local_secret_key: BTreeMap<String, KeyPackage<C>>,
}

impl<C> Participant<C> where C: Ciphersuite {
    pub fn new(party_id: frost_core::Identifier<C>) -> Self {
        Self {
            party_id,
            local_secret_key: BTreeMap::new(),
        }
    }

    pub fn load_from_local(_conf: PathBuf) -> Self {
        unimplemented!()
    }
}