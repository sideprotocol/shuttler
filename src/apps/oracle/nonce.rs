use std::collections::BTreeMap;

use rand::thread_rng;
use serde::{Deserialize, Serialize};

use crate::helper::{mem_store, store::Store};

use super::Oracle;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceGeneration {
    pub index: u64,
    pub oracle_group_address: String,
    pub nonce: String,
    pub event_id: Option<String>,
    pub generate_at: u64,
}

impl NonceGeneration {
    pub fn id(&self) -> String {
        format!("{}-{}", self.oracle_group_address, self.index)
    }
}

impl Oracle {
    pub async fn fetch_new_announcement(&self) {
        let new_task = NonceGeneration {
            index: 1,
            oracle_group_address: "aaaa".to_string(),
            nonce: "".to_string(),
            event_id: Some("".to_string()),
            generate_at: 1234,
        };
        self.db_nonce.save(&new_task.nonce, &new_task);
    }

    pub fn generate_round1_package(&self, task: NonceGeneration) {
        let keypair = match self.db_keypair.get(&task.oracle_group_address) {
            Some(k) => k,
            None => return,
        };

        if !keypair.pub_key.verifying_shares().contains_key(&self.identifier) {
            return;
        }

        let mut rng = thread_rng();
        if let Ok((secret_packet, round1_package)) = frost_adaptor_signature::keys::dkg::part1(
            self.identifier,
            keypair.pub_key.verifying_shares().len() as u16,
            *keypair.priv_key.min_signers(),
            &mut rng,
        ) {
            tracing::debug!("round1_secret_package: {:?}-{}", task.oracle_group_address, task.index);
            mem_store::set_dkg_round1_secret_packet(&task.id(), secret_packet);

            let mut round1_packages = BTreeMap::new();
            round1_packages.insert(self.identifier, round1_package);

            self.db_dkg_round1.save(&task.id(), &round1_packages);
        } else {
            tracing::error!("error in DKG round 1: {:?}", task.id());
        }
    }

    
}


