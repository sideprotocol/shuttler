
use std::collections::BTreeMap;

use anyhow::anyhow;
use bitcoin::{hashes::Hash, sighash::{Prevouts, SighashCache}, Address, Psbt, TapSighashType};
use side_proto::side::btcbridge::{query_client::QueryClient as BtcQueryClient, DkgRequest, DkgRequestStatus, QueryDkgRequestsRequest, SigningRequest};
use tracing::{debug, error, info};

use crate::{
    apps::{Context, Input, SignMode, Task}, 
    helper::{client_side::get_signing_requests, encoding::{from_base64, pubkey_to_identifier}, mem_store, store::Store}, 
};

use super::BridgeSigner;

pub async fn tasks_executor(ctx: &mut Context, signer: &mut BridgeSigner ) {
    
    if ctx.swarm.connected_peers().count() == 0 {
        return
    }

    // // 1. dkg tasks
    fetch_dkg_requests(ctx, signer).await;

    // // fetch request for next execution
    fetch_signing_requests(ctx, signer).await;
    // broadcast_sign_packages(swarm);
    
}

pub async fn fetch_signing_requests(
    ctx: &mut Context,
    signer: &mut BridgeSigner,
) {
    let host = ctx.conf.side_chain.grpc.as_str();

    match get_signing_requests(&host).await {
        Ok(response) => {
            let requests = response.into_inner().requests;
            let tasks_in_process = requests.iter().map(|r| r.txid.clone() ).collect::<Vec<_>>();
            debug!("In-process signing tasks: {:?} {:?}", tasks_in_process.len(), tasks_in_process);
            for request in requests {
                // create a dkg task
                if let Ok(task) = new_task_from_signing_request(ctx, &request) {

                    if ctx.task_store.exists(&task.id) { continue; }
                    ctx.task_store.save(&task.id, &task);
    
                    signer.signer.generate_commitments(ctx, &task);
                }
            }
        }
        Err(e) => {
            error!("Failed to fetch signing requests: {:?}", e);
            return;
        }
    };
}

async fn fetch_dkg_requests(ctx: &mut Context, signer: &mut BridgeSigner) {
    let host = ctx.conf.side_chain.grpc.clone();
    let mut client = match BtcQueryClient::connect(host.to_owned()).await {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create btcbridge query client: {host} {}", e);
            return;
        }
    };
    if let Ok(requests_response) = client
        .query_dkg_requests(QueryDkgRequestsRequest {
            status: DkgRequestStatus::Pending as i32,
        })
        .await
    {
        let requests = requests_response.into_inner().requests;
        debug!("DKG Requests, {:?}", requests);

        debug!("my pubkey: {:?}", ctx.id_base64);
        for request in requests {
            if request
                .participants
                .iter()
                .find(|p| p.consensus_pubkey == ctx.id_base64)
                .is_some()
            {
                // create a dkg task
                if let Some(mut task) = new_task_from_vault_dkg(&request) {

                    if ctx.task_store.exists(&task.id) { continue; }
                    task.dkg_input.tweaks = request.vault_types;
                    ctx.task_store.save(&task.id, &task);
    
                    signer.keygen.generate(ctx, &task);
                }
            }
        }
    };
}

fn task_id_to_request_id(task_id: &String) -> u64 {
    task_id.replace("dkg-", "").parse().unwrap()
}

fn request_id_to_task_id(id: u64) -> String {
    format!("dkg-{}", id)
}

fn new_task_from_vault_dkg(request: &DkgRequest) -> Option<Task> {

    let mut participants = vec![];
    for p in &request.participants {
        match from_base64(&p.consensus_pubkey) {
            Ok(b) => {
               participants.push(pubkey_to_identifier(&b))
            },
            Err(_) => return None,
        };
    }
    Some(Task::new_dkg(request_id_to_task_id(request.id), participants, request.threshold as u16 ))
}

fn new_task_from_signing_request(ctx: &mut Context, request: &SigningRequest) -> anyhow::Result<Task> {


    let psbt_bytes = from_base64(&request.psbt)?;
    let task_id = request.txid.clone();

    let psbt = Psbt::deserialize(psbt_bytes.as_slice())?;

    info!("Prepare for signing: {:?} {} inputs ", &request.txid[..6], psbt.inputs.len()  );
    let mut inputs = BTreeMap::new();
    let preouts = psbt.inputs.iter()
        //.filter(|input| input.witness_utxo.is_some())
        .map(|input| input.witness_utxo.clone().unwrap())
        .collect::<Vec<_>>();

    for (i, input) in psbt.inputs.iter().enumerate() {

        let script = input.witness_utxo.clone().unwrap().script_pubkey;
        let address = Address::from_script(&script, ctx.conf.bitcoin.network)?.to_string();

        // check if there are sufficient participants for this tasks
        let participants = mem_store::count_task_participants(ctx, &address.to_string());
        match ctx.keystore.get(&address) {
            Some(k) => if participants.len() < k.priv_key.min_signers().clone() as usize { return Err(anyhow!("insufficient signers")); },
            None => continue,
        };

        // get the message to sign
        let hash_ty = input
            .sighash_type
            .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
            .unwrap_or(TapSighashType::Default);
        let hash = SighashCache::new(&psbt.unsigned_tx).taproot_key_spend_signature_hash( i,&Prevouts::All(&preouts),hash_ty,)?;

        let input = Input {
            key: address,
            index: i,
            participants,
            message: hash.to_raw_hash().to_byte_array().to_vec(),
            mode: SignMode::SignWithTweak,
            signature: None,
        };

        inputs.insert(i, input);
 
    };

    if inputs.len() == 0 {
        return Err(anyhow!("invalid psbt, 0 input"));
    }

    let task = Task::new_signing(task_id, request.psbt.clone(), inputs);

    ctx.task_store.save(&task.id, &task);

    Ok(task)

}

