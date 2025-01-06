
use side_proto::side::dlc::{AgencyStatus, QueryAgenciesRequest};
use side_proto::side::dlc::query_client::QueryClient as DLCQueryClient;
use crate::{
    apps::{Context, Task}, helper::{encoding::pubkey_to_identifier, store::Store}};
use super::Agency;

impl Agency {

    pub async fn fetch_new_agency(&self, ctx: &mut Context) {
        let mut dlc_client = match DLCQueryClient::connect(ctx.conf.side_chain.grpc.clone()).await {
            Ok(c) => c,
            Err(e) => panic!("{}", e),
        };
        let response3 = dlc_client.agencies(QueryAgenciesRequest{status: AgencyStatus::Pending as i32, pagination: None}).await;
        let agencies = match response3 {
            Ok(resp) => resp.into_inner().agencies,
            Err(_) => return,
        };
        agencies.iter().for_each(|agency| {

            let mut participants = vec![];
            for p in &agency.participants {
                match hex::decode(p) {
                    Ok(b) => {
                       participants.push(pubkey_to_identifier(&b))
                    },
                    Err(_) => return,
                };
            }

            let task = Task::new_dkg(format!("agency-{}", agency.id), participants, agency.threshold as u16);

            if ctx.task_store.exists(&task.id) { return }
            ctx.task_store.save(&task.id, &task);

            self.keygen.generate(ctx, &task);
        });
    }

}


