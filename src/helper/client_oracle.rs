use crate::app::config::OracleCfg;
use serde::{Deserialize, Serialize};
use reqwest::{header, Client, Error};

#[derive(Debug)]
pub struct OracleClient {
    client: Client,
    fetch_fee_rate_url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BitcoinFees {
    pub fastest_fee: i64,
    pub half_hour_fee: i64,
    pub hour_fee: i64,
    pub economy_fee: i64,
    pub minimum_fee: i64,
}

impl OracleClient {
    pub fn new(oracle: &OracleCfg) -> Self {
        OracleClient {
            client: reqwest::Client::new(),
            fetch_fee_rate_url: oracle.fetch_fee_rate_url.clone(),
        }
    }

    pub async fn get_fees(&self) -> Result<BitcoinFees, Error> {
        match self
            .client
            .get(&self.fetch_fee_rate_url)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
        {
            Ok(resp) => resp.json::<BitcoinFees>().await,
            Err(e) => Err(e),
        }
    }
}
