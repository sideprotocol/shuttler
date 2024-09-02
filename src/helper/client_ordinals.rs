use bitcoin::OutPoint;
use ord::api::{Output, Rune};
use ordinals::RuneId;

use reqwest::{header, Client, Error};

#[derive(Debug)]
pub struct OrdinalsClient {
    pub endpoint: String,
    client: Client,
}

impl OrdinalsClient {
    pub fn new(endpoint: &str) -> Self {
        OrdinalsClient {
            endpoint: endpoint.to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn get_rune(&self, id: RuneId) -> Result<Rune, Error> {
        let api = format!("{}/rune/{}", self.endpoint, id);

        match self
            .client
            .get(api)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
        {
            Ok(resp) => resp.json::<Rune>().await,
            Err(e) => Err(e),
        }
    }

    pub async fn get_output(&self, out_point: OutPoint) -> Result<Output, Error> {
        let api = format!("{}/output/{}", self.endpoint, out_point);

        match self
            .client
            .get(api)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
        {
            Ok(resp) => resp.json::<Output>().await,
            Err(e) => Err(e),
        }
    }
}
