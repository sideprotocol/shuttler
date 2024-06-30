use reqwest::Error;

pub fn get_http_client() -> reqwest::Client {
    reqwest::Client::new()
}

pub async fn get<T>(url: &str) -> Result<T, Error> where T: serde::de::DeserializeOwned {
    let response = match reqwest::get(url).await {
        Ok(response) => response,
        Err(error) => {
            tracing::error!("Failed to send request: {:?}", error);
            return Err(error);
        }
    };

    response.json::<T>().await
}

pub async fn post<I, O>(url: &str, data: I) -> Result<O, Error> where I: serde::Serialize, O: serde::de::DeserializeOwned {

    let client = get_http_client();
    let response = match client.post(url).json(&data).send().await {
        Ok(response) => response,
        Err(error) => {
            tracing::error!("Failed to send request: {:?}", error);
            return Err(error);
        }
    };    
    response.json::<O>().await
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Pagination {
    pub limit: u32,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SigningRequest {
    pub address: String,
    pub psbt: String,
    pub status: String,
    pub sequence: u32,
    pub vault_address: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SigningRequestsResponse {
    requests: Vec<SigningRequest>,
    pagination: Option<Pagination>,
}

impl SigningRequestsResponse {
    pub fn requests(&self) -> &Vec<SigningRequest> {
        &self.requests
    }

    pub fn pagination(&self) -> Option<&Pagination> {
        self.pagination.as_ref()
    }
}

pub async fn get_signing_requests(host: &str ) -> Result<SigningRequestsResponse, Error> {
    let url = format!("{}/signing_requests", host);
    get::<SigningRequestsResponse>(url.as_str()).await
}

pub async fn mock_signing_requests() -> Result<SigningRequestsResponse, Error> {
    Ok(SigningRequestsResponse {
        requests: vec![
            SigningRequest {
                address: "bc1q5wgdhplnzn075eq7xep4zes7lnk5jy2ke0scsm".to_string(),
                psbt: "cHNidP8BAIkCAAAAARuMLk06K1ufndtymk3RaWdbLy21UYs9vUs8D6o8HjtNAAAAAAAAAAAAAkCcAAAAAAAAIlEglUAPVXmsEIekhIthcGwg/vRxs93mpUYfH3vFVlGNjiEoIwAAAAAAACJRIJVAD1V5rBCHpISLYXBsIP70cbPd5qVGHx97xVZRjY4hAAAAAAABAStQwwAAAAAAACJRIJVAD1V5rBCHpISLYXBsIP70cbPd5qVGHx97xVZRjY4hAQMEAAAAAAAAAA==".to_string(),
                status: "pending".to_string(),
                sequence: 1,
                vault_address: "bc1q5wgdhplnzn075eq7xep4zes7lnk5jy2ke0scsm".to_string(),
            }],
        pagination: None,
    })
}