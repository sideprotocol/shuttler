
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
