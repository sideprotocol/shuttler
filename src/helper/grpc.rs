use std::convert::TryInto;
use std::str::FromStr;
use std::time::Duration;

use tonic::transport::{Endpoint, Error};

pub struct Dst {
    url: String,
    timeout: Duration,
}

impl Dst {
    pub fn new(url: String, timeout: Duration) -> Self {
        Dst { url, timeout }
    }
}

impl TryInto<Endpoint> for Dst {
    type Error = Error;

    fn try_into(self) -> Result<Endpoint, Self::Error> {
       let mut endpoint = match Endpoint::from_str(&self.url) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                return Err(e);
            }
        };

        endpoint = endpoint.timeout(self.timeout);
        
        Ok(endpoint)
    }
}
