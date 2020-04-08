use anyhow::Result;
use reqwest::blocking::Client as HttpClient;
use reqwest::blocking::Response;
use reqwest::header::{HeaderValue, ACCEPT};
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::Serialize;

const TOKEN: &str = "X-Xsrftoken";

pub struct Client {
    client: HttpClient,
}

impl Client {
    pub fn new() -> Result<Self> {
        Ok(Client {
            client: HttpClient::builder().cookie_store(true).build()?,
        })
    }

    pub fn get(&self, url: Url) -> Result<Response> {
        self.client
            .get(url)
            .send()?
            .error_for_status()
            .map_err(|e| e.into())
    }

    pub fn post<I, O>(&self, url: Url, body: &I, token: &str) -> Result<O, reqwest::Error>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        let json = HeaderValue::from_static("application/json");
        self.client
            .post(url)
            .json(body)
            .header(ACCEPT, &json)
            .header(TOKEN, token)
            .send()?
            .error_for_status()?
            .json()
    }
}
