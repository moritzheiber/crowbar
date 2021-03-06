use crate::config::app::AppProfile;

use anyhow::Result;
use reqwest::blocking::Client as HttpClient;
use reqwest::blocking::Response;
use reqwest::header::{HeaderValue, ACCEPT};
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub struct Client {
    client: HttpClient,
    pub base_url: Url,
    pub session_token: Option<String>,
}

impl Client {
    pub fn new(profile: AppProfile) -> Result<Client> {
        Ok(Client {
            client: HttpClient::builder().cookie_store(true).build()?,
            base_url: profile.base_url()?,
            session_token: None,
        })
    }

    pub fn get(&self, mut url: Url) -> Result<Response> {
        if let Some(token) = &self.session_token {
            url.query_pairs_mut().append_pair("sessionToken", token);
        }
        self.client
            .get(url)
            .send()?
            .error_for_status()
            .map_err(|e| e.into())
    }

    pub fn post<I, O>(&self, url: Url, body: &I) -> Result<O>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        self.client
            .post(url)
            .json(body)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .send()?
            .error_for_status()?
            .json()
            .map_err(|e| e.into())
    }
}
