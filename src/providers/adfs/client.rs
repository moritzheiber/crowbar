use anyhow::Result;
use reqwest::blocking::Client as HttpClient;
use reqwest::blocking::Response;
use reqwest::IntoUrl;
use serde::Serialize;

pub struct Client {
    client: HttpClient,
}

impl Client {
    pub fn new() -> Result<Self> {
        Ok(Client {
            client: HttpClient::builder().cookie_store(true).build()?,
        })
    }

    pub fn get<U: IntoUrl>(&self, url: U) -> Result<Response> {
        self.client
            .get(url)
            .send()?
            .error_for_status()
            .map_err(|e| e.into())
    }

    pub fn post<U: IntoUrl, I>(&self, url: U, form_content: &I) -> Result<Response, reqwest::Error>
    where
        I: Serialize,
    {
        self.client
            .post(url)
            .form(form_content)
            .send()?
            .error_for_status()
    }
}
