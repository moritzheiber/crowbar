use anyhow::Result;
use itertools::Itertools;
use reqwest::blocking::Client as HttpClient;
use reqwest::blocking::Response;
use reqwest::header::{HeaderValue, ACCEPT, COOKIE};
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;

use crate::config::app::AppProfile;

pub struct Client {
    client: HttpClient,
    profile: AppProfile,
    cookies: HashMap<String, String>,
}

impl Client {
    pub fn new(profile: AppProfile) -> Client {
        Client {
            client: HttpClient::new(),
            profile,
            cookies: HashMap::new(),
        }
    }

    pub fn set_session_id(&mut self, session_id: String) {
        self.cookies.insert("sid".to_string(), session_id);
    }

    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .join(";")
    }

    pub fn get_response(&self, url: Url) -> Result<Response> {
        self.client
            .get(url)
            .header(COOKIE, self.cookie_header())
            .send()?
            .error_for_status()
            .map_err(|e| e.into())
    }

    pub fn post<I, O>(&self, path: &str, body: &I) -> Result<O>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        self.client
            .post(self.profile.base_url()?.join(path)?)
            .json(body)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(COOKIE, self.cookie_header())
            .send()?
            .error_for_status()?
            .json()
            .map_err(|e| e.into())
    }

    pub fn post_absolute<I, O>(&self, url: Url, body: &I) -> Result<O>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        self.client
            .post(url)
            .json(body)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(COOKIE, self.cookie_header())
            .send()?
            .error_for_status()?
            .json()
            .map_err(|e| e.into())
    }
}
