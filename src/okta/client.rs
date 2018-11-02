use failure::Error;
use itertools::Itertools;
use reqwest::header::{HeaderValue, ACCEPT, COOKIE};
use reqwest::Client as HttpClient;
use reqwest::Response;
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;

use okta::Organization;

pub struct Client {
    client: HttpClient,
    organization: Organization,
    cookies: HashMap<String, String>,
}

impl Client {
    pub fn new(organization: Organization) -> Client {
        Client {
            client: HttpClient::new(),
            organization,
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

    pub fn get_response(&self, url: Url) -> Result<Response, Error> {
        self.client
            .get(url)
            .header(COOKIE, self.cookie_header())
            .send()?
            .error_for_status()
            .map_err(|e| e.into())
    }

    pub fn get<O>(&self, path: &str) -> Result<O, Error>
    where
        O: DeserializeOwned,
    {
        self.client
            .get(self.organization.base_url.join(path)?)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(COOKIE, self.cookie_header())
            .send()?
            .error_for_status()?
            .json()
            .map_err(|e| e.into())
    }

    pub fn post<I, O>(&self, path: &str, body: &I) -> Result<O, Error>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        self.client
            .post(self.organization.base_url.join(path)?)
            .json(body)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(COOKIE, self.cookie_header())
            .send()?
            .error_for_status()?
            .json()
            .map_err(|e| e.into())
    }

    pub fn post_absolute<I, O>(&self, url: Url, body: &I) -> Result<O, Error>
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
