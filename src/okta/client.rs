use failure::Error;
use reqwest::header::{Accept, ContentType, Cookie};
use reqwest::Client;
use reqwest::Response;
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub struct OktaClient {
    client: Client,
    base_url: String,
    cookies: Cookie,
}

impl OktaClient {
    pub fn new(organization: String) -> OktaClient {
        OktaClient {
            client: Client::new(),
            base_url: String::from(format!("https://{}.okta.com", organization)),
            cookies: Cookie::new(),
        }
    }

    pub fn set_session_id(&mut self, session_id: String) {
        self.cookies.append("sid", session_id);
    }

    pub fn get_response(&self, url: Url) -> Result<Response, Error> {
        self.client
            .get(url)
            .header(self.cookies.clone())
            .send()?
            .error_for_status()
            .map_err(|e| e.into())
    }

    pub fn get<O>(&self, path: String) -> Result<O, Error>
    where
        O: DeserializeOwned,
    {
        self.client
            .get(&format!("{}/{}", self.base_url, path))
            .header(ContentType::json())
            .header(Accept::json())
            .header(self.cookies.clone())
            .send()?
            .error_for_status()?
            .json()
            .map_err(|e| e.into())
    }

    pub fn post<I, O>(&self, path: String, body: I) -> Result<O, Error>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        self.client
            .post(&format!("{}/{}", self.base_url, path))
            .json(&body)
            .header(ContentType::json())
            .header(Accept::json())
            .header(self.cookies.clone())
            .send()?
            .error_for_status()?
            .json()
            .map_err(|e| e.into())
    }

    pub fn post_absolute<I, O>(&self, url: Url, body: I) -> Result<O, Error>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        self.client
            .post(url)
            .json(&body)
            .header(ContentType::json())
            .header(Accept::json())
            .header(self.cookies.clone())
            .send()?
            .error_for_status()?
            .json()
            .map_err(|e| e.into())
    }
}
