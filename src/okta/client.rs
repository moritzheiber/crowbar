use failure::Error;
use reqwest::header::{Accept, ContentType, Cookie};
use reqwest::Client as HttpClient;
use reqwest::Response;
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::Serialize;

use okta::Organization;

pub struct Client {
    client: HttpClient,
    organization: Organization,
    cookies: Cookie,
}

impl Client {
    pub fn new(organization: Organization) -> Client {
        Client {
            client: HttpClient::new(),
            organization,
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

    pub fn get<O>(&self, path: &str) -> Result<O, Error>
    where
        O: DeserializeOwned,
    {
        self.client
            .get(&format!("{}/{}", self.organization.base_url, path))
            .header(ContentType::json())
            .header(Accept::json())
            .header(self.cookies.clone())
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
            .post(&format!("{}/{}", self.organization.base_url, path))
            .json(body)
            .header(ContentType::json())
            .header(Accept::json())
            .header(self.cookies.clone())
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
            .header(ContentType::json())
            .header(Accept::json())
            .header(self.cookies.clone())
            .send()?
            .error_for_status()?
            .json()
            .map_err(|e| e.into())
    }
}
