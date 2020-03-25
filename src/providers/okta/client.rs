use crate::config::app::AppProfile;
use crate::providers::okta::auth::LoginRequest;
use crate::saml::Response as SamlResponse;
use anyhow::{anyhow, Result};
use itertools::Itertools;
use kuchiki;
use kuchiki::traits::TendrilSink;
use regex::Regex;
use reqwest::blocking::Client as HttpClient;
use reqwest::blocking::Response;
use reqwest::header::{HeaderValue, ACCEPT, COOKIE};
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::str;
use thiserror::Error as DeriveError;

pub struct Client {
    client: HttpClient,
    profile: AppProfile,
    cookies: HashMap<String, String>,
}

#[derive(DeriveError, Debug)]
pub enum ExtractSamlResponseError {
    #[error("No SAML found")]
    NotFound,
    #[error("Invalid")]
    Invalid(anyhow::Error),
}

impl From<anyhow::Error> for ExtractSamlResponseError {
    fn from(e: anyhow::Error) -> ExtractSamlResponseError {
        ExtractSamlResponseError::Invalid(e)
    }
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

    pub fn get_saml_response(&self, url: Url) -> Result<SamlResponse> {
        let response = self.get_response(url.clone())?.text()?;

        trace!("SAML response doc for app {:?}: {}", &url, &response);

        match extract_saml_response(response.clone()) {
            Err(ExtractSamlResponseError::NotFound) => {
                debug!("No SAML found for app {:?}, will re-login", &url);

                let state_token = extract_state_token(&response)?;
                let _session_token =
                    self.get_session_token(&LoginRequest::from_state_token(state_token))?;
                self.get_saml_response(url)
            }
            Err(_e) => Err(anyhow!("Error extracting SAML response")),
            Ok(saml) => Ok(saml),
        }
    }
}

fn extract_state_token(text: &str) -> Result<String> {
    let re = Regex::new(r#"var stateToken = '(.+)';"#)?;

    if let Some(cap) = re.captures(text) {
        Ok(cap[1].to_owned().replace("\\x2D", "-"))
    } else {
        Err(anyhow!("No state token found"))
    }
}

fn extract_saml_response(text: String) -> Result<SamlResponse, ExtractSamlResponseError> {
    let doc = kuchiki::parse_html().one(text);
    let input_node = doc
        .select("input[name='SAMLResponse']")
        .map_err(|_| ExtractSamlResponseError::NotFound)?
        .next()
        .ok_or(ExtractSamlResponseError::NotFound)?;

    let attributes = &input_node.attributes.borrow();
    let saml = attributes
        .get("value")
        .ok_or(ExtractSamlResponseError::NotFound)?;

    trace!("SAML: {}", saml);
    saml.parse().map_err(|e: anyhow::Error| e.into())
}
