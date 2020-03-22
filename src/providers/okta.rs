pub mod auth;
pub mod client;
pub mod factors;
pub mod sessions;
pub mod users;

use crate::providers::okta::auth::LoginRequest;
use crate::providers::okta::client::Client;
use anyhow::{anyhow, Result};
use kuchiki;
use kuchiki::traits::TendrilSink;
use regex::Regex;
use reqwest::Url;
use serde_str;
use thiserror::Error as DeriveError;

use crate::saml::Response as SamlResponse;

use std::str;

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum Links {
    Single(Link),
    Multi(Vec<Link>),
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    name: Option<String>,
    #[serde(with = "serde_str")]
    pub href: Url,
    hints: Hint,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Hint {
    allow: Vec<String>,
}

impl Client {
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

#[cfg(test)]
#[test]
fn can_extract_state_token() {}

#[test]
fn can_extract_saml_response() {}
