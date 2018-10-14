pub mod auth;
pub mod client;
pub mod factors;
pub mod sessions;
pub mod users;

use failure::{Compat, Error};
use kuchiki;
use kuchiki::traits::TendrilSink;
use okta::auth::LoginRequest;
use okta::client::Client;
use regex::Regex;
use reqwest::Url;
use serde_str;

use saml::Response as SamlResponse;

use std::str;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct Organization {
    pub name: String,
    pub base_url: Url,
}

impl FromStr for Organization {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Organization {
            name: String::from(s),
            base_url: Url::parse(&format!("https://{}.okta.com/", s))?,
        })
    }
}

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
    pub fn get_saml_response(&self, app_url: Url) -> Result<SamlResponse, Error> {
        let response = self.get_response(app_url.clone())?.text()?;

        trace!("SAML response doc for app {:?}: {}", &app_url, &response);

        match extract_saml_response(response.clone()) {
            Err(ExtractSamlResponseError::NotFound) => {
                debug!("No SAML found for app {:?}, will re-login", &app_url);

                let state_token = extract_state_token(&response)?;
                let session_token =
                    self.get_session_token(&LoginRequest::from_state_token(state_token))?;
                self.get_saml_response(app_url)
            }
            Err(e) => Err(e.into()),
            Ok(saml) => Ok(saml),
        }
    }
}

fn extract_state_token(text: &str) -> Result<String, Error> {
    let re = Regex::new(r#"var stateToken = '(.+)';"#)?;

    if let Some(cap) = re.captures(text) {
        Ok(cap[1].to_owned().replace("\\x2D", "-"))
    } else {
        bail!("No state token found")
    }
}

pub fn extract_saml_response(text: String) -> Result<SamlResponse, ExtractSamlResponseError> {
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
    saml.parse().map_err(|e: Error| e.into())
}

#[derive(Fail, Debug)]
pub enum ExtractSamlResponseError {
    #[fail(display = "No SAML found")]
    NotFound,
    #[fail(display = "{}", _0)]
    Invalid(#[cause] Compat<Error>),
}

impl From<Error> for ExtractSamlResponseError {
    fn from(e: Error) -> ExtractSamlResponseError {
        ExtractSamlResponseError::Invalid(e.compat())
    }
}
