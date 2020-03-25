pub mod auth;
pub mod client;
pub mod factors;
pub mod sessions;
pub mod users;

use crate::aws::role as RoleManager;
use crate::aws::role::Role as AwsRole;
use crate::config::app::AppProfile;
use crate::credentials::aws::AwsCredentials;
use crate::credentials::config::ConfigCredentials;
use crate::credentials::Credential;
use crate::providers::okta::auth::LoginRequest;
use crate::providers::okta::client::Client;
use crate::providers::{Provider, ProviderSession};
use crate::saml::Response as SamlResponse;
use anyhow::{anyhow, Context, Result};
use dialoguer::{theme::SimpleTheme, Select};
use kuchiki;
use kuchiki::traits::TendrilSink;
use regex::Regex;
use reqwest::Url;
use serde_str;
use std::collections::HashSet;
use std::str;
use thiserror::Error as DeriveError;

pub struct OktaProvider {
    client: Client,
}

pub struct OktaSessionId {
    id: String,
}

impl OktaProvider {
    pub fn new(profile: &AppProfile) -> OktaProvider {
        OktaProvider {
            client: Client::new(profile.clone()),
        }
    }
}

impl Provider<AppProfile, ProviderSession<OktaSessionId>, AwsCredentials> for OktaProvider {
    fn new_session(&self, profile: &AppProfile) -> Result<ProviderSession<OktaSessionId>> {
        let config_credentials =
            ConfigCredentials::load(profile).or_else(|_| ConfigCredentials::new(profile))?;

        let username = &profile.username;
        let password = &config_credentials.password;
        let session_id = self
            .client
            .new_session(
                self.client
                    .get_session_token(&LoginRequest::from_credentials(
                        username.clone(),
                        password.clone(),
                    ))?,
                &HashSet::new(),
            )?
            .id;

        let session = OktaSessionId { id: session_id };

        config_credentials.write(profile)?;

        Ok(ProviderSession { session })
    }

    fn fetch_aws_credentials(
        &mut self,
        profile: &AppProfile,
        provider_session: &ProviderSession<OktaSessionId>,
    ) -> Result<AwsCredentials> {
        self.client
            .set_session_id(provider_session.session.id.clone());

        debug!("Requesting temporary STS credentials for {}", &profile.name);

        let url = profile.clone().request_url().unwrap();
        let saml = self
            .client
            .get_saml_response(url)
            .with_context(|| format!("Error getting SAML response for profile {}", profile.name))?;

        trace!("SAML response: {:?}", saml);

        let roles = saml.roles;

        debug!("SAML Roles: {:?}", &roles);

        let selection = match roles.clone() {
            r if r.len() < 2 => 0,
            r => Select::with_theme(&SimpleTheme)
                .with_prompt("Select the role to assume:")
                .default(0)
                .items(
                    &r.iter()
                        .map(|r| r.clone().role_arn)
                        .collect::<Vec<String>>(),
                )
                .interact()
                .unwrap(),
        };

        let role: &AwsRole = roles.iter().collect::<Vec<&AwsRole>>()[selection];

        debug!("Found role: {} for profile {}", &role, &profile.name);

        let assumption_response = RoleManager::assume_role(role, saml.raw)
            .with_context(|| format!("Error assuming role for profile {}", profile.name))?;

        let credentials = AwsCredentials::from(
            assumption_response
                .credentials
                .with_context(|| "Error fetching credentials from assumed AWS role")?,
        );

        trace!("Credentials: {:?}", credentials);
        Ok(credentials)
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
