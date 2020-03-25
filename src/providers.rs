pub mod okta;

use anyhow::{anyhow, Result};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ProviderType {
    #[serde(alias = "okta", alias = "OKTA")]
    Okta,
}

pub struct ProviderSession<T> {
    session: T,
}

pub trait Provider<T, U, C> {
    fn new_session(&self, profile: &T) -> Result<U>;
    fn fetch_aws_credentials(&mut self, profile: &T, session: &U) -> Result<C>;
}

impl FromStr for ProviderType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "okta" | "OKTA" | "Okta" => Ok(ProviderType::Okta),
            _ => Err(anyhow!("Unable to determine provider type")),
        }
    }
}
