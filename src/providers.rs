pub mod jumpcloud;
pub mod okta;

use anyhow::{anyhow, Result};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ProviderType {
    #[serde(alias = "okta", alias = "OKTA")]
    Okta,
    #[serde(alias = "Jumpcloud", alias = "JUMPCLOUD", alias = "JumpCloud")]
    Jumpcloud,
}

pub trait Provider<C> {
    fn new_session(&mut self) -> Result<&Self>;
    fn fetch_aws_credentials(&self) -> Result<C>;
}

impl FromStr for ProviderType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        match s.as_str() {
            "okta" => Ok(ProviderType::Okta),
            "jumpcloud" => Ok(ProviderType::Jumpcloud),
            _ => Err(anyhow!("Unable to determine provider type")),
        }
    }
}
