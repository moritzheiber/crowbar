// pub mod adfs;
pub mod jumpcloud;
pub mod okta;

use anyhow::{anyhow, Result};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ProviderType {
    #[serde(alias = "okta", alias = "OKTA")]
    Okta,
    #[serde(alias = "jumpcloud", alias = "JUMPCLOUD", alias = "JumpCloud")]
    Jumpcloud,
    /* #[serde(alias = "ADFS", alias = "adfs")]
    Adfs, */
}

impl FromStr for ProviderType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        match s.as_str() {
            "okta" => Ok(ProviderType::Okta),
            "jumpcloud" => Ok(ProviderType::Jumpcloud),
            // "adfs" => Ok(ProviderType::Adfs),
            _ => Err(anyhow!("Unable to determine provider type")),
        }
    }
}
