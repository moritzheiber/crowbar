pub mod okta;

use crate::config::app::AppProfile;
use crate::credentials::aws as AwsCredentialsOperator;
use crate::credentials::aws::AwsCredentials;
use crate::credentials::{CredentialState, State};
use crate::providers::okta::client::Client as OktaClient;
use anyhow::{anyhow, Result};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ProviderType {
    #[serde(alias = "okta", alias = "OKTA")]
    Okta,
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

trait Provider {}

pub fn fetch_credentials(
    profile: &AppProfile,
    force_new_credentials: bool,
) -> Result<AwsCredentials> {
    match profile.provider {
        ProviderType::Okta => {
            let mut okta_client = OktaClient::new(profile.clone());

            if force_new_credentials {
                AwsCredentialsOperator::delete(&profile)?
            };

            let loaded_credentials = AwsCredentialsOperator::load(&profile);
            let aws_creds = match loaded_credentials {
                Some(creds) => match creds.state() {
                    CredentialState::Valid => creds,
                    CredentialState::Expired => {
                        debug!("AWS credentials expired");
                        AwsCredentialsOperator::fetch_credentials(
                            &mut okta_client,
                            &profile,
                            &force_new_credentials,
                        )?
                    }
                },
                None => {
                    debug!("No stored AWS credentials found");
                    AwsCredentialsOperator::fetch_credentials(
                        &mut okta_client,
                        &profile,
                        &force_new_credentials,
                    )?
                }
            };

            Ok(AwsCredentialsOperator::save(&profile, aws_creds)?)
        }
    }
}
