pub mod auth;
pub mod client;
pub mod factors;
pub mod sessions;
pub mod structure;
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
use anyhow::{Context, Result};
use dialoguer::{theme::SimpleTheme, Select};
use std::collections::HashSet;

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

#[cfg(test)]
mod test {
    #[test]
    fn can_extract_state_token() {}

    #[test]
    fn can_extract_saml_response() {}
}
