use crate::aws::role::Role;
use crate::config::app::AppProfile;
use crate::credentials::config as ConfigCredentials;
use crate::credentials::{CredentialState, State};
use crate::providers::okta::auth::LoginRequest;
use crate::providers::okta::client::Client as OktaClient;

use anyhow::{anyhow, Context, Result};
use base64::{decode, encode};
use chrono::{DateTime, Utc};
use dialoguer::{theme::SimpleTheme, Select};
use keyring::{Keyring, KeyringError};
use rusoto_sts::Credentials;
use std::collections::HashSet;
use std::{fmt, str};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct AwsCredentials {
    version: i32,
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

impl AwsCredentials {
    pub fn is_expired(&self) -> bool {
        let expiration = DateTime::parse_from_rfc3339(&self.expiration).unwrap();
        expiration.signed_duration_since(Utc::now()).num_seconds() < 0
    }
}

impl State for AwsCredentials {
    fn state(&self) -> CredentialState {
        if self.is_expired() {
            CredentialState::Expired
        } else {
            CredentialState::Valid
        }
    }
}

impl fmt::Display for AwsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let json = serde_json::to_string(&self);
        write!(f, "{}", json.unwrap().trim())
    }
}

impl From<Credentials> for AwsCredentials {
    fn from(creds: Credentials) -> Self {
        AwsCredentials {
            version: 1,
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
            expiration: creds.expiration,
        }
    }
}

pub fn fetch_credentials(
    okta_client: &mut OktaClient,
    profile: &AppProfile,
    force_new_password: bool,
) -> Result<AwsCredentials> {
    let username = &profile.username;
    let password = ConfigCredentials::get_password(&profile, username, force_new_password)?;

    let session_id = okta_client
        .new_session(
            okta_client.get_session_token(&LoginRequest::from_credentials(
                username.clone(),
                password.clone(),
            ))?,
            &HashSet::new(),
        )?
        .id;
    okta_client.set_session_id(session_id);

    ConfigCredentials::save(&profile, &username, &password)?;
    fetch_sts_assume_role_credentials(&okta_client, &profile)
}

pub fn fetch_sts_assume_role_credentials(
    client: &OktaClient,
    profile: &AppProfile,
) -> Result<AwsCredentials> {
    debug!("Requesting temporary STS credentials for {}", profile.name);

    let url = profile.clone().request_url().unwrap();
    let saml = client
        .get_saml_response(url)
        .with_context(|| format!("Error getting SAML response for profile {}", profile.name))?;

    trace!("SAML response: {:?}", saml);

    let roles = saml.roles;

    debug!("SAML Roles: {:?}", &roles);

    let selection = match &roles {
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

    let role: &Role = roles.iter().collect::<Vec<&Role>>()[selection];

    debug!("Found role: {} for profile {}", &role, &profile.name);

    let assumption_response = crate::aws::role::assume_role(role.clone(), saml.raw)
        .with_context(|| format!("Error assuming role for profile {}", profile.name))?;

    let credentials = AwsCredentials::from(
        assumption_response
            .credentials
            .with_context(|| "Error fetching credentials from assumed AWS role")?,
    );

    trace!("Credentials: {:?}", credentials);

    Ok(credentials)
}

pub fn load(profile: &AppProfile) -> Option<AwsCredentials> {
    let profile_name = &profile.name;
    let id = format!("crowbar::aws::{}", &profile);

    debug!(
        "Trying to fetch AWS credentials for {} for ID {}",
        profile_name, id
    );

    let encoded_creds = match Keyring::new(&id, profile_name).get_password() {
        Ok(ec) => Some(ec),
        Err(e) => {
            debug!("Couldn't retrieve credentials: {}", e);
            None
        }
    };

    match encoded_creds {
        None => None,
        Some(creds) => {
            let decoded_creds = match decode(&creds) {
                Ok(c) => Some(c),
                Err(e) => {
                    error!("Failed decoding the credentials: {}", e);
                    return None;
                }
            };

            match str::from_utf8(decoded_creds.unwrap().as_slice()) {
                Ok(creds) => match serde_json::from_str(creds) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        error!("Failed to deserialize the credentials: {}", e);
                        None
                    }
                },
                Err(e) => {
                    error!(
                        "Failed to translate the decoded credentials into a string: {}",
                        e
                    );
                    None
                }
            }
        }
    }
}

pub fn save(profile: &AppProfile, credentials: AwsCredentials) -> Result<AwsCredentials> {
    debug!("Saving AWS credentials for {}", profile.name);

    match Keyring::new(&format!("crowbar::aws::{}", &profile), &profile.name)
        .set_password(encode(&serde_json::to_string(&credentials)?).as_str())
    {
        Ok(_s) => Ok(credentials),
        Err(e) => Err(anyhow!("{}", e)),
    }
}

pub fn delete(profile: &AppProfile) -> Result<()> {
    let id = &format!("crowbar::aws::{}", &profile);
    let profile = &profile.name;

    debug!("Deleting credentials for {} at {}", profile, id);

    match Keyring::new(id, profile).delete_password() {
        Err(KeyringError::NoPasswordFound) => Ok(()),
        Err(e) => Err(anyhow!("{}", e)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn shows_if_expired() {
        assert_eq!(false, create_credentials().is_expired());
        assert_eq!(true, create_expired_credentials().is_expired())
    }

    #[test]
    #[should_panic]
    fn shows_if_not_expired() {
        assert_eq!(true, create_credentials().is_expired());
        assert_eq!(false, create_credentials().is_expired())
    }

    #[test]
    fn returns_valid_state() {
        assert_eq!(
            CredentialState::Expired,
            create_expired_credentials().state()
        );
        assert_eq!(CredentialState::Valid, create_credentials().state())
    }

    #[test]
    #[should_panic]
    fn returns_invalid_state() {
        assert_eq!(CredentialState::Valid, create_expired_credentials().state());
        assert_eq!(CredentialState::Expired, create_credentials().state())
    }

    #[test]
    fn should_render_proper_json() {
        let json = r#"{"Version":1,"AccessKeyId":"some_key","SecretAccessKey":"some_secret","SessionToken":"some_token","Expiration":"2038-01-01T10:10:10Z"}"#;
        assert_eq!(json, format!("{}", create_credentials()))
    }

    #[test]
    fn should_convert_credentials_to_awscredentials() {
        assert_eq!(
            AwsCredentials::from(create_real_aws_credentials()),
            create_credentials()
        )
    }

    fn create_credentials() -> AwsCredentials {
        AwsCredentials {
            version: 1,
            access_key_id: "some_key".to_string(),
            secret_access_key: "some_secret".to_string(),
            session_token: "some_token".to_string(),
            expiration: "2038-01-01T10:10:10Z".to_string(),
        }
    }
    fn create_expired_credentials() -> AwsCredentials {
        AwsCredentials {
            version: 1,
            access_key_id: "some_key".to_string(),
            secret_access_key: "some_secret".to_string(),
            session_token: "some_token".to_string(),
            expiration: "2004-01-01T10:10:10Z".to_string(),
        }
    }

    fn create_real_aws_credentials() -> Credentials {
        Credentials {
            access_key_id: "some_key".to_string(),
            secret_access_key: "some_secret".to_string(),
            session_token: "some_token".to_string(),
            expiration: "2038-01-01T10:10:10Z".to_string(),
        }
    }
}
