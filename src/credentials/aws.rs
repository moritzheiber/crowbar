use crate::config::app::AppProfile;
use crate::config::CrowbarConfig;
use crate::credentials::config::ConfigCredentials;
use crate::credentials::Credential;
use crate::credentials::CredentialType;
use crate::providers::adfs::AdfsProvider;
use crate::providers::jumpcloud::JumpcloudProvider;
use crate::providers::okta::OktaProvider;
use crate::providers::ProviderType;
use aws_smithy_types::date_time::Format;
use log::debug;
use serde::{Deserialize, Serialize};

use anyhow::{anyhow, Result};
use aws_sdk_sts::model::Credentials;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::{fmt, str};

const SECONDS_TO_EXPIRATION: i64 = 900; // 15 minutes

#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct AwsCredentials {
    pub version: i32,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub expiration: Option<String>,
}

impl AwsCredentials {
    pub fn is_expired(&self) -> bool {
        match &self.expiration {
            Some(dt) => {
                let expiration = DateTime::parse_from_rfc3339(dt).unwrap();
                expiration.signed_duration_since(Utc::now()).num_seconds() < SECONDS_TO_EXPIRATION
            }
            _ => false,
        }
    }

    pub fn valid(&self) -> bool {
        self.access_key_id.is_some()
            && self.secret_access_key.is_some()
            && self.session_token.is_some()
            && self.expiration.is_some()
    }
}

impl From<Credentials> for AwsCredentials {
    fn from(creds: Credentials) -> Self {
        AwsCredentials {
            version: 1,
            access_key_id: creds.access_key_id().map(|ak| ak.to_owned()),
            secret_access_key: creds.secret_access_key().map(|sk| sk.to_owned()),
            session_token: creds.session_token().map(|t| t.to_owned()),
            expiration: creds
                .expiration()
                .and_then(|t| t.fmt(Format::DateTime).ok()),
        }
    }
}

impl From<HashMap<String, Option<String>>> for AwsCredentials {
    fn from(mut map: HashMap<String, Option<String>>) -> Self {
        AwsCredentials {
            version: 1,
            access_key_id: map.remove("access_key_id").unwrap_or_default(),
            secret_access_key: map.remove("secret_access_key").unwrap_or_default(),
            session_token: map.remove("session_token").unwrap_or_default(),
            expiration: map.remove("expiration").unwrap_or_default(),
        }
    }
}

impl From<AwsCredentials> for HashMap<String, Option<String>> {
    fn from(creds: AwsCredentials) -> HashMap<String, Option<String>> {
        [
            ("access_key_id".to_string(), creds.access_key_id),
            ("secret_access_key".to_string(), creds.secret_access_key),
            ("session_token".to_string(), creds.session_token),
            ("expiration".to_string(), creds.expiration),
        ]
        .iter()
        .cloned()
        .collect()
    }
}

impl Default for AwsCredentials {
    fn default() -> Self {
        AwsCredentials {
            version: 1,
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            expiration: None,
        }
    }
}

impl fmt::Display for AwsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let json = serde_json::to_string(&self);
        write!(f, "{}", json.unwrap().trim())
    }
}

impl Credential<AppProfile, AwsCredentials> for AwsCredentials {
    fn create(_profile: &AppProfile) -> Result<AwsCredentials> {
        Ok(AwsCredentials::default())
    }

    fn load(profile: &AppProfile) -> Result<AwsCredentials> {
        let default_map: HashMap<String, Option<String>> = AwsCredentials::default().into();
        let mut credential_map: HashMap<String, Option<String>> = AwsCredentials::default().into();
        let service = credentials_as_service(profile);

        debug!("Trying to fetch cached AWS credentials for ID {}", &service);

        for key in default_map.keys() {
            let _res = credential_map.insert(
                key.clone(),
                match keyring::Entry::new(&service, key).get_password() {
                    Ok(s) => Some(s),
                    Err(e) => {
                        debug!("Error while fetching credentials: {}", e);
                        break;
                    }
                },
            );
        }

        Ok(AwsCredentials::from(credential_map))
    }

    fn write(self, profile: &AppProfile) -> Result<AwsCredentials> {
        let credential_map: HashMap<String, Option<String>> = self.clone().into();
        let service = credentials_as_service(profile);
        debug!("Saving AWS credentials for {}", &service);

        for (key, secret) in credential_map.iter() {
            if let Some(s) = secret {
                keyring::Entry::new(&service, key)
                    .set_password(s)
                    .map_err(|e| anyhow!("{}", e))?;
            }
        }

        Ok(self)
    }

    fn delete(self, profile: &AppProfile) -> Result<AwsCredentials> {
        let credential_map: HashMap<String, Option<String>> = self.clone().into();
        let service = credentials_as_service(profile);

        for (key, _) in credential_map.iter() {
            let keyring = keyring::Entry::new(&service, key);
            let pass = keyring.get_password();

            if pass.is_ok() {
                debug!("Deleting secret for {} at service {}", &key, &service);
                keyring.delete_password().map_err(|e| anyhow!("{}", e))?
            }
        }

        Ok(self)
    }
}

pub fn fetch_aws_credentials(
    profile: String,
    crowbar_config: CrowbarConfig,
    force_new_credentials: bool,
) -> Result<AwsCredentials> {
    let profiles = crowbar_config
        .read()?
        .profiles
        .into_iter()
        .filter(|p| p.clone().is_profile(&profile))
        .collect::<Vec<AppProfile>>();

    if profiles.is_empty() {
        return Err(anyhow!("No profiles available or empty configuration."));
    }

    let profile = match profiles.first() {
        Some(profile) => Ok(profile),
        None => Err(anyhow!("Unable to use parsed profile")),
    }?;

    if force_new_credentials {
        let _creds = ConfigCredentials::load(profile)
            .map_err(|e| debug!("Couldn't reset credentials: {}", e))
            .and_then(|creds| creds.delete(profile).map_err(|e| debug!("{}", e)));
    }

    let mut aws_credentials = AwsCredentials::load(profile).unwrap_or_default();

    if !aws_credentials.valid() || aws_credentials.is_expired() {
        aws_credentials = match profile.provider {
            ProviderType::Okta => {
                let mut provider = OktaProvider::new(profile)?;
                provider.new_session()?;
                provider.fetch_aws_credentials()?
            }
            ProviderType::Jumpcloud => {
                let mut provider = JumpcloudProvider::new(profile)?;
                provider.new_session()?;
                provider.fetch_aws_credentials()?
            }
            ProviderType::Adfs => {
                let mut provider = AdfsProvider::new(profile)?;
                provider.fetch_aws_credentials()?
            }
        };

        aws_credentials = aws_credentials.write(profile)?;
    }

    Ok(aws_credentials)
}

pub fn credentials_as_service(profile: &AppProfile) -> String {
    format!("crowbar::{}::{}", CredentialType::Aws, profile.name)
}

#[cfg(test)]
mod test {
    use super::*;
    use aws_smithy_types::DateTime;

    const FUTURE: &str = "2038-01-01T10:10:10.311833Z";

    #[test]
    fn shows_if_expired() {
        assert!(!create_credentials().is_expired());
        assert!(create_expired_credentials().is_expired())
    }

    #[test]
    #[should_panic]
    fn shows_if_not_expired() {
        assert!(create_credentials().is_expired());
        assert!(!create_credentials().is_expired())
    }

    #[test]
    fn should_render_proper_json() {
        let json = format!(
            "{}{}{}",
            r#"{"Version":1,"AccessKeyId":"some_key","SecretAccessKey":"some_secret","SessionToken":"some_token","Expiration":""#,
            FUTURE,
            r#""}"#
        );
        assert_eq!(json, format!("{}", create_credentials()))
    }

    #[test]
    fn should_convert_credentials_to_awscredentials() {
        assert_eq!(
            AwsCredentials::from(create_real_aws_credentials()),
            create_credentials()
        )
    }

    #[test]
    fn parses_aws_credentials_to_hashmap() {
        let hash_map: HashMap<String, Option<String>> = create_credentials().into();
        assert_eq!(hash_map, hashmap_credentials());
    }

    #[test]
    fn creates_aws_credentials_from_hashmap() {
        assert_eq!(
            create_credentials(),
            AwsCredentials::from(hashmap_credentials())
        );
    }

    fn create_credentials() -> AwsCredentials {
        AwsCredentials {
            version: 1,
            access_key_id: Some("some_key".to_string()),
            secret_access_key: Some("some_secret".to_string()),
            session_token: Some("some_token".to_string()),
            expiration: Some(FUTURE.to_string()),
        }
    }

    fn create_expired_credentials() -> AwsCredentials {
        AwsCredentials {
            version: 1,
            access_key_id: Some("some_key".to_string()),
            secret_access_key: Some("some_secret".to_string()),
            session_token: Some("some_token".to_string()),
            expiration: Some("2004-01-01T10:10:10Z".to_string()),
        }
    }

    fn create_real_aws_credentials() -> Credentials {
        Credentials::builder()
            .access_key_id("some_key")
            .secret_access_key("some_secret")
            .session_token("some_token")
            .expiration(
                DateTime::from_str(FUTURE, Format::DateTime)
                    .expect("Unable to convert future time for test"),
            )
            .build()
    }

    fn hashmap_credentials() -> HashMap<String, Option<String>> {
        [
            ("access_key_id".to_string(), Some("some_key".to_string())),
            (
                "secret_access_key".to_string(),
                Some("some_secret".to_string()),
            ),
            ("session_token".to_string(), Some("some_token".to_string())),
            ("expiration".to_string(), Some(FUTURE.to_string())),
        ]
        .iter()
        .cloned()
        .collect()
    }
}
