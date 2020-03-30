use crate::config::app::AppProfile;
use crate::credentials::{Credential, CredentialType};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use keyring::Keyring;
use rusoto_sts::Credentials;
use std::collections::HashMap;
use std::{fmt, str};

const SECONDS_TO_EXPIRATION: i64 = 900; // 15 minutes

#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct AwsCredentials {
    version: i32,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    session_token: Option<String>,
    expiration: Option<String>,
}

impl AwsCredentials {
    pub fn is_expired(&self) -> bool {
        match &self.expiration {
            Some(dt) => {
                let expiration = DateTime::parse_from_rfc3339(&dt).unwrap();
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
            access_key_id: Some(creds.access_key_id),
            secret_access_key: Some(creds.secret_access_key),
            session_token: Some(creds.session_token),
            expiration: Some(creds.expiration),
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

impl Into<HashMap<String, Option<String>>> for AwsCredentials {
    fn into(self) -> HashMap<String, Option<String>> {
        [
            ("access_key_id".to_string(), self.access_key_id),
            ("secret_access_key".to_string(), self.secret_access_key),
            ("session_token".to_string(), self.session_token),
            ("expiration".to_string(), self.expiration),
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
    fn new(_profile: &AppProfile) -> Result<AwsCredentials> {
        Ok(AwsCredentials::default())
    }

    fn load(profile: &AppProfile) -> Result<AwsCredentials> {
        let mut credential_map: HashMap<String, Option<String>> = AwsCredentials::default().into();

        let service = format!("crowbar::{}::{}", CredentialType::Aws, profile);

        debug!("Trying to fetch cached AWS credentials for ID {}", service);

        for key in credential_map.clone().keys() {
            let _res = credential_map.insert(
                key.clone(),
                match Keyring::new(&service, key).get_password() {
                    Ok(s) => Some(s),
                    Err(e) => {
                        debug!("Error while fetching credentials: {}", e);
                        None
                    }
                },
            );
        }

        Ok(AwsCredentials::from(credential_map))
    }

    fn write(self, profile: &AppProfile) -> Result<AwsCredentials> {
        let credential_map: HashMap<String, Option<String>> = self.clone().into();
        let service = format!("crowbar::{}::{}", CredentialType::Aws, profile);
        debug!("Saving AWS credentials for {}", &service);

        for (key, secret) in credential_map.iter() {
            Keyring::new(&service, key)
                .set_password(&secret.clone().unwrap())
                .map_err(|e| anyhow!("{}", e))?;
        }

        Ok(self)
    }

    fn delete(self, profile: &AppProfile) -> Result<AwsCredentials> {
        let service = format!("crowbar::aws::{}", profile);
        let username = &profile.name;
        let keyring = Keyring::new(&service, &username);

        debug!("Deleting credentials for {} at {}", &username, service);

        let pass = keyring.get_password();

        if pass.is_ok() {
            keyring.delete_password().map_err(|e| anyhow!("{}", e))?
        }

        Ok(self)
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
            access_key_id: Some("some_key".to_string()),
            secret_access_key: Some("some_secret".to_string()),
            session_token: Some("some_token".to_string()),
            expiration: Some("2038-01-01T10:10:10Z".to_string()),
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
        Credentials {
            access_key_id: "some_key".to_string(),
            secret_access_key: "some_secret".to_string(),
            session_token: "some_token".to_string(),
            expiration: "2038-01-01T10:10:10Z".to_string(),
        }
    }
}
