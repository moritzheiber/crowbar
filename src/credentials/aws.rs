use crate::config::app::AppProfile;
use crate::credentials::{Credential, CredentialType};

use anyhow::{anyhow, Result};
use base64::{decode, encode};
use chrono::{DateTime, Utc};
use keyring::Keyring;
use rusoto_sts::Credentials;
use std::{fmt, str};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
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
                expiration.signed_duration_since(Utc::now()).num_seconds() < 0
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
        let username = &profile.name;
        let service = format!("crowbar::{}::{}", CredentialType::Aws, profile);

        debug!(
            "Trying to fetch cached AWS credentials for {} for ID {}",
            username, service
        );

        let encoded_creds = match Keyring::new(&service, username).get_password() {
            Ok(ec) => Some(ec),
            Err(e) => {
                debug!("Couldn't retrieve credentials: {}", e);
                None
            }
        };

        match encoded_creds {
            None => Ok(AwsCredentials::default()),
            Some(aws_creds) => {
                let decoded_creds = decode(aws_creds).map_err(|e| anyhow!("{}", e))?;

                match str::from_utf8(decoded_creds.as_slice()) {
                    Ok(creds) => Ok(serde_json::from_str(creds).map_err(|e| anyhow!("{}", e))?),
                    Err(e) => Err(e.into()),
                }
            }
        }
    }

    fn write(self, profile: &AppProfile) -> Result<AwsCredentials> {
        let service = format!("crowbar::aws::{}", profile);
        let username = &profile.name;
        debug!("Saving AWS credentials for {}", username);

        Keyring::new(&service, username)
            .set_password(encode(&serde_json::to_string(&self)?).as_str())
            .map_err(|e| anyhow!("{}", e))?;

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
