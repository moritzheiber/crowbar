use failure::Error;
use ini::Ini;
use rusoto_core;
use rusoto_core::Region;
use rusoto_sts::{AssumeRoleWithSAMLRequest, AssumeRoleWithSAMLResponse, Credentials, Sts,
                 StsClient};
use rusoto_credential::StaticProvider;

use std::env;
use std::str;
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
struct AwsCredentialStore {
    aws_access_key_id: String,
    aws_secret_access_key: String,
    aws_session_token: String,
}

#[derive(Debug)]
pub struct Role {
    pub provider_arn: String,
    pub role_arn: String,
}

impl FromStr for Role {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let splitted: Vec<&str> = s.split(',').collect();

        match splitted.len() {
            0 | 1 => bail!("Not enough elements in {}", s),
            2 => Ok(Role {
                provider_arn: String::from(splitted[0]),
                role_arn: String::from(splitted[1]),
            }),
            _ => bail!("Too many elements in {}", s),
        }
    }
}

impl Role {
    pub fn role_name(&self) -> Result<&str, Error> {
        let splitted: Vec<&str> = self.role_arn.split('/').collect();

        match splitted.len() {
            0 | 1 => bail!("Not enough elements in {}", self.role_arn),
            2 => Ok(splitted[1]),
            _ => bail!("Too many elements in {}", self.role_arn),
        }
    }
}

pub fn assume_role(
    Role {
        provider_arn,
        role_arn,
    }: Role,
    saml_assertion: String,
) -> Result<AssumeRoleWithSAMLResponse, Error> {
    let req = AssumeRoleWithSAMLRequest {
        duration_seconds: None,
        policy: None,
        principal_arn: provider_arn,
        role_arn,
        saml_assertion,
    };

    let provider = StaticProvider::new_minimal(String::from(""), String::from(""));
    let client = StsClient::new(
        rusoto_core::default_tls_client()?,
        provider,
        Region::UsEast1,
    );

    client.assume_role_with_saml(&req).map_err(|e| e.into())
}

pub fn set_credentials(profile: &str, credentials: &Credentials) -> Result<(), Error> {
    let path_buf = env::home_dir().unwrap().join(".aws/credentials");
    let path = path_buf.to_str().unwrap();

    let mut conf = Ini::load_from_file(path)?;

    conf.with_section(Some(profile.to_owned()))
        .set("aws_access_key_id", credentials.access_key_id.to_owned())
        .set(
            "aws_secret_access_key",
            credentials.secret_access_key.to_owned(),
        )
        .set("aws_session_token", credentials.session_token.to_owned());

    info!("Saving AWS credentials to {}", path);
    conf.write_to_file(path).map_err(|e| e.into())
}
