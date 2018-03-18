use failure::Error;
use rusoto_core;
use rusoto_core::Region;
use rusoto_sts::{AssumeRoleWithSAMLRequest, AssumeRoleWithSAMLResponse, Sts, StsClient};
use rusoto_credential::StaticProvider;

use std::str;
use std::str::FromStr;

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
