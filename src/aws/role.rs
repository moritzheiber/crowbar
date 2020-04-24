use anyhow::{anyhow, Error, Result};
use rusoto_core::request::HttpClient;
use rusoto_core::Region;
use rusoto_credential::StaticProvider;
use rusoto_sts::{AssumeRoleWithSAMLRequest, AssumeRoleWithSAMLResponse, Sts, StsClient};

use std::str::FromStr;
use std::{fmt, str};
use tokio::runtime::Runtime;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Role {
    pub provider_arn: String,
    pub role_arn: String,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.role_arn)
    }
}

impl FromStr for Role {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut splitted: Vec<&str> = s.split(',').map(|s| s.trim()).collect();
        splitted.sort();

        match splitted.len() {
            0 | 1 => Err(anyhow!("Not enough elements in {}", s)),
            2 => Ok(Role {
                role_arn: String::from(splitted[0]),
                provider_arn: String::from(splitted[1]),
            }),
            _ => Err(anyhow!("Too many elements in {}", s)),
        }
    }
}

pub fn assume_role(
    Role {
        provider_arn,
        role_arn,
    }: &Role,
    saml_assertion: String,
) -> Result<AssumeRoleWithSAMLResponse, Error> {
    let req = AssumeRoleWithSAMLRequest {
        duration_seconds: None,
        policy: None,
        policy_arns: None,
        principal_arn: provider_arn.to_owned(),
        role_arn: role_arn.to_owned(),
        saml_assertion,
    };

    let provider = StaticProvider::new_minimal(String::from(""), String::from(""));
    let client = StsClient::new_with(HttpClient::new()?, provider, Region::default());

    trace!("Assuming role: {:?}", &req);

    let mut runtime = Runtime::new()?;
    runtime.block_on(async {
        client
            .assume_role_with_saml(req)
            .await
            .map_err(|e| e.into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_attribute() {
        let attribute =
            "arn:aws:iam::123456789012:saml-provider/okta-idp,arn:aws:iam::123456789012:role/role1";

        let expected_role = create_role();

        assert_eq!(attribute.parse::<Role>().unwrap(), expected_role);
    }

    #[test]
    fn expected_string_output_for_role() {
        assert_eq!(
            "arn:aws:iam::123456789012:role/role1",
            format!("{}", create_role())
        )
    }

    fn create_role() -> Role {
        Role {
            provider_arn: "arn:aws:iam::123456789012:saml-provider/okta-idp".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/role1".to_string(),
        }
    }
}
