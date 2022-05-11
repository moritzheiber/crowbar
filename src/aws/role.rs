use crate::aws::AWS_DEFAULT_REGION;
use anyhow::{anyhow, Error, Result};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_sts::output::AssumeRoleWithSamlOutput;
use aws_sdk_sts::Region;

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
        splitted.sort_unstable();

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
) -> Result<AssumeRoleWithSamlOutput, Error> {
    let runtime = Runtime::new()?;
    runtime.block_on(async {
        let region_provider =
            RegionProviderChain::default_provider().or_else(Region::new(AWS_DEFAULT_REGION));
        let config = aws_config::from_env().region(region_provider).load().await;
        let client = aws_sdk_sts::Client::new(&config)
            .assume_role_with_saml()
            .principal_arn(provider_arn)
            .role_arn(role_arn)
            .saml_assertion(saml_assertion);

        client.send().await.map_err(|e| e.into())
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
