use crate::aws::role as RoleManager;
use crate::aws::role::Role;
use crate::credentials::aws::AwsCredentials;
use crate::utils;

use anyhow::{anyhow, Context as AnyhowContext, Result};
use base64::decode;
use kuchiki;
use kuchiki::traits::TendrilSink;
use std::collections::HashSet;
use std::str::FromStr;
use sxd_document::parser;
use sxd_xpath::{Context, Factory, Value};
use thiserror::Error as DeriveError;

#[derive(Debug)]
pub struct Response {
    pub raw: String,
    pub roles: HashSet<Role>,
}

#[derive(DeriveError, Debug)]
pub enum ExtractSamlResponseError {
    #[error("No SAML found")]
    NotFound,
    #[error("Invalid")]
    Invalid(anyhow::Error),
}

impl From<anyhow::Error> for ExtractSamlResponseError {
    fn from(e: anyhow::Error) -> ExtractSamlResponseError {
        ExtractSamlResponseError::Invalid(e)
    }
}

impl FromStr for Response {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let decoded_saml = String::from_utf8(decode(&s)?)?;

        trace!("SAML: {}", s);

        let package = parser::parse(&decoded_saml).expect("Failed parsing xml");
        let document = package.as_document();

        let xpath = Factory::new()
            .build("//saml2:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']/saml2:AttributeValue")?
            .with_context(|| "No XPath was compiled")?;

        let mut context = Context::new();
        context.set_namespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

        let roles = match xpath.evaluate(&context, document.root())? {
            Value::Nodeset(ns) => ns
                .iter()
                .map(|a| a.string_value().parse())
                .collect::<Result<HashSet<Role>, anyhow::Error>>()?,
            _ => HashSet::new(),
        };

        Ok(Response {
            raw: s.to_owned(),
            roles,
        })
    }
}

pub fn extract_saml_response(text: String) -> Result<Response, ExtractSamlResponseError> {
    let doc = kuchiki::parse_html().one(text);
    let input_node = doc
        .select("input[name='SAMLResponse']")
        .map_err(|_| ExtractSamlResponseError::NotFound)?
        .next()
        .ok_or(ExtractSamlResponseError::NotFound)?;

    let attributes = &input_node.attributes.borrow();
    let saml = attributes
        .get("value")
        .ok_or(ExtractSamlResponseError::NotFound)?;

    saml.parse().map_err(|e: anyhow::Error| e.into())
}

pub fn get_credentials_from_saml(input: String) -> Result<AwsCredentials> {
    let saml = match extract_saml_response(input) {
        Err(_e) => Err(anyhow!("Error extracting SAML response")),
        Ok(saml) => Ok(saml),
    }?;

    debug!("SAML response: {:?}", saml);

    let roles = saml.roles;

    debug!("SAML Roles: {:?}", &roles);

    let role = utils::select_role(roles)?;

    let assumption_response =
        RoleManager::assume_role(&role, saml.raw).with_context(|| "Error assuming role")?;

    Ok(AwsCredentials::from(
        assumption_response
            .credentials
            .with_context(|| "Error fetching credentials from assumed AWS role")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::encode;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn parse_okta_response() {
        let mut f = File::open("tests/fixtures/okta/saml_response.xml").expect("file not found");

        let mut saml_xml = String::new();
        f.read_to_string(&mut saml_xml)
            .expect("something went wrong reading the file");

        let saml_base64 = encode(&saml_xml);

        let response: Response = saml_base64.parse().unwrap();

        let expected_roles = vec![
            Role {
                provider_arn: String::from("arn:aws:iam::123456789012:saml-provider/okta-idp"),
                role_arn: String::from("arn:aws:iam::123456789012:role/role1"),
            },
            Role {
                provider_arn: String::from("arn:aws:iam::123456789012:saml-provider/okta-idp"),
                role_arn: String::from("arn:aws:iam::123456789012:role/role2"),
            },
        ]
        .into_iter()
        .collect::<HashSet<Role>>();

        assert_eq!(response.roles, expected_roles);
    }

    #[test]
    fn parse_jumpcloud_response() {
        let mut f =
            File::open("tests/fixtures/jumpcloud/saml_response.xml").expect("file not found");

        let mut saml_xml = String::new();
        f.read_to_string(&mut saml_xml)
            .expect("something went wrong reading the file");

        let saml_base64 = encode(&saml_xml);

        let response: Response = saml_base64.parse().unwrap();
        let expected_roles = vec![
            Role {
                provider_arn: String::from("arn:aws:iam::000000000000:saml-provider/jumpcloud"),
                role_arn: String::from("arn:aws:iam::000000000000:role/jumpcloud-admin"),
            },
            Role {
                provider_arn: String::from("arn:aws:iam::000000000000:saml-provider/jumpcloud"),
                role_arn: String::from("arn:aws:iam::000000000000:role/jumpcloud-user"),
            },
        ]
        .into_iter()
        .collect::<HashSet<Role>>();

        assert_eq!(response.roles, expected_roles);
    }

    #[test]
    fn parse_response_invalid_no_role() {
        let mut f = File::open("tests/fixtures/okta/saml_response_invalid_no_role.xml")
            .expect("file not found");

        let mut saml_xml = String::new();
        f.read_to_string(&mut saml_xml)
            .expect("something went wrong reading the file");

        let saml_base64 = encode(&saml_xml);

        let response: anyhow::Error = saml_base64.parse::<Response>().unwrap_err();

        assert_eq!(
            response.to_string(),
            "Not enough elements in arn:aws:iam::123456789012:saml-provider/okta-idp"
        );
    }
}
