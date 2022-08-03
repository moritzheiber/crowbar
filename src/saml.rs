use crate::aws::role as RoleManager;
use crate::aws::role::Role;
use crate::credentials::aws::AwsCredentials;
use crate::utils;

use anyhow::{anyhow, Context as AnyhowContext, Result};
use base64::decode;
use log::{debug, trace};
use select::document::Document;
use select::predicate::Attr;
use std::collections::HashSet;
use std::str::FromStr;
use sxd_document::parser;
use sxd_xpath::{Context, Factory, Value};

#[derive(PartialEq, Debug)]
pub struct Response {
    pub raw: String,
    pub roles: HashSet<Role>,
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

pub fn get_credentials_from_saml(input: String, role: Option<String>) -> Result<AwsCredentials> {
    let saml = extract_saml_assertion(&input)?;

    debug!("SAML response: {:?}", &saml);

    let roles = saml.roles;

    debug!("SAML Roles: {:?}", &roles);

    let role = utils::select_role(roles, role)?;

    let assumption_response =
        RoleManager::assume_role(&role, saml.raw).with_context(|| "Error assuming role")?;

    Ok(AwsCredentials::from(
        assumption_response.credentials.with_context(|| {
            "Error fetching credentials for selected AWS role from assumption response"
        })?,
    ))
}

pub fn extract_saml_assertion(text: &str) -> Result<Response> {
    let document = Document::from(text);
    let node = document.find(Attr("name", "SAMLResponse")).next();

    if let Some(element) = node {
        if let Some(value) = element.attr("value") {
            value.parse()
        } else {
            Err(anyhow!("Missing SAML response in assertion element"))
        }
    } else {
        Err(anyhow!("Could not find SAML element in HTML response"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::encode;
    use claim::assert_ok;
    use std::fs;

    #[test]
    fn parse_okta_response() -> Result<()> {
        let response = get_response("tests/fixtures/okta/saml_response.xml")?;
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

        Ok(())
    }

    #[test]
    fn parse_jumpcloud_response() -> Result<()> {
        let response = get_response("tests/fixtures/jumpcloud/saml_response.xml")?;
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

        Ok(())
    }

    #[test]
    #[should_panic(
        expected = "Not enough elements in arn:aws:iam::123456789012:saml-provider/okta-idp"
    )]
    fn parse_response_invalid_no_role() {
        get_response("tests/fixtures/okta/saml_response_invalid_no_role.xml").unwrap();
    }

    #[test]
    fn can_parse_html_text_response() -> Result<()> {
        let html: String = fs::read_to_string("tests/fixtures/jumpcloud/html_saml_response.html")?;
        let saml_response = extract_saml_assertion(&html);

        assert_ok!(saml_response);

        Ok(())
    }

    fn get_response(path: &str) -> Result<Response> {
        let saml_xml: String = fs::read_to_string(path)?;
        let saml_base64 = encode(&saml_xml);
        saml_base64.parse()
    }
}
