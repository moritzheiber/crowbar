use base64::decode;
use failure::Error;
use sxd_document::parser;
use sxd_xpath::{Context, Factory, Value};

use std::collections::HashSet;
use std::str::FromStr;

use aws::role::Role;

#[derive(Debug)]
pub struct Response {
    pub raw: String,
    pub roles: HashSet<Role>,
}

impl FromStr for Response {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded_saml = String::from_utf8(decode(&s)?)?;

        trace!("SAML: {}", s);

        let package = parser::parse(&decoded_saml).expect("Failed parsing xml");
        let document = package.as_document();

        let xpath = Factory::new()
            .build("//saml2:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']/saml2:AttributeValue")?
            .ok_or(format_err!("No XPath was compiled"))?;

        let mut context = Context::new();
        context.set_namespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

        let roles = match xpath.evaluate(&context, document.root())? {
            Value::Nodeset(ns) => ns
                .iter()
                .map(|a| a.string_value().parse())
                .collect::<Result<HashSet<Role>, Error>>()?,
            _ => HashSet::new(),
        };

        Ok(Response {
            raw: s.to_owned(),
            roles,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::encode;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn parse_response() {
        let mut f = File::open("tests/fixtures/saml_response.xml").expect("file not found");

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
        ].into_iter()
            .collect::<HashSet<Role>>();

        assert_eq!(response.roles, expected_roles);
    }

    #[test]
    fn parse_response_invalid_no_role() {
        let mut f =
            File::open("tests/fixtures/saml_response_invalid_no_role.xml").expect("file not found");

        let mut saml_xml = String::new();
        f.read_to_string(&mut saml_xml)
            .expect("something went wrong reading the file");

        let saml_base64 = encode(&saml_xml);

        let response: Error = saml_base64.parse::<Response>().unwrap_err();

        assert_eq!(
            response.to_string(),
            "Not enough elements in arn:aws:iam::123456789012:saml-provider/okta-idp"
        );
    }
}
