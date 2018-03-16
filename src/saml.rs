use base64::decode;
use failure::Error;
use sxd_document::parser;
use sxd_xpath::{Context, Factory, Value};

use std::str::FromStr;

use aws::Role;

#[derive(Debug)]
pub struct Response {
    pub raw: String,
    pub roles: Vec<Role>,
}

impl FromStr for Response {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded_saml = String::from_utf8(decode(&s)?)?;

        debug!("Decoded SAML: {}", decoded_saml);

        let package = parser::parse(&decoded_saml).expect("Failed parsing xml");
        let document = package.as_document();

        let xpath = Factory::new()
            .build("//saml2:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']/saml2:AttributeValue")?
            .expect("No XPath was compiled");

        let mut context = Context::new();
        context.set_namespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

        let value = xpath
            .evaluate(&context, document.root())
            .expect("XPath evaluation failed");

        let mut roles = Vec::new();
        if let Value::Nodeset(ns) = value {
            for a in ns.iter() {
                roles.push(a.string_value().parse()?);
            }
        }

        Ok(Response {
            raw: s.to_owned(),
            roles,
        })
    }
}
