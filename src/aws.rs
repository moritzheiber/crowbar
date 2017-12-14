use base64::decode;
use failure::Error;
use ini::Ini;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use rusoto_core::{default_tls_client, Region};
use rusoto_sts::{AssumeRoleWithSAMLRequest, AssumeRoleWithSAMLResponse, Credentials, Sts,
                 StsClient};
use rusoto_credential::StaticProvider;

use std::env;
use std::str;
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
struct AwsCredentialStore {
    aws_access_key_id: String,
    aws_secret_access_key: String,
    aws_session_token: String,
}

pub fn find_saml_attributes(saml_assertion: &str) -> Result<HashMap<String, String>, Error> {
    let decoded_saml = String::from_utf8(decode(&saml_assertion)?)?;

    let mut reader = Reader::from_str(&decoded_saml);
    reader.trim_text(true);

    let mut values = HashMap::new();
    let mut buf = Vec::new();
    let mut in_attribute_value = false;

    let attribute_value_name = b"saml2:AttributeValue";

    loop {
        match reader.read_event(&mut buf) {
            Ok(Event::Start(ref e)) => {
                if e.name() == attribute_value_name {
                    in_attribute_value = true;
                }
            }
            Ok(Event::End(ref e)) => {
                if e.name() == attribute_value_name {
                    in_attribute_value = false;
                }
            }
            Ok(Event::Text(e)) => {
                if in_attribute_value {
                    let value = e.unescape_and_decode(&reader).unwrap();
                    let splitted: Vec<&str> = value.split(',').collect();

                    if splitted.len() == 2 {
                        values.insert(splitted[1].to_owned(), splitted[0].to_owned());
                    }
                }
            }
            Ok(Event::Eof) => break, // exits the loop when reaching end of file
            Err(e) => panic!("Error at position {}: {:?}", reader.buffer_position(), e),
            _ => (), // There are several other `Event`s we do not consider here
        }

        // if we don't keep a borrow elsewhere, we can clear the buffer to keep memory usage low
        buf.clear();
    }

    Ok(values)
}

pub fn assume_role(
    principal_arn: &str,
    role_arn: &str,
    saml_assertion: &str,
) -> Result<AssumeRoleWithSAMLResponse, Error> {
    let provider = StaticProvider::new_minimal(String::from(""), String::from(""));

    let req = AssumeRoleWithSAMLRequest {
        duration_seconds: None,
        policy: None,
        principal_arn: String::from(principal_arn),
        role_arn: String::from(role_arn),
        saml_assertion: String::from(saml_assertion),
    };

    let client = StsClient::new(default_tls_client()?, provider, Region::UsEast1);

    Ok(client.assume_role_with_saml(&req)?)
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

    Ok(conf.write_to_file(path)?)
}
