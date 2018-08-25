use failure::Error;
use itertools::Itertools;

use okta::client::Client;

use std::collections::HashSet;
use std::fmt;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequest {
    session_token: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub id: String,
}

#[derive(PartialEq, Eq, Hash)]
pub enum SessionProperties {
    CookieToken,
    CookieTokenUrl,
}

impl fmt::Display for SessionProperties {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SessionProperties::CookieToken => write!(f, "cookieToken"),
            SessionProperties::CookieTokenUrl => write!(f, "cookieTokenUrl"),
        }
    }
}

impl Client {
    pub fn new_session(
        &self,
        session_token: String,
        additional_fields: HashSet<SessionProperties>,
    ) -> Result<SessionResponse, Error> {
        self.post(
            &format!(
                "api/v1/sessions?additionalFields={}",
                additional_fields.iter().join(",")
            ),
            &SessionRequest {
                session_token: Some(session_token),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws::role::Role;
    use base64::encode;
    use saml::Response;
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
