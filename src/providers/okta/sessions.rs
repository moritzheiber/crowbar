use crate::providers::okta::client::Client;
use anyhow::Result;
use itertools::Itertools;
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

#[allow(dead_code)]
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
        additional_fields: &HashSet<SessionProperties>,
    ) -> Result<SessionResponse> {
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
