use crate::providers::okta::client::Client;
use crate::providers::okta::factors::Factor;
use crate::providers::okta::response::{Response, User};
use crate::providers::okta::API_AUTHN_PATH;

use anyhow::Result;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<Options>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state_token: Option<String>,
}

impl LoginRequest {
    pub fn from_credentials(username: String, password: String) -> Self {
        Self {
            username: Some(username),
            password: Some(password),
            relay_state: None,
            options: None,
            state_token: None,
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LoginEmbedded {
    #[serde(default)]
    pub factors: Vec<Factor>,
    user: User,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Options {
    multi_optional_factor_enroll: bool,
    warn_before_password_expired: bool,
}

impl Client {
    pub fn login(&self, req: &LoginRequest) -> Result<Response> {
        let url = self.base_url.join(API_AUTHN_PATH)?;
        self.post(url, req)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::providers::okta::response::{FactorResult, Status};
    use std::fs;

    #[test]
    fn parses_login_response() -> Result<()> {
        let response = serde_json::de::from_str::<Response>(&fs::read_to_string(
            "tests/fixtures/okta/login_response_mfa_required.json",
        )?)?;

        let factor_result = &response.factor_result.unwrap();
        let status = &response.status;
        let embedded = &response.embedded.unwrap();
        let factor = embedded.factors.clone().unwrap();
        let id = match factor.first().unwrap() {
            Factor::WebAuthn { ref id, .. } => Some(id),
            _ => None,
        };

        assert_eq!(factor_result, &FactorResult::Success);
        assert_eq!(status, &Status::MfaRequired);
        assert_eq!(id.unwrap(), "factor-id-webauthn");

        Ok(())
    }
}
