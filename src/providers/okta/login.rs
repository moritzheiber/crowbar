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
#[allow(dead_code)]
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
