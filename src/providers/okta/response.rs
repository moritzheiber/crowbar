use crate::providers::okta::auth::PUSH_WAIT_TIMEOUT;
use crate::providers::okta::factors::Factor;

use reqwest::Url;
use serde_str;
use std::collections::HashMap;
use std::fmt;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub state_token: Option<String>,
    pub session_token: Option<String>,
    expires_at: String,
    pub status: Status,
    pub factor_result: Option<FactorResult>,
    relay_state: Option<String>,
    #[serde(rename = "_links", default)]
    pub links: Option<HashMap<String, Links>>,
    #[serde(rename = "_embedded")]
    pub embedded: Option<Embedded>,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Unauthenticated,
    PasswordWarn,
    PasswordExpired,
    Recovery,
    RecoveryChallenge,
    PasswordReset,
    LockedOut,
    MfaEnroll,
    MfaEnrollActivate,
    MfaRequired,
    MfaChallenge,
    Success,
}

#[derive(Deserialize, PartialEq, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactorResult {
    Challenge,
    Success,
    Timeout,
    Waiting,
    Rejected,
}

impl fmt::Display for FactorResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FactorResult::Waiting { .. } | FactorResult::Challenge => write!(f, "."),
            FactorResult::Timeout => {
                write!(f, "No verification after {} seconds", PUSH_WAIT_TIMEOUT)
            }
            FactorResult::Rejected { .. } => write!(f, "Verification challenge was rejected"),
            FactorResult::Success { .. } => write!(f, "Verification challenge was successful"),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Embedded {
    #[serde(default)]
    pub factors: Option<Vec<Factor>>,
    pub factor: Option<Factor>,
    user: User,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Links {
    Single(Link),
    Multi(Vec<Link>),
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    name: Option<String>,
    #[serde(with = "serde_str")]
    pub href: Url,
    hints: Hint,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Hint {
    allow: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct User {
    id: String,
    profile: UserProfile,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
    login: String,
    first_name: String,
    last_name: String,
    locale: String,
    time_zone: String,
}
