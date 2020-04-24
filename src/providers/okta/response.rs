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

#[derive(Deserialize, PartialEq, Clone, Debug)]
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
            FactorResult::Waiting { .. } | FactorResult::Challenge => {
                write!(f, "Waiting for confirmation")
            }
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
    #[serde(default)]
    pub factor: Option<Factor>,
    user: User,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum Links {
    Single(Link),
    Multi(Vec<Link>),
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    name: Option<String>,
    #[serde(with = "serde_str")]
    pub href: Url,
    hints: Hint,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Hint {
    allow: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct User {
    id: String,
    profile: UserProfile,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
    login: String,
    first_name: String,
    last_name: String,
    locale: String,
    time_zone: String,
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;
    use claim::assert_ok;
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

    #[test]
    fn parses_webauthn_challenge_response() -> Result<()> {
        let response = serde_json::de::from_str::<Response>(&fs::read_to_string(
            "tests/fixtures/okta/challenge_response_webauthn.json",
        )?)?;

        let factor_result = &response.factor_result.unwrap();
        let status = &response.status;
        let embedded = &response.embedded.unwrap();
        let factor = embedded.factor.clone().unwrap();
        let (id, factor_embedded, profile) = match factor {
            Factor::WebAuthn {
                ref id,
                ref embedded,
                ref profile,
                ..
            } => (id, embedded.clone().unwrap(), profile),
            _ => panic!("Didn't find the expected factor!"),
        };

        assert_eq!(factor_result, &FactorResult::Challenge);
        assert_eq!(status, &Status::MfaChallenge);
        assert_eq!(
            factor_embedded.challenge.unwrap().challenge.unwrap(),
            "challenge"
        );
        assert_eq!(profile.credential_id, "credential-id");
        assert_eq!(id, "factor-id-webauthn");

        Ok(())
    }

    #[test]
    fn parses_login_response_with_unknown_factors() -> Result<()> {
        let response = serde_json::de::from_str::<Response>(&fs::read_to_string(
            "tests/fixtures/okta/login_response_unimplemented_factors.json",
        )?);

        assert_ok!(response);
        Ok(())
    }
}
