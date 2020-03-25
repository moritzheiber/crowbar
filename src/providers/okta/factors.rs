use crate::providers::okta::auth::{LoginResponse, PUSH_WAIT_TIMEOUT};
use crate::providers::okta::client::Client;
use crate::providers::okta::structure::Links;
use crate::providers::okta::structure::Links::Multi;
use crate::providers::okta::structure::Links::Single;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::fmt;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase", tag = "factorType")]
pub enum Factor {
    #[serde(rename_all = "camelCase")]
    Push {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: PushFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
    #[serde(rename_all = "camelCase")]
    Sms {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: SmsFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
    #[serde(rename_all = "camelCase")]
    Call {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: CallFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
    #[serde(rename = "token", rename_all = "camelCase")]
    Token {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: TokenFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
        verify: Option<FactorVerification>,
    },
    #[serde(rename = "token:software:totp", rename_all = "camelCase")]
    Totp {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: TokenFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
    #[serde(rename = "token:hardware", rename_all = "camelCase")]
    Hotp {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: TokenFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
        verify: Option<FactorVerification>,
    },
    #[serde(rename_all = "camelCase")]
    Question {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: QuestionFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
    #[serde(rename_all = "camelCase")]
    Web {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: WebFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
    #[serde(rename_all = "camelCase")]
    WebAuthn {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: WebAuthnFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactorProvider {
    Okta,
    Rsa,
    Symantec,
    Google,
    Duo,
    Yubico,
    Fido,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactorStatus {
    NotSetup,
    PendingActivation,
    Enrolled,
    Active,
    Inactive,
    Expired,
}

#[derive(Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactorResult {
    Waiting,
    Success,
    Rejected,
    Timeout,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FactorVerification {
    pass_code: String,
    next_pass_code: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SmsFactorProfile {
    phone_number: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PushFactorProfile {
    credential_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CallFactorProfile {
    phone_number: String,
    phone_extension: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct QuestionFactorProfile {
    question: String,
    question_text: String,
    answer: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TokenFactorProfile {
    credential_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WebFactorProfile {
    credential_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnFactorProfile {
    credential_id: String,
}

#[derive(Deserialize, Debug, Serialize)]
#[serde(untagged)]
pub enum FactorVerificationRequest {
    #[serde(rename_all = "camelCase")]
    Question { answer: String },
    #[serde(rename_all = "camelCase")]
    Sms {
        state_token: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pass_code: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Push { state_token: String },
    #[serde(rename_all = "camelCase")]
    Call { pass_code: Option<String> },
    #[serde(rename_all = "camelCase")]
    Totp {
        state_token: String,
        pass_code: String,
    },
    #[serde(rename_all = "camelCase")]
    Token { pass_code: String },
}

impl fmt::Display for Factor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Factor::Push { .. } => write!(f, "Okta Verify Push"),
            Factor::Sms { ref profile, .. } => write!(f, "Okta SMS to {}", profile.phone_number),
            Factor::Call { ref profile, .. } => write!(f, "Okta Call to {}", profile.phone_number),
            Factor::Token { .. } => write!(f, "Okta One-time Password"),
            Factor::Totp {
                // Okta identifies any other TOTP provider as "Google"
                provider: FactorProvider::Google,
                ..
            } => write!(f, "Software TOTP"),
            Factor::Totp { .. } => write!(f, "Okta Verify TOTP"),
            Factor::Hotp { .. } => write!(f, "Okta Hardware One-time Password"),
            Factor::Question { ref profile, .. } => write!(f, "Question: {}", profile.question),
            Factor::Web { .. } => write!(f, "Okta Web"),
            Factor::WebAuthn { .. } => write!(f, "Okta WebAuthn"),
        }
    }
}

impl fmt::Display for FactorResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FactorResult::Waiting { .. } | FactorResult::Timeout => {
                write!(f, "No verification after {} seconds", PUSH_WAIT_TIMEOUT)
            }
            FactorResult::Rejected { .. } => write!(f, "Verification challenge was rejected"),
            FactorResult::Success { .. } => write!(f, "Verification challenge was successful"),
        }
    }
}

impl Client {
    pub fn verify(
        &self,
        factor: &Factor,
        request: &FactorVerificationRequest,
    ) -> Result<LoginResponse> {
        match *factor {
            Factor::Sms { ref links, .. } => {
                let url = match links.get("verify").unwrap() {
                    Single(ref link) => link.href.clone(),
                    Multi(ref links) => links.first().unwrap().href.clone(),
                };

                self.post_absolute(url, request)
            }
            Factor::Totp { ref links, .. } => {
                let url = match links.get("verify").unwrap() {
                    Single(ref link) => link.href.clone(),
                    Multi(ref links) => links.first().unwrap().href.clone(),
                };

                self.post_absolute(url, request)
            }
            Factor::Push { ref links, .. } => {
                let url = match links.get("verify").unwrap() {
                    Single(ref link) => link.href.clone(),
                    Multi(ref links) => links.first().unwrap().href.clone(),
                };

                self.post_absolute(url, request)
            }
            _ => {
                // TODO
                Err(anyhow!("Unsupported MFA method"))
            }
        }
    }
    pub fn poll(
        &self,
        response: &LoginResponse,
        request: &FactorVerificationRequest,
    ) -> Result<LoginResponse> {
        let url = match response.links.get("next").unwrap() {
            Single(ref link) => link.href.clone(),
            Multi(ref links) => links.first().unwrap().href.clone(),
        };

        self.post_absolute(url, request)
    }
}
