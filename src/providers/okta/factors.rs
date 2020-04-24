use crate::providers::okta::response::Links;
use std::collections::HashMap;
use std::fmt;

#[allow(clippy::large_enum_variant)]
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase", tag = "factorType")]
pub enum Factor {
    #[serde(rename_all = "camelCase")]
    Push {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: PushFactorProfile,
        #[serde(rename = "_links")]
        links: Option<HashMap<String, Links>>,
        #[serde(rename = "_embedded")]
        embedded: Option<FactorEmbedded>,
    },
    #[serde(rename_all = "camelCase")]
    Sms {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: SmsFactorProfile,
        #[serde(rename = "_links")]
        links: Option<HashMap<String, Links>>,
    },

    #[serde(rename = "token:software:totp", rename_all = "camelCase")]
    Totp {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: TokenFactorProfile,
        #[serde(rename = "_links")]
        links: Option<HashMap<String, Links>>,
    },
    WebAuthn {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: WebAuthnFactorProfile,
        #[serde(rename = "_links")]
        links: Option<HashMap<String, Links>>,
        #[serde(rename = "_embedded")]
        embedded: Option<FactorEmbedded>,
    },
    #[serde(other)]
    Unimplemented,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FactorEmbedded {
    pub challenge: Option<FactorChallenge>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FactorChallenge {
    pub challenge: Option<String>,
    pub correct_answer: Option<u64>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactorProvider {
    Okta,
    Google,
    Fido,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactorStatus {
    NotSetup,
    PendingActivation,
    Enrolled,
    Active,
    Inactive,
    Expired,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SmsFactorProfile {
    pub phone_number: String,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PushFactorProfile {
    credential_id: String,
    device_type: String,
    name: String,
    platform: String,
    version: String,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TokenFactorProfile {
    credential_id: String,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnFactorProfile {
    pub credential_id: String,
    pub authenticator_name: String,
}

impl fmt::Display for Factor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Factor::Push { ref profile, .. } => write!(f, "Okta Verify Push to {}", profile.name),
            Factor::Sms { ref profile, .. } => write!(f, "Okta SMS to {}", profile.phone_number),
            Factor::Totp {
                // Okta identifies any other TOTP provider as "Google"
                provider: FactorProvider::Google,
                ..
            } => write!(f, "Software TOTP"),
            Factor::Totp { .. } => write!(f, "Okta Verify TOTP"),
            Factor::WebAuthn { ref profile, .. } => {
                write!(f, "WebAuthn with {}", profile.authenticator_name)
            }
            _ => write!(f, "Unimplemented factor"),
        }
    }
}
