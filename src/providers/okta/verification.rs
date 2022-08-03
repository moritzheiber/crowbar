use crate::providers::okta::client::Client;
use crate::providers::okta::factors::Factor;
use crate::providers::okta::response::{Links, Response};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Debug, Serialize)]
#[serde(untagged)]
pub enum VerificationRequest {
    #[serde(rename_all = "camelCase")]
    Sms {
        state_token: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pass_code: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Push { state_token: String },
    #[serde(rename_all = "camelCase")]
    Totp {
        state_token: String,
        pass_code: String,
    },
    #[serde(rename_all = "camelCase")]
    WebAuthn {
        state_token: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature_data: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        authenticator_data: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_data: Option<String>,
    },
}

impl Client {
    pub fn verify(&self, factor: &Factor, request: &VerificationRequest) -> Result<Response> {
        match *factor {
            Factor::Sms { ref links, .. }
            | Factor::Totp { ref links, .. }
            | Factor::Push { ref links, .. }
            | Factor::WebAuthn { ref links, .. } => {
                if let Some(l) = links {
                    let url = match l.get("verify").unwrap() {
                        Links::Single(ref link) => link.href.clone(),
                        Links::Multi(ref links) => links.first().unwrap().href.clone(),
                    };

                    self.post(url, request)
                } else {
                    Err(anyhow!("Missing verification link in factor"))
                }
            }
            _ => Err(anyhow!(
                "The factor cannot be verified since it isn't implemented"
            )),
        }
    }

    pub fn poll(
        &self,
        links: &HashMap<String, Links>,
        request: &VerificationRequest,
    ) -> Result<Response> {
        let url = match links.get("next").unwrap() {
            Links::Single(ref link) => link.href.clone(),
            Links::Multi(ref links) => links.first().unwrap().href.clone(),
        };

        self.post(url, request)
    }
}
