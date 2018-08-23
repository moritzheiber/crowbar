use dialoguer;
use dialoguer::Input;
use failure::Error;
use okta::client::OktaClient;
use okta::OktaEmbedded;
use okta::OktaLinks;
use std::collections::HashMap;

use okta::factor::FactorVerificationRequest;

#[derive(Serialize)]
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

    pub fn from_state_token(token: String) -> Self {
        Self {
            username: None,
            password: None,
            relay_state: None,
            options: None,
            state_token: Some(token),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Options {
    multi_optional_factor_enroll: bool,
    warn_before_password_expired: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    state_token: Option<String>,
    pub session_token: Option<String>,
    expires_at: String,
    status: OktaLoginState,
    relay_state: Option<String>,
    #[serde(rename = "_embedded")]
    embedded: Option<OktaEmbedded>,
    #[serde(rename = "_links", default)]
    links: HashMap<String, OktaLinks>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OktaLoginState {
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

impl OktaClient {
    pub fn login(&self, req: &LoginRequest) -> Result<LoginResponse, Error> {
        let login_type = if req.state_token.is_some() {
            "State Token"
        } else {
            "Credentials"
        };

        debug!("Attempting to login with {}", login_type);

        self.post(String::from("api/v1/authn"), req)
    }

    pub fn get_session_token(&self, req: &LoginRequest) -> Result<String, Error> {
        let response = self.login(req)?;

        trace!("Login response: {:?}", response);

        match response.status {
            OktaLoginState::Success => Ok(response.session_token.unwrap()),
            OktaLoginState::MfaRequired => {
                info!("MFA required");

                let factors = response.embedded.unwrap().factors;

                let factor = match factors.len() {
                    0 => bail!("MFA required, and no available factors"),
                    1 => {
                        info!("Only one factor available, using it");
                        &factors[0]
                    }
                    _ => {
                        let mut menu = dialoguer::Select::new();
                        for factor in &factors {
                            menu.item(&factor.to_string());
                        }
                        &factors[menu.interact()?]
                    }
                };

                debug!("Factor: {:?}", factor);

                if let Some(state_token) = response.state_token {
                    let factor_prompt_response = self.verify(
                        &factor,
                        FactorVerificationRequest::Sms {
                            state_token,
                            pass_code: None,
                        },
                    )?;

                    trace!("Factor Prompt Response: {:?}", factor_prompt_response);

                    if let Some(state_token) = factor_prompt_response.state_token {
                        let mut input = Input::new("MFA response");

                        let mfa_code = input.interact().unwrap();

                        let factor_provided_response = self.verify(
                            &factor,
                            FactorVerificationRequest::Sms {
                                state_token,
                                pass_code: Some(mfa_code),
                            },
                        )?;

                        trace!("Factor Provided Response: {:?}", factor_provided_response);

                        Ok(factor_provided_response.session_token.unwrap())
                    } else {
                        bail!("No state token found in factor prompt response");
                    }
                } else {
                    bail!("No state token found in response");
                }
            }
            _ => {
                println!("Resp: {:?}", response);
                bail!("Non MFA")
            }
        }
    }
}
