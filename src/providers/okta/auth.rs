use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use dialoguer;
use dialoguer::Input;
use std::collections::HashMap;
use std::{thread, time::Duration};

use crate::providers::okta::client::Client;
use crate::providers::okta::factors::{Factor, FactorResult, FactorVerificationRequest};
use crate::providers::okta::users::User;
use crate::providers::okta::Links;

const BACKOFF_TIMEOUT: Duration = Duration::from_secs(2);
pub const PUSH_WAIT_TIMEOUT: i64 = 60;

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
    status: LoginState,
    pub factor_result: Option<FactorResult>,
    relay_state: Option<String>,
    #[serde(rename = "_embedded")]
    embedded: Option<LoginEmbedded>,
    #[serde(rename = "_links", default)]
    pub links: HashMap<String, Links>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LoginEmbedded {
    #[serde(default)]
    factors: Vec<Factor>,
    user: User,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LoginState {
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

impl Client {
    pub fn login(&self, req: &LoginRequest) -> Result<LoginResponse> {
        let login_type = if req.state_token.is_some() {
            "State Token"
        } else {
            "Credentials"
        };

        debug!("Attempting to login with {}", login_type);

        self.post("api/v1/authn", req)
    }

    pub fn get_session_token(&self, req: &LoginRequest) -> Result<String> {
        let response = self.login(req)?;

        trace!("Login response: {:?}", response);

        match response.status {
            LoginState::Success => Ok(response.session_token.unwrap()),
            LoginState::MfaRequired => {
                let factors = response.embedded.unwrap().factors;

                let factor = match factors.len() {
                    0 => return Err(anyhow!("MFA required, and no available factors")),
                    1 => {
                        info!("Only one factor available, using it");
                        &factors[0]
                    }
                    _ => {
                        eprintln!("Please select the factor to use:");
                        let mut menu = dialoguer::Select::new();
                        for factor in &factors {
                            menu.item(&factor.to_string());
                        }
                        &factors[menu.interact()?]
                    }
                };

                debug!("Factor: {:?}", factor);

                let mut state_token = response
                    .state_token
                    .clone()
                    .with_context(|| "No state token found in response")?;

                let factor_challenge_response =
                    match self.send_verification_challenge(state_token.clone(), factor)? {
                        Some(res) => {
                            state_token = res
                                .state_token
                                .clone()
                                .with_context(|| "No state token found in response")?;
                            Some(res)
                        }
                        None => None,
                    };

                let factor_verification_request = match factor {
                    Factor::Sms { .. } => {
                        let mfa_code = prompt_mfa()?;

                        Some(FactorVerificationRequest::Sms {
                            state_token,
                            pass_code: Some(mfa_code),
                        })
                    }
                    Factor::Totp { .. } => {
                        let mfa_code = prompt_mfa()?;

                        Some(FactorVerificationRequest::Totp {
                            state_token,
                            pass_code: mfa_code,
                        })
                    }
                    Factor::Push { .. } => Some(FactorVerificationRequest::Push { state_token }),
                    _ => None,
                };

                trace!(
                    "Factor Verification Request: {:?}",
                    factor_verification_request
                );

                let factor_verification_response = match factor {
                    Factor::Push { .. } => self.poll_for_push_result(
                        &factor_challenge_response.unwrap(),
                        &factor_verification_request.unwrap(),
                    )?,
                    _ => self.verify(&factor, &factor_verification_request.unwrap())?,
                };

                trace!(
                    "Factor Verification Response: {:?}",
                    factor_verification_response
                );

                match factor_verification_response.factor_result {
                    Some(fr) => match fr {
                        FactorResult::Success { .. } => {
                            Ok(factor_verification_response.session_token.unwrap())
                        }
                        _ => Err(anyhow!(fr)),
                    },
                    None => Ok(factor_verification_response.session_token.unwrap()),
                }
            }
            _ => {
                println!("Resp: {:?}", response);
                Err(anyhow!("Failed determining MFA status"))
            }
        }
    }

    fn send_verification_challenge(
        &self,
        state_token: String,
        factor: &Factor,
    ) -> Result<Option<LoginResponse>> {
        let factor_verification_challenge = match factor {
            Factor::Sms { .. } => Some(FactorVerificationRequest::Sms {
                state_token,
                pass_code: None,
            }),
            Factor::Push { .. } => Some(FactorVerificationRequest::Push { state_token }),
            _ => None,
        };

        match factor_verification_challenge {
            Some(challenge) => {
                trace!("Factor Challenge Request: {:?}", challenge);

                Ok(Some(self.verify(&factor, &challenge)?))
            }
            None => Ok(None),
        }
    }

    fn poll_for_push_result(
        &self,
        res: &LoginResponse,
        req: &FactorVerificationRequest,
    ) -> Result<LoginResponse> {
        let mut response = self.poll(&res, &req)?;
        let time_at_execution = Utc::now();

        eprint!("Waiting for confirmation");

        while timeout_not_reached(time_at_execution) {
            let login_response = self.poll(&res, &req)?;
            eprint!(".");

            match login_response.factor_result {
                Some(r) if r == FactorResult::Waiting => {
                    thread::sleep(BACKOFF_TIMEOUT);
                    continue;
                }
                _ => {
                    response = login_response;
                    break;
                }
            }
        }

        eprintln!();
        Ok(response)
    }
}

fn timeout_not_reached(time: DateTime<Utc>) -> bool {
    time.signed_duration_since(Utc::now()).num_seconds() < PUSH_WAIT_TIMEOUT
}

fn prompt_mfa() -> Result<String> {
    let mut input = Input::new();
    let input = input.with_prompt("MFA response");

    match input.interact() {
        Ok(mfa) => Ok(mfa),
        Err(e) => Err(anyhow!("Failed to get MFA input: {}", e)),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::NaiveDateTime;

    #[test]
    fn should_reach_timeout() -> Result<()> {
        let dt = DateTime::<Utc>::from_utc(
            NaiveDateTime::parse_from_str("2038-01-01T10:10:10", "%Y-%m-%dT%H:%M:%S")?,
            Utc,
        );
        assert_eq!(false, timeout_not_reached(dt));
        Ok(())
    }

    #[test]
    fn should_not_reach_timeout() -> Result<()> {
        let dt = Utc::now();
        thread::sleep(Duration::from_secs(3));
        assert_eq!(true, timeout_not_reached(dt));
        Ok(())
    }
}
