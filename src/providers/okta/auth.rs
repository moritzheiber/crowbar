use crate::providers::okta::client::Client;
use crate::providers::okta::factors::Factor;
use crate::providers::okta::response::{FactorResult, Links, Response, Status};
use crate::providers::okta::verification::VerificationRequest;
use crate::utils;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use console::Term;
use std::collections::HashMap;
use std::{thread, time::Duration};

const BACKOFF_TIMEOUT: Duration = Duration::from_secs(2);
pub const PUSH_WAIT_TIMEOUT: i64 = 60;

impl Client {
    pub fn get_session_token(&self, response: Response) -> Result<String> {
        trace!("Session token response input: {:?}", response);

        match response.status {
            Status::Unauthenticated => Err(anyhow!(
                "Username or password wrong. Please check them and try again"
            )),
            Status::Success => {
                eprintln!("Authentication successful!");
                Ok(response
                    .session_token
                    .expect("The session token is missing from the success response"))
            }
            Status::MfaRequired => {
                let state_token = response
                    .state_token
                    .clone()
                    .with_context(|| "Missing state token in response")?;
                let factors = filter_factors(
                    response
                        .embedded
                        .expect("Missing embedded information for MFA challenge")
                        .factors
                        .expect("Missing factor for MFA challenge"),
                );

                let factor = select_factor(factors)?;

                let verification_request = match factor {
                    Factor::Sms { .. } => VerificationRequest::Sms {
                        state_token,
                        pass_code: None,
                    },
                    Factor::Totp { .. } => {
                        let mfa_code = utils::prompt_mfa()?;

                        VerificationRequest::Totp {
                            state_token,
                            pass_code: mfa_code,
                        }
                    }
                    Factor::Push { .. } => VerificationRequest::Push { state_token },
                    Factor::WebAuthn { .. } => VerificationRequest::WebAuthn {
                        state_token,
                        authenticator_data: None,
                        signature_data: None,
                        client_data: None,
                    },
                    _ => return Err(anyhow!("The selected factor isn't implemented")),
                };

                debug!("Verification request: {:#?}", &verification_request);

                let verification_response = self.verify(&factor, &verification_request)?;
                self.get_session_token(verification_response)
            }
            Status::MfaChallenge => {
                let state_token = response
                    .state_token
                    .clone()
                    .with_context(|| "Missing state token in response")?;
                let factor = response
                    .embedded
                    .expect("Missing embedded information for MFA challenge")
                    .factor
                    .expect("Missing factor for MFA challenge");
                let links = response
                    .links
                    .clone()
                    .expect("Missing verification links for factor");

                if let Some(fr) = response.factor_result {
                    match fr {
                        FactorResult::Rejected | FactorResult::Timeout => {
                            eprintln!("{}", fr);
                            return Err(anyhow!("Authentication failed"));
                        }
                        _ => (),
                    }
                };

                let factor_verification_request = match factor {
                    Factor::Sms { .. } => {
                        let mfa_code = utils::prompt_mfa()?;

                        VerificationRequest::Sms {
                            state_token,
                            pass_code: Some(mfa_code),
                        }
                    }
                    Factor::Push { .. } => VerificationRequest::Push { state_token },
                    // Factor::WebAuthn { .. } => {
                    //     unimplemented!()
                    //     let challenge =
                    //     embedded.expect("Missing embedded challenge for WebAuthn factor");
                    //     get_webauthn_verification_request(&challenge)?
                    // }
                    _ => return Err(anyhow!("Unknown challenge received for MFA type")),
                };

                trace!(
                    "Factor Verification Request: {:?}",
                    factor_verification_request
                );

                let verification_response = match factor {
                    Factor::Push { .. } => {
                        self.poll_for_push_result(&links, &factor_verification_request)?
                    }
                    _ => self.verify(&factor, &factor_verification_request)?,
                };

                trace!("Factor Verification Response: {:?}", verification_response);

                self.get_session_token(verification_response)
            }
            _ => Err(anyhow!("Unknown response status received, bailing!")),
        }
    }

    fn poll_for_push_result(
        &self,
        links: &HashMap<String, Links>,
        req: &VerificationRequest,
    ) -> Result<Response> {
        let mut verification_response = self.poll(links, &req)?;
        let time_at_execution = Utc::now();
        let mut tick = String::new();
        let term = Term::stderr();

        while timeout_not_reached(time_at_execution) {
            verification_response = self.poll(links, &req)?;
            term.clear_last_lines(1)?;

            match verification_response.factor_result.clone() {
                Some(r) if r == FactorResult::Waiting || r == FactorResult::Challenge => {
                    let answer = fetch_correct_push_answer(&verification_response);

                    if let Some(a) = answer {
                        let message = format!("The correct answer is: {}. {}{}", a, r, tick);
                        term.write_line(&message)?;
                    } else {
                        let message = format!("{}{}", r, tick);
                        term.write_line(&message)?;
                    };

                    tick.push('.');
                    thread::sleep(BACKOFF_TIMEOUT);
                    continue;
                }
                _ => break,
            }
        }

        Ok(verification_response)
    }
}

fn select_factor(factors: Vec<Factor>) -> Result<Factor> {
    let factor = match factors.len() {
        0 => return Err(anyhow!("MFA required, and no available factors")),
        1 => {
            info!("Only one factor available, using it");
            factors[0].clone()
        }
        _ => {
            eprintln!("Please select the factor to use:");
            let mut menu = dialoguer::Select::new();
            for factor in &factors {
                menu.item(&factor.to_string());
            }
            factors[menu.interact()?].clone()
        }
    };

    debug!("Factor: {:?}", factor);

    Ok(factor)
}

// fn get_webauthn_verification_request(challenge: &FactorChallenge) -> Result<VerificationRequest> {}

fn timeout_not_reached(time: DateTime<Utc>) -> bool {
    time.signed_duration_since(Utc::now()).num_seconds() < PUSH_WAIT_TIMEOUT
}

fn filter_factors(factors: Vec<Factor>) -> Vec<Factor> {
    factors
        .iter()
        .filter(|f| **f != Factor::Unimplemented)
        .cloned()
        .collect()
}

fn fetch_correct_push_answer(response: &Response) -> Option<u64> {
    match response.embedded.clone().unwrap().factor.unwrap() {
        Factor::Push { ref embedded, .. } => {
            if let Some(factor_embedded) = embedded.to_owned() {
                if let Some(challenge) = factor_embedded.challenge {
                    challenge.correct_answer
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::providers::okta::factors::FactorProvider;
    use crate::providers::okta::factors::{Factor, SmsFactorProfile};
    use chrono::NaiveDateTime;
    use std::fs;

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

    #[test]
    fn filters_unknown_factors() -> Result<()> {
        let sms_factor = Factor::Sms {
            id: "id".to_string(),
            links: None,
            profile: SmsFactorProfile {
                phone_number: "12345".to_string(),
            },
            status: None,
            provider: FactorProvider::Okta,
        };

        let factors = vec![
            Factor::Unimplemented,
            sms_factor.clone(),
            Factor::Unimplemented,
        ];

        let filtered = filter_factors(factors);
        assert_eq!(filtered.len(), 1);

        let factor = filtered.first().unwrap().to_owned();
        assert_eq!(factor, sms_factor);

        Ok(())
    }

    #[test]
    fn parses_push_challenge_response() -> Result<()> {
        let response = serde_json::de::from_str::<Response>(&fs::read_to_string(
            "tests/fixtures/okta/challenge_response_push.json",
        )?)?;

        assert_eq!(fetch_correct_push_answer(&response).unwrap(), 44);

        Ok(())
    }
}
