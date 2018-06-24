pub mod factor;

use dialoguer;
use dialoguer::{Input, PasswordInput};
use failure::Error;
use kuchiki;
use kuchiki::traits::TendrilSink;
use okta::factor::Factor;
use regex::Regex;
use reqwest;
use reqwest::header::{Accept, ContentType, Cookie};
use reqwest::Url;
use serde_json;
use serde_str;
use std::collections::HashMap;

use okta::factor::FactorVerificationRequest;
use saml::Response as SamlResponse;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaLoginRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OktaOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state_token: Option<String>,
}

impl OktaLoginRequest {
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
struct OktaOptions {
    multi_optional_factor_enroll: bool,
    warn_before_password_expired: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OktaLoginResponse {
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

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OktaAppLink {
    id: String,
    pub label: String,
    #[serde(with = "serde_str")]
    pub link_url: Url,
    pub app_name: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OktaEmbedded {
    #[serde(default)]
    factors: Vec<Factor>,
    user: OktaUser,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OktaUser {
    id: String,
    profile: OktaUserProfile,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OktaUserProfile {
    login: String,
    first_name: String,
    last_name: String,
    locale: String,
    time_zone: String,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum OktaLinks {
    Single(OktaLink),
    Multi(Vec<OktaLink>),
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OktaLink {
    name: Option<String>,
    #[serde(with = "serde_str")]
    pub href: Url,
    hints: OktaHint,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OktaHint {
    allow: Vec<String>,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OktaSessionRequest {
    session_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OktaSessionResponse {
    id: String,
}

pub fn login(org: &str, req: &OktaLoginRequest) -> Result<String, Error> {
    let client = reqwest::Client::new();

    let url = format!("https://{}.okta.com/api/v1/authn", org);
    let login_type = if req.state_token.is_some() {
        "State Token"
    } else {
        "Credentials"
    };

    debug!("Attempting login to {} with {}", url, login_type);

    let raw_response = client
        .post(&url)
        .json(&req)
        .header(ContentType::json())
        .header(Accept::json())
        .send()?
        .error_for_status()?
        .text()?;

    let response: OktaLoginResponse = serde_json::from_str(&raw_response)?;

    trace!("Login response: {:?}", response);

    match response.status {
        OktaLoginState::Success => Ok(response.session_token.unwrap()),
        OktaLoginState::MfaRequired => {
            info!("MFA required");

            let embedded = response.embedded.unwrap();

            let factors = embedded.factors;

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
                let factor_prompt_response = factor.verify(FactorVerificationRequest::Sms {
                    state_token,
                    pass_code: None,
                })?;

                trace!("Factor Prompt Response: {:?}", factor_prompt_response);

                if let Some(state_token) = factor_prompt_response.state_token {
                    let mut input = Input::new("MFA response");

                    let mfa_code = input.interact().unwrap();

                    let factor_provided_response = factor.verify(FactorVerificationRequest::Sms {
                        state_token,
                        pass_code: Some(mfa_code),
                    })?;

                    trace!("Factor Provided Response: {:?}", factor_provided_response);

                    Ok(factor_provided_response.session_token.unwrap())
                } else {
                    bail!("No state token found");
                }
            } else {
                bail!("No state token found");
            }
        }
        _ => {
            println!("Resp: {:?}", response);
            bail!("Non MFA")
        }
    }
}

pub fn get_session_id(org: &str, session_token: &str) -> Result<String, Error> {
    let client = reqwest::Client::new();

    let session_url = format!("https://{}.okta.com/api/v1/sessions", org);
    let session_req = OktaSessionRequest {
        session_token: Some(String::from(session_token)),
    };

    let session = client
        .post(&session_url)
        .json(&session_req)
        .header(ContentType::json())
        .header(Accept::json())
        .send()?
        .error_for_status()?
        .text()?;

    trace!("Session {:?}", &session);

    Ok(serde_json::from_str::<OktaSessionResponse>(&session)?.id)
}

pub fn get_apps(org: &str, session_id: &str) -> Result<Vec<OktaAppLink>, Error> {
    let url = format!("https://{}.okta.com/api/v1/users/me/appLinks", org);

    let client = reqwest::Client::new();

    let mut cookies = Cookie::new();
    cookies.append("sid", session_id.to_owned());

    let mut resp = client
        .get(&url)
        .header(ContentType::json())
        .header(Accept::json())
        .header(cookies)
        .send()?
        .error_for_status()?;

    //println!("Response {:?}", &resp.text());

    let app_links = resp.json()?;

    Ok(app_links)
}

impl SamlResponse {
    pub fn from_okta_session_id(org: &str, app_url: Url, session_id: &str) -> Result<Self, Error> {
        let client = reqwest::Client::new();

        let mut cookies = Cookie::new();
        cookies.append("sid", session_id.to_owned());

        trace!(
            "Attempting to fetch SAML from {} with sid:{}",
            &app_url,
            &session_id
        );

        let response = client
            .get(app_url.clone())
            .header(cookies)
            .send()?
            .error_for_status()?
            .text()?;

        trace!("SAML response doc: {}", response);

        let doc = kuchiki::parse_html().one(response.clone());

        if let Some(input_node) = doc.select("input[name='SAMLResponse']").unwrap().next() {
            if let Some(saml) = input_node.attributes.borrow().get("value") {
                debug!("SAML: {}", saml);
                return Ok(saml.parse()?);
            }
        }

        debug!("No SAML found, will re-login");

        let re = Regex::new(r#"var stateToken = '(.+)';"#).unwrap();

        if let Some(cap) = re.captures(&response) {
            let mut state_token = cap[1].to_owned().replace("\\x2D", "-");

            let session_token = login(org, &OktaLoginRequest::from_state_token(state_token))?;
            let session_id = get_session_id(org, &session_token)?;

            SamlResponse::from_okta_session_token(org, app_url, &session_id)
        } else {
            bail!("No SAML block found")
        }
    }

    pub fn from_okta_session_token(
        org: &str,
        app_url: Url,
        session_token: &str,
    ) -> Result<Self, Error> {
        let client = reqwest::Client::new();

        trace!(
            "Attempting to fetch SAML from {} with session token: {}",
            &app_url,
            &session_token
        );

        let response = client
            .get(&format!("{}?onetimetoken={}", app_url, session_token))
            .send()?
            .error_for_status()?
            .text()?;

        trace!("SAML response doc: {}", response);

        bail!("Unknown");
    }
}
