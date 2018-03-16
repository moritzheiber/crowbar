use failure::Error;
use reqwest;
use reqwest::Url;
use reqwest::header::{Accept, ContentType, Cookie};
use kuchiki;
use kuchiki::traits::TendrilSink;
use regex::Regex;
use dialoguer;
use serde_str;

use saml::Response as SamlResponse;

use std::fmt;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaLoginRequest {
    #[serde(skip_serializing_if = "Option::is_none")] username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] relay_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] options: Option<OktaOptions>,
    #[serde(skip_serializing_if = "Option::is_none")] state_token: Option<String>,
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
    #[serde(rename = "_embedded")] embedded: Option<OktaEmbedded>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OktaAppLink {
    id: String,
    pub label: String,
    #[serde(with = "serde_str")] pub link_url: Url,
    pub app_name: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OktaEmbedded {
    #[serde(default)] factors: Vec<OktaMfaFactor>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase", tag = "factorType")]
pub enum OktaMfaFactor {
    #[serde(rename_all = "camelCase")] Push { id: String },
    #[serde(rename_all = "camelCase")] Sms { id: String },
    #[serde(rename_all = "camelCase")] Call { id: String },
    #[serde(rename = "token:software:totp", rename_all = "camelCase")] Totp { id: String },
}

impl fmt::Display for OktaMfaFactor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            OktaMfaFactor::Push { .. } => write!(f, "Okta Verify Push"),
            OktaMfaFactor::Sms { .. } => write!(f, "Okta SMS"),
            OktaMfaFactor::Call { .. } => write!(f, "Okta Call"),
            OktaMfaFactor::Totp { .. } => write!(f, "Okta Verify TOTP"),
        }
    }
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

    let response: OktaLoginResponse = client
        .post(&format!("https://{}.okta.com/api/v1/authn", org))
        .json(&req)
        .header(ContentType::json())
        .header(Accept::json())
        .send()?
        .error_for_status()?
        .json()?;

    match response.status {
        OktaLoginState::Success => get_session_id(org, &response.session_token.unwrap()),
        OktaLoginState::MfaRequired => {
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
                    &factors[menu.interact().unwrap()]
                }
            };

            println!("Factor: {:?}", factor);

            bail!("MFA")
        }
        _ => {
            println!("Resp: {:?}", response);
            bail!("Non MFA")
        }
    }
}

fn get_session_id(org: &str, session_token: &str) -> Result<String, Error> {
    let client = reqwest::Client::new();

    let session_url = format!("https://{}.okta.com/api/v1/sessions", org);
    let session_req = OktaSessionRequest {
        session_token: Some(String::from(session_token)),
    };

    let session: OktaSessionResponse = client
        .post(&session_url)
        .json(&session_req)
        .header(ContentType::json())
        .header(Accept::json())
        .send()?
        .error_for_status()?
        .json()?;

    Ok(session.id)
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
    pub fn from_okta(org: &str, app_url: Url, session_id: &str) -> Result<Self, Error> {
        let client = reqwest::Client::new();

        let mut cookies = Cookie::new();
        cookies.append("sid", session_id.to_owned());

        let response = client
            .get(app_url)
            .header(cookies)
            .send()?
            .error_for_status()?
            .text()?;

        let doc = kuchiki::parse_html().one(response.clone());

        if let Some(input_node) = doc.select("input[name='SAMLResponse']").unwrap().next() {
            if let Some(saml) = input_node.attributes.borrow().get("value") {
                debug!("SAML: {}", saml);
                return Ok(saml.parse()?);
            }
        }

        let re = Regex::new(r#"var stateToken = '(.+)';"#).unwrap();

        if let Some(cap) = re.captures(&response) {
            let mut state_token = cap[1].to_owned().replace("\\x2D", "-");

            let _login_resp = login(org, &OktaLoginRequest::from_state_token(state_token))?;
            //println!("Login Resp: {:?}", login_resp);
        }

        bail!("No SAML block found")

        /*If no SAML block found then do:
            Trigger factor
            Provide Response
            Use session token like above*/
    }
}
