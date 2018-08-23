pub mod auth;
pub mod client;
pub mod factor;

use failure::Error;
use kuchiki;
use kuchiki::traits::TendrilSink;
use okta::auth::LoginRequest;
use okta::client::OktaClient;
use okta::factor::Factor;
use regex::Regex;
use reqwest::Url;
use serde_str;

use saml::Response as SamlResponse;

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

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OktaSessionRequest {
    session_token: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OktaSessionResponse {
    id: String,
}

impl OktaClient {
    pub fn get_session_id(&self, session_token: &str) -> Result<String, Error> {
        let session: OktaSessionResponse = self.post(
            String::from("api/v1/sessions?additionalFields=cookieTokenUrl"),
            OktaSessionRequest {
                session_token: Some(String::from(session_token)),
            },
        )?;

        debug!("Session {:?}", &session);

        Ok(session.id)
    }

    pub fn get_apps(&self) -> Result<Vec<OktaAppLink>, Error> {
        self.get(String::from("api/v1/users/me/appLinks"))
    }

    pub fn get_saml_response(&self, app_url: Url) -> Result<SamlResponse, Error> {
        let response = self.get_response(app_url.clone())?.text()?;

        trace!("SAML response doc for app {:?}: {}", &app_url, &response);

        if let Ok(saml) = SamlResponse::from_html(response.clone()) {
            return Ok(saml);
        } else {
            debug!("No SAML found for app {:?}, will re-login", &app_url);

            let state_token = extract_state_token(&response)?;
            let session_token =
                self.get_session_token(&LoginRequest::from_state_token(state_token))?;
            self.get_saml_response(app_url)
        }
    }
}

fn extract_state_token(text: &str) -> Result<String, Error> {
    let re = Regex::new(r#"var stateToken = '(.+)';"#).unwrap();

    if let Some(cap) = re.captures(text) {
        Ok(cap[1].to_owned().replace("\\x2D", "-"))
    } else {
        trace!("Expected state token in {}", &text);
        bail!("No state token found")
    }
}

impl SamlResponse {
    pub fn from_html(text: String) -> Result<Self, Error> {
        let doc = kuchiki::parse_html().one(text);

        if let Some(input_node) = doc.select("input[name='SAMLResponse']").unwrap().next() {
            if let Some(saml) = input_node.attributes.borrow().get("value") {
                trace!("SAML: {}", saml);
                saml.parse()
            } else {
                bail!("No `value` found in SAML block")
            }
        } else {
            bail!("No SAML block found")
        }
    }
}
