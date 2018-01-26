use failure::Error;
use reqwest;
use scraper::{Html, Selector};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginRequest {
    username: Option<String>,
    password: Option<String>,
    relay_state: Option<String>,
    token: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    expires_at: String,
    pub session_token: String,
    status: String,
}

pub fn login(org: &str, user: &str, password: &str) -> Result<LoginResponse, Error> {
    let req = LoginRequest {
        username: Some(String::from(user)),
        password: Some(String::from(password)),
        relay_state: None,
        token: None,
    };

    let client = reqwest::Client::new();
    let mut resp: reqwest::Response = client
        .post(&format!("https://{}.okta.com/api/v1/authn", org))
        .json(&req)
        .send()?
        .error_for_status()?;
    Ok(resp.json()?)
}

pub fn fetch_saml(org: &str, app_id: &str, session_token: &str) -> Result<String, Error> {
    let client = reqwest::Client::new();
    let mut resp = client
        .get(&format!(
            "https://{}.okta.com/app/{}/sso/saml?onetimetoken={}",
            org, app_id, session_token
        ))
        .send()?;

    let selector = Selector::parse("input[name=\"SAMLResponse\"]").unwrap();
    let document = Html::parse_document(&resp.text()?);

    Ok(document
        .select(&selector)
        .next()
        .unwrap()
        .value()
        .attr("value")
        .unwrap()
        .to_owned())
}
