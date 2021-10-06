mod client;

use crate::config::app::AppProfile;
use crate::credentials::aws::AwsCredentials;
use crate::credentials::config::ConfigCredentials;
use crate::credentials::Credential;
use crate::providers::jumpcloud::client::Client;
use crate::saml;
use crate::utils;

use anyhow::{anyhow, Context, Result};
use reqwest::{StatusCode, Url};

const AUTH_SUBMIT_URL: &str = "https://console.jumpcloud.com/userconsole/auth";
const XSRF_URL: &str = "https://console.jumpcloud.com/userconsole/xsrf";

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    context: String,
    #[serde(rename = "email")]
    username: String,
    password: String,
    redirect_to: String,
    pub otp: String,
}

impl LoginRequest {
    pub fn from_credentials(username: String, password: String, redirect_to: String) -> Self {
        Self {
            context: "sso".to_string(),
            username,
            password,
            redirect_to,
            otp: String::new(),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    redirect_to: String,
}

#[derive(Deserialize, Debug)]
pub struct XsrfResponse {
    xsrf: String,
}

pub struct JumpcloudProvider {
    client: Client,
    profile: AppProfile,
    pub redirect_to: Option<String>,
}

impl JumpcloudProvider {
    pub fn new(profile: &AppProfile) -> Result<Self> {
        Ok(JumpcloudProvider {
            client: Client::new()?,
            profile: profile.clone(),
            redirect_to: None,
        })
    }
}

impl JumpcloudProvider {
    pub fn new_session(&mut self) -> Result<&Self> {
        let profile = &self.profile;

        let config_credentials =
            ConfigCredentials::load(profile).or_else(|_| ConfigCredentials::create(profile))?;

        let response: XsrfResponse = self
            .client
            .get(Url::parse(XSRF_URL)?)
            .with_context(|| "Unable to obtain XSRF token")?
            .json()?;

        let token = response.xsrf;
        let username = &profile.username;
        let password = &config_credentials.password;
        let redirect_to = create_redirect_to(&profile.url)?;
        let mut login_request =
            LoginRequest::from_credentials(username.clone(), password.clone(), redirect_to);

        debug!("Login request: {:?}", login_request);

        let login_response: Result<LoginResponse, _> =
            self.client
                .post(Url::parse(AUTH_SUBMIT_URL)?, &login_request, &token);

        let content: LoginResponse = match login_response {
            Ok(r) => r,
            Err(e) => match e.status() {
                Some(StatusCode::UNAUTHORIZED) if login_request.otp.is_empty() => {
                    login_request.otp = utils::prompt_mfa()?;
                    self.client
                        .post(Url::parse(AUTH_SUBMIT_URL)?, &login_request, &token)?
                }
                _ => return Err(anyhow!("Unable to login: {}", e)),
            },
        };

        config_credentials.write(profile)?;

        self.redirect_to = Some(content.redirect_to);
        Ok(self)
    }

    pub fn fetch_aws_credentials(&self) -> Result<AwsCredentials> {
        let profile = &self.profile;
        let url = self.redirect_to.clone().expect("Missing SAML redirect URL");

        let input = self
            .client
            .get(Url::parse(&url)?)
            .with_context(|| format!("Error getting SAML response for profile {}", profile.name))?
            .text()?;

        debug!("Text for SAML response: {:#?}", input);

        let credentials = saml::get_credentials_from_saml(input, profile.role.clone())?;

        trace!("Credentials: {:#?}", credentials);
        Ok(credentials)
    }
}

fn create_redirect_to(s: &str) -> Result<String> {
    let mut url = Url::parse(s)?.path().to_owned();

    // We need to remove the leading slash
    url.remove(0);
    Ok(url)
}
