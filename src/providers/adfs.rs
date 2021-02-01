use crate::config::app::AppProfile;
use crate::credentials::aws::AwsCredentials;
use crate::credentials::config::ConfigCredentials;
use crate::credentials::Credential;
use crate::providers::adfs::client::Client;
use crate::saml;

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use select::document::Document;
use select::predicate::{Attr, Name};
use std::collections::HashMap;

mod client;

const ADFS_URL_SUFFIX: &str = "/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices";

pub struct AdfsProvider {
    client: Client,
    profile: AppProfile,
}

#[derive(PartialEq, Debug)]
struct AdfsResponse {
    state: ResponseState,
    credentials: Option<AwsCredentials>,
}

#[derive(PartialEq, Debug)]
enum ResponseState {
    Success,
    MfaPrompt,
    MfaWait,
    Error,
}

impl Default for AdfsResponse {
    fn default() -> Self {
        AdfsResponse {
            state: ResponseState::Error,
            credentials: None,
        }
    }
}

impl AdfsProvider {
    pub fn new(profile: &AppProfile) -> Result<Self> {
        Ok(AdfsProvider {
            client: Client::new()?,
            profile: profile.clone(),
        })
    }

    pub fn fetch_aws_credentials(&mut self) -> Result<AwsCredentials> {
        let profile = &self.profile;

        let config_credentials =
            ConfigCredentials::load(profile).or_else(|_| ConfigCredentials::new(profile))?;

        let username = self.profile.username.clone();
        let password = config_credentials.password.unwrap();
        let mut url = self.profile.url.clone();
        url.push_str(ADFS_URL_SUFFIX);

        let response = self
            .client
            .get(&url)
            .with_context(|| "Unable to reach login form")?;

        let document = Document::from(response.text()?.as_str());
        let form_content = build_login_form_elements(&username, &password, &document);
        let submit_url = fetch_submit_url(&document);

        let response = self.client.post(submit_url, &form_content)?;
        let adfs_response = evaluate_response_state(response.text()?)?;

        let credentials = match adfs_response.state {
            ResponseState::Success => adfs_response.credentials.unwrap(),
            ResponseState::MfaPrompt => AwsCredentials::default(),
            ResponseState::MfaWait => AwsCredentials::default(),
            _ => return Err(anyhow!("Unable to acquire credentials")),
        };

        Ok(credentials)
    }
}

fn build_login_form_elements<'a>(
    username: &'a str,
    password: &'a str,
    document: &'a Document,
) -> HashMap<String, String> {
    let ur = Regex::new(r"(^email.*|^[Uu]ser.*)").unwrap();
    let pr = Regex::new(r"(^[Pp]ass.*)").unwrap();
    let mut form_content: HashMap<String, String> = HashMap::new();
    let elements = document.find(Name("input"));

    for element in elements {
        match element.attr("name") {
            Some(name) if ur.is_match(name) => {
                let _ = form_content.insert(name.to_owned(), username.to_owned());
            }
            Some(name) if pr.is_match(name) => {
                let _ = form_content.insert(name.to_owned(), password.to_owned());
            }
            _ => {
                let name = element.attr("name");
                let value = element.attr("value");
                if let Some(n) = name {
                    if let Some(v) = value {
                        let _ = form_content.insert(n.to_owned(), v.to_owned());
                    }
                }
            }
        };
    }

    form_content
}

fn fetch_submit_url(document: &Document) -> &str {
    let forms = document.find(Name("form"));
    let mut url = None;

    for form in forms {
        url = form.attr("action")
    }

    url.expect("Missing submission URL for authentication form")
}

fn evaluate_response_state(response: String) -> Result<AdfsResponse> {
    let mut adfs_response = AdfsResponse::default();

    match saml::get_credentials_from_saml(response.clone()) {
        Ok(credentials) => {
            adfs_response.credentials = Some(credentials);
            adfs_response.state = ResponseState::Success;
        }
        Err(_) => {
            let document = Document::from(response.as_str());

            if let Some(node) = document.find(Attr("name", "AuthMethod")).next() {
                match node.attr("value") {
                    Some("VIPAuthenticationProviderWindowsAccountName") => {
                        adfs_response.state = ResponseState::MfaPrompt
                    }
                    Some("AzureMfaAuthentication") | Some("AzureMfaServerAuthentication") => {
                        adfs_response.state = ResponseState::MfaWait
                    }
                    _ => (),
                }
            } else if document
                .find(Attr("name", "VerificationCode"))
                .next()
                .is_some()
            {
                adfs_response.state = ResponseState::MfaPrompt
            }
        }
    }

    Ok(adfs_response)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs;

    #[test]
    fn parses_body_returns_form_content() -> Result<()> {
        let body = Document::from(
            r#"
            <input name="UserName" type="email" />
            <input name="Password" type="password" />
            <input name="Checkbox" type="checkbox" />
            <input name="AuthForm" type="hidden" value="SomethingSecret" />
        "#,
        );

        let form_content = build_login_form_elements("jdoe", "password", &body);

        assert_eq!(*form_content.get("UserName").unwrap(), "jdoe");
        assert_eq!(*form_content.get("Password").unwrap(), "password");
        assert_eq!(*form_content.get("AuthForm").unwrap(), "SomethingSecret");

        Ok(())
    }

    #[test]
    fn gets_form_data_from_landing_page() -> Result<()> {
        let body = fs::read_to_string("tests/fixtures/adfs/initial_login_form.html")?;
        let body = Document::from(body.as_str());

        let form_content = build_login_form_elements("jdoe", "password", &body);

        assert_eq!(*form_content.get("UserName").unwrap(), "jdoe");
        assert_eq!(*form_content.get("Password").unwrap(), "password");
        assert_eq!(*form_content.get("Kmsi").unwrap(), "true");
        assert_eq!(
            *form_content.get("AuthMethod").unwrap(),
            "FormsAuthentication"
        );

        Ok(())
    }

    #[test]
    fn fetches_submit_url_from_form() -> Result<()> {
        let body = fs::read_to_string("tests/fixtures/adfs/initial_login_form.html")?;
        let body = Document::from(body.as_str());

        let submit_url = fetch_submit_url(&body);
        assert_eq!("https://adfs.example.com:443/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices".to_owned(), submit_url);

        Ok(())
    }

    #[test]
    fn filters_input_params() -> Result<()> {
        let response = r#"
            <input name="AuthMethod" value="VIPAuthenticationProviderWindowsAccountName" />
        "#
        .to_string();

        let adfs_response = evaluate_response_state(response)?;
        assert_eq!(adfs_response.state, ResponseState::MfaPrompt);

        let response = r#"
            <input name="AuthMethod" value="AzureMfaAuthentication" />
        "#
        .to_string();

        let adfs_response = evaluate_response_state(response)?;
        assert_eq!(adfs_response.state, ResponseState::MfaWait);

        let response = r#"
            <input name="AuthMethod" value="AzureMfaServerAuthentication" />
        "#
        .to_string();

        let adfs_response = evaluate_response_state(response)?;
        assert_eq!(adfs_response.state, ResponseState::MfaWait);

        let response = r#"
            <input name="VerificationCode" value="" />
        "#
        .to_string();

        let adfs_response = evaluate_response_state(response)?;
        assert_eq!(adfs_response.state, ResponseState::MfaPrompt);

        let response = r#"
            <input name="SomeOtherInput" value="Value" />
        "#
        .to_string();

        let adfs_response = evaluate_response_state(response)?;
        assert_eq!(adfs_response.state, ResponseState::Error);

        Ok(())
    }
}
