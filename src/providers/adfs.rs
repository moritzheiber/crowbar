use crate::config::app::AppProfile;
use crate::credentials::aws::AwsCredentials;
use crate::credentials::config::ConfigCredentials;
use crate::credentials::Credential;
use crate::providers::Provider;
use crate::saml;
use crate::utils;

use regex::Regex;
use select::document::Document;
use select::predicate::Name;
use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use reqwest::blocking::{Request, RequestBuilder, Response};
use reqwest::{StatusCode, Url};

const ADFS_URL_SUFFIX: &str = "/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices";

// pub struct AdfsProvider {
//     client: Client,
//     profile: AppProfile,
// }

// impl AdfsProvider {
//     pub fn new(profile: &AppProfile) -> Result<Self> {
//         Ok(AdfsProvider {
//             client: Client::new()?,
//             profile: profile.clone(),
//         })
//     }
// }

// impl Provider<AwsCredentials> for AdfsProvider {
//     fn new_session(&mut self) -> Result<&Self> {
//         let profile = &self.profile;

//         let config_credentials =
//             ConfigCredentials::load(profile).or_else(|_| ConfigCredentials::new(profile))?;

//         let response: XsrfResponse = self
//             .client
//             .get(Url::parse(XSRF_URL)?)
//             .with_context(|| "Unable to obtain XSRF token")?
//             .json()?;

//         let token = response.xsrf;
//         let username = &profile.username;
//         let password = &config_credentials.password;
//         let redirect_to = create_redirect_to(&profile.url)?;
//         let mut login_request =
//             LoginRequest::from_credentials(username.clone(), password.clone(), redirect_to);

//         debug!("Login request: {:?}", login_request);

//         let login_response: Result<LoginResponse, _> =
//             self.client
//                 .post(Url::parse(AUTH_SUBMIT_URL)?, &login_request, &token);

//         let content: LoginResponse = match login_response {
//             Ok(r) => r,
//             Err(e) => match e.status() {
//                 Some(StatusCode::UNAUTHORIZED) if login_request.otp.is_empty() => {
//                     login_request.otp = utils::prompt_mfa()?;
//                     self.client
//                         .post(Url::parse(AUTH_SUBMIT_URL)?, &login_request, &token)?
//                 }
//                 _ => return Err(anyhow!("Unable to login: {}", e)),
//             },
//         };

//         config_credentials.write(profile)?;

//         self.redirect_to = Some(content.redirect_to);
//         Ok(self)
//     }

//     fn fetch_aws_credentials(&self) -> Result<AwsCredentials> {
//         let profile = &self.profile;
//         let url = self.redirect_to.clone().expect("Missing SAML redirect URL");

//         let input = self
//             .client
//             .get(Url::parse(&url)?)
//             .with_context(|| format!("Error getting SAML response for profile {}", profile.name))?
//             .text()?;

//         debug!("Text for SAML response: {:?}", input);

//         let credentials = saml::get_credentials_from_saml(input)?;

//         trace!("Credentials: {:?}", credentials);
//         Ok(credentials)
//     }
// }

//impl AdfsProvider {}

fn build_login_form_elements<'a>(
    username: &'a str,
    password: &'a str,
    document: &'a Document,
) -> Result<HashMap<&'a str, &'a str>> {
    let ur = Regex::new(r"(^email.*|^[Uu]ser.*)")?;
    let pr = Regex::new(r"(^[Pp]ass.*)")?;
    let mut form_content: HashMap<&str, &str> = HashMap::new();
    let elements = document.find(Name("input"));

    for element in elements {
        let attrs: HashMap<&str, &str> = element.attrs().collect();

        match attrs.get("name") {
            Some(name) if ur.is_match(name) => {
                let _ = form_content.insert(name, username);
            }
            Some(name) if pr.is_match(name) => {
                let _ = form_content.insert(name, password);
            }
            _ => {
                let name = attrs.get("name");
                let value = attrs.get("value");
                if name.is_some() && value.is_some() {
                    let _ = form_content.insert(name.unwrap(), value.unwrap());
                }
            }
        };
    }

    Ok(form_content)
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

        let form_content = build_login_form_elements("jdoe", "password", &body)?;

        assert_eq!(*form_content.get("UserName").unwrap(), "jdoe");
        assert_eq!(*form_content.get("Password").unwrap(), "password");
        assert_eq!(*form_content.get("AuthForm").unwrap(), "SomethingSecret");

        Ok(())
    }

    #[test]
    fn gets_form_data_from_landing_page() -> Result<()> {
        let body = fs::read_to_string("tests/fixtures/adfs/initial_login_form.html")?;
        let body = Document::from(body.as_str());

        let form_content = build_login_form_elements("jdoe", "password", &body)?;

        assert_eq!(*form_content.get("UserName").unwrap(), "jdoe");
        assert_eq!(*form_content.get("Password").unwrap(), "password");
        assert_eq!(*form_content.get("Kmsi").unwrap(), "true");
        assert_eq!(
            *form_content.get("AuthMethod").unwrap(),
            "FormsAuthentication"
        );

        Ok(())
    }
}
