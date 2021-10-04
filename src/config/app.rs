use crate::providers::ProviderType;
use anyhow::{anyhow, Result};
use clap::ArgMatches;
use sha2::Digest;
use std::fmt;
use std::str::FromStr;
use url::Url;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AppProfile {
    pub name: String,
    pub provider: ProviderType,
    pub username: String,
    pub url: String,
    pub role: Option<String>,
}

impl fmt::Display for AppProfile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let identifier = match self.base_url() {
            Ok(url) => {
                let identifier = format!("{}-{}", url.as_str(), self.username);
                format!("{:x}", sha2::Sha256::digest(identifier.as_bytes()))
            }
            Err(_e) => return Err(std::fmt::Error),
        };

        write!(f, "{}", identifier)
    }
}

impl<'a> From<&ArgMatches<'a>> for AppProfile {
    fn from(action: &ArgMatches) -> AppProfile {
        AppProfile {
            name: action.value_of("profile").unwrap().to_owned(),
            username: action.value_of("username").unwrap().to_owned(),
            url: action.value_of("url").unwrap().to_owned(),
            role: action.value_of("role").map(|r| r.to_owned()),
            provider: ProviderType::from_str(action.value_of("provider").unwrap()).unwrap(),
        }
    }
}

impl AppProfile {
    pub fn request_url(&self) -> Result<Url> {
        let url = self.url.clone();
        match Url::parse(&url) {
            Ok(u) => Ok(u),
            Err(e) => Err(anyhow!("Cannot parse profile URL: {}", e)),
        }
    }

    pub fn base_url(&self) -> Result<Url> {
        let url = self.request_url()?;
        let base_url = &format!("{}://{}", url.scheme(), url.host().unwrap());
        match Url::from_str(base_url) {
            Ok(u) => Ok(u),
            Err(e) => Err(anyhow!("Unable to create base URL: {}", e)),
        }
    }

    pub fn is_profile(&self, profile: &str) -> bool {
        self.name == profile
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn returns_request_url() -> Result<()> {
        assert_eq!(
            Url::from_str("https://example.com/example/url")?,
            short_profile().request_url()?
        );
        Ok(())
    }

    #[test]
    fn returns_base_of_url_just_host() -> Result<()> {
        assert_eq!(
            Url::from_str("https://example.com")?,
            short_profile().base_url()?
        );
        Ok(())
    }

    #[test]
    fn returns_base_of_url_host_and_subdomain() -> Result<()> {
        assert_eq!(
            Url::from_str("https://subdomain.example.com")?,
            long_profile().base_url()?
        );
        Ok(())
    }

    #[test]
    fn validates_profile_name() {
        assert_eq!("profile", short_profile().name)
    }

    fn long_profile() -> AppProfile {
        toml::from_str(
            r#"
            name = "profile"
            provider = "okta"
            url = "https://subdomain.example.com/example/url"
            username = "username"
            role = "role"
        "#
            .trim_start(),
        )
        .unwrap()
    }

    fn short_profile() -> AppProfile {
        toml::from_str(
            r#"
            name = "profile"
            provider = "okta"
            url = "https://example.com/example/url"
            username = "username"
        "#
            .trim_start(),
        )
        .unwrap()
    }
}
