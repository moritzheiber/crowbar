use crate::config::app::AppProfile;
use crate::credentials::{Credential, CredentialType};
use crate::utils;
use anyhow::{anyhow, Result};
use keyring::Keyring;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigCredentials {
    pub password: Option<String>,
}

impl Default for ConfigCredentials {
    fn default() -> Self {
        ConfigCredentials { password: None }
    }
}

impl Credential<AppProfile, ConfigCredentials> for ConfigCredentials {
    fn new(profile: &AppProfile) -> Result<ConfigCredentials> {
        ConfigCredentials::default().ask_password(profile)
    }

    fn load(profile: &AppProfile) -> Result<ConfigCredentials> {
        let service = profile_as_service(profile);
        let username = &profile.username;

        debug!("Trying to load credentials from ID {}", &service);

        let password = Keyring::new(&service, &username).get_password().ok();

        Ok(ConfigCredentials { password })
    }

    fn write(self, profile: &AppProfile) -> Result<ConfigCredentials> {
        let service = profile_as_service(profile);
        let username = &profile.username;
        let password = self.password.to_owned().unwrap_or_default();

        debug!("Saving configuration credentials for {} at {}", username, &service);

        Keyring::new(&service, &username)
            .set_password(&password)
            .map_err(|e| anyhow!("{}", e))?;

        Ok(self)
    }

    fn delete(self, profile: &AppProfile) -> Result<ConfigCredentials> {
        let service = format!("crowbar::{}::{}", CredentialType::Config, profile);
        let username = &profile.username;
        let keyring = Keyring::new(&service, username);

        debug!("Deleting configuration credentials for {} at {}", username, &service);

        let credential = keyring.get_password();

        if credential.is_ok() {
            keyring.delete_password().map_err(|e| anyhow!("{}", e))?
        }

        Ok(self)
    }
}

impl ConfigCredentials {
    pub fn ask_password(mut self, profile: &AppProfile) -> Result<ConfigCredentials> {
        self.password = utils::prompt_password(profile).ok();
        Ok(self)
    }

    pub fn valid(&self) -> bool {
        self.password.is_some()
    }
}

pub fn profile_as_service(profile: &AppProfile) -> String {
    format!("crowbar::{}::{}", CredentialType::Config, profile)
}
