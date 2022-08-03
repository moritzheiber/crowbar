use crate::config::app::AppProfile;
use crate::credentials::{Credential, CredentialType};
use crate::utils;
use anyhow::{anyhow, Result};
use log::debug;

#[derive(Clone)]
pub struct ConfigCredentials {
    credential_type: CredentialType,
    pub password: String,
}

impl Credential<AppProfile, ConfigCredentials> for ConfigCredentials {
    fn create(profile: &AppProfile) -> Result<ConfigCredentials> {
        let credential_type = CredentialType::Config;
        let password = utils::prompt_password(profile)?;

        Ok(ConfigCredentials {
            credential_type,
            password,
        })
    }

    fn load(profile: &AppProfile) -> Result<ConfigCredentials> {
        let credential_type = CredentialType::Config;
        let service = format!("crowbar::{}::{}", &credential_type, profile);

        debug!("Trying to load credentials from ID {}", &service);

        let password = keyring::Entry::new(&service, &profile.username)
            .get_password()
            .map_err(|e| anyhow!("{}", e))?;

        Ok(ConfigCredentials {
            credential_type,
            password,
        })
    }

    fn write(self, profile: &AppProfile) -> Result<ConfigCredentials> {
        let service = format!("crowbar::{}::{}", self.credential_type, profile);

        debug!(
            "Saving credentials for {}",
            profile.base_url()?.host().unwrap()
        );

        keyring::Entry::new(&service, &profile.username)
            .set_password(&self.password)
            .map_err(|e| anyhow!("{}", e))?;

        Ok(self)
    }

    fn delete(self, profile: &AppProfile) -> Result<ConfigCredentials> {
        let service = format!("crowbar::{}::{}", self.credential_type, profile);
        let keyring = keyring::Entry::new(&service, &profile.username);

        debug!(
            "Deleting credentials for {} at {}",
            &profile.username, &service
        );

        let pass = keyring.get_password();

        if pass.is_ok() {
            keyring.delete_password().map_err(|e| anyhow!("{}", e))?
        }

        Ok(self)
    }
}
