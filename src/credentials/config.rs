use crate::config::app::AppProfile;
use anyhow::{anyhow, Result};
use dialoguer::PasswordInput;
use keyring::{Keyring, KeyringError};

pub fn get_password(profile: &AppProfile, username: &str, force_new: &bool) -> Result<String> {
    if *force_new {
        debug!("Force new is set, prompting for password");
        prompt_password(profile)
    } else {
        let id = format!("crowbar::okta::{}", profile);
        debug!("Trying to load credentials from ID {}", id);

        match Keyring::new(&id, username).get_password() {
            Ok(password) => Ok(password),
            Err(e) => {
                debug!(
                    "Retrieving cached password failed, prompting for password because of {:?}",
                    e
                );
                prompt_password(profile)
            }
        }
    }
}

fn prompt_password(profile: &AppProfile) -> Result<String> {
    PasswordInput::new()
        .with_prompt(&format!(
            "Password for {} at {}",
            profile.clone().username,
            profile.clone().base_url()?.host().unwrap()
        ))
        .interact()
        .map_err(|e| e.into())
}

pub fn save(profile: &AppProfile, username: &str, password: &str) -> Result<()> {
    debug!(
        "Saving Okta credentials for {}",
        profile.clone().base_url()?.host().unwrap()
    );

    Keyring::new(&format!("crowbar::okta::{}", profile), username)
        .set_password(password)
        .map_err(|e| anyhow!("{}", e))
}

pub fn delete(profile: &AppProfile) -> Result<()> {
    debug!(
        "Deleting Okta credentials for {}",
        profile.clone().base_url()?.host().unwrap()
    );

    match Keyring::new(&format!("crowbar::okta::{}", profile), &profile.username).delete_password()
    {
        Err(KeyringError::NoPasswordFound) => Ok(()),
        Err(e) => Err(anyhow!("{}", e)),
        _ => Ok(()),
    }
}
