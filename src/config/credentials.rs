use dialoguer::{Input, PasswordInput};
use keyring::Keyring;
use okta::Organization;
#[cfg(windows)]
use rpassword;
use username;

use failure::Error;

pub fn get_username(org: &Organization) -> Result<String, Error> {
    let mut input = Input::new(&format!("Username for {}", org.base_url));
    if let Ok(system_user) = username::get_user_name() {
        input.default(&system_user);
    }

    input.interact().map_err(|e| e.into())
}

pub fn get_password(
    organization: &Organization,
    username: &str,
    force_new: bool,
) -> Result<String, Error> {
    if force_new {
        debug!("Force new is set, prompting for password");
        prompt_password(organization, username)
    } else {
        match Keyring::new(&format!("oktaws::okta::{}", organization.name), username).get_password()
        {
            Ok(password) => Ok(password),
            Err(e) => {
                debug!(
                    "Retrieving cached password failed, prompting for password because of {:?}",
                    e
                );
                prompt_password(organization, username)
            }
        }
    }
}

// We use rpassword here because dialoguer hangs on windows
#[cfg(windows)]
fn prompt_password(organization: &Organization, username: &str) -> Result<String, Error> {
    let mut url = organization.base_url.clone();
    url.set_username(username)
        .map_err(|_| format_err!("Cannot set username for URL"))?;

    rpassword::prompt_password_stdout(&format!("Password for {}: ", url)).map_err(|e| e.into())
}

#[cfg(not(windows))]
fn prompt_password(organization: &Organization, username: &str) -> Result<String, Error> {
    let mut url = organization.base_url.clone();
    url.set_username(username)
        .map_err(|_| format_err!("Cannot set username for URL"))?;

    PasswordInput::new(&format!("Password for {}", url))
        .interact()
        .map_err(|e| e.into())
}

pub fn save_credentials(
    organization: &Organization,
    username: &str,
    password: &str,
) -> Result<(), Error> {
    let mut url = organization.base_url.clone();
    url.set_username(username)
        .map_err(|_| format_err!("Cannot set username for URL"))?;

    info!("Saving Okta credentials for {}", url);

    Keyring::new(&format!("oktaws::okta::{}", organization.name), username)
        .set_password(password)
        .map_err(|e| format_err!("{}", e))
}
