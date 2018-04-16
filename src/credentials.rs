use keyring::Keyring;
use username;
use dialoguer::{Input, PasswordInput};
use rpassword;

use failure::Error;

pub fn get_username(org: &str) -> Result<String, Error> {
    let mut input = Input::new(&format!("Username for https://{}.okta.com", org));
    if let Ok(system_user) = username::get_user_name() {
        input.default(&system_user);
    }

    input.interact().map_err(|e| e.into())
}

pub fn get_password(org: &str, username: &str, force_new: bool) -> Result<String, Error> {
    if force_new {
        debug!("Force new is set, prompting for password");
        prompt_password(org, username)
    } else {
        match Keyring::new(&format!("oktaws::okta::{}", org), username).get_password() {
            Ok(password) => Ok(password),
            Err(e) => {
                debug!(
                    "Retrieving cached password failed, prompting for password because of {:?}",
                    e
                );
                prompt_password(org, username)
            }
        }
    }
}

// We use rpassword here because dialoguer hangs on windows
#[cfg(windows)]
fn prompt_password(org: &str, username: &str) -> Result<String, Error> {
    rpassword::prompt_password_stdout(&format!(
        "Password for https://{}@{}.okta.com: ",
        username, org
    )).map_err(|e| e.into())
}

#[cfg(not(windows))]
fn prompt_password(org: &str, username: &str) -> Result<String, Error> {
    PasswordInput::new(&format!(
        "Password for https://{}@{}.okta.com",
        username, org
    )).interact()
        .map_err(|e| e.into())
}

pub fn set_credentials(org: &str, username: &str, password: &str) {
    info!("Saving Okta credentials for {}", username);
    let key = format!("oktaws::okta::{}", org);
    let keyring = Keyring::new(&key, username);
    trace!("Setting {}'s password to {}", username, password);
    keyring.set_password(password).unwrap();
}
