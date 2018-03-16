use keyring::Keyring;
use username;
use dialoguer::{Input, PasswordInput};

use failure::Error;

pub fn get_username(org: &str) -> Result<String, Error> {
    let mut input = Input::new(&format!("Username for https://{}.okta.com", org));
    if let Ok(system_user) = username::get_user_name() {
        input.default(&system_user);
    }

    input.interact().map_err(|e| e.into())
}

pub fn get_password(org: &str, username: &str, force_new: bool) -> Result<String, Error> {
    let input = PasswordInput::new(&format!(
        "Password for https://{}@{}.okta.com",
        username, org
    ));

    if force_new {
        debug!("Force new is set, prompting for password");
        input.interact().map_err(|e| e.into())
    } else {
        match Keyring::new(&format!("oktaws::okta::{}", org), username).get_password() {
            Ok(password) => Ok(password),
            Err(e) => {
                debug!(
                    "Get password failed, prompting for password because of {:?}",
                    e
                );
                input.interact().map_err(|e| e.into())
            }
        }
    }
}

pub fn set_credentials(org: &str, username: &str, password: &str) {
    info!("Saving Okta credentials for {}", username);
    let key = format!("oktaws::okta::{}", org);
    let keyring = Keyring::new(&key, username);
    trace!("Setting {}'s password to {}", username, password);
    keyring.set_password(password).unwrap();
}
